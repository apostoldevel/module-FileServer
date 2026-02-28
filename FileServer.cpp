#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "FileServer.hpp"
#include "apostol/application.hpp"

#include "apostol/base64.hpp"
#include "apostol/file_utils.hpp"
#include "apostol/http.hpp"
#include "apostol/http_utils.hpp"
#include "apostol/jwt.hpp"
#include "apostol/pg_exec.hpp"
#include "apostol/pg_utils.hpp"

#include <fmt/format.h>
#include <fstream>

namespace apostol
{

// ─── Construction ────────────────────────────────────────────────────────────

FileServer::FileServer(Application& app)
    : pool_(app.db_pool())
    , bot_(app.db_pool(), "FileServer/2.0", "127.0.0.1")
    , providers_(app.providers())
    , enabled_(true)
{
    if (auto* cfg = app.module_config("FileServer")) {
        if (cfg->contains("endpoints") && (*cfg)["endpoints"].is_array())
            for (auto& e : (*cfg)["endpoints"])
                if (e.is_string()) endpoints_.push_back(e.get<std::string>());
        if (cfg->contains("path"))
            files_path_ = app.resolve_path((*cfg)["path"].get<std::string>(), "files");
        if (cfg->contains("timeout") && (*cfg)["timeout"].is_number())
            timeout_secs_ = (*cfg)["timeout"].get<int>();
    }
    if (endpoints_.empty())
        endpoints_.push_back("/file/*");
    if (files_path_.empty())
        files_path_ = app.resolve_path("", "files");
    if (timeout_secs_ <= 0)
        timeout_secs_ = 60;

    // Load OAuth2 "service" credentials for bot session (/public/* paths)
    auto [cid, csecret] = app.providers().credentials("service");
    if (!cid.empty()) {
        client_id_ = std::move(cid);
        client_secret_ = std::move(csecret);
        bot_.set_credentials(client_id_, client_secret_);
    }

    load_allowed_origins(providers_);
}

// ─── Lifecycle ──────────────────────────────────────────────────────────────

void FileServer::on_start()
{
    // FileServer is a worker — no LISTEN needed
}

void FileServer::on_stop()
{
    bot_.sign_out();
}

void FileServer::heartbeat(std::chrono::system_clock::time_point /*now*/)
{
    bot_.refresh_if_needed();
}

// ─── check_location ─────────────────────────────────────────────────────────

bool FileServer::check_location(const HttpRequest& req) const
{
    return match_path(req.path, endpoints_);
}

// ─── init_methods ───────────────────────────────────────────────────────────

void FileServer::init_methods()
{
    add_method("GET", [this](auto& req, auto& resp) { do_get(req, resp); });
}

// ─── do_get ─────────────────────────────────────────────────────────────────
//
// Mirrors v1 CFileServer::DoGet():
//   1. Parse path → {dir, filename}
//   2. /public/* → use bot session
//   3. Other → check_auth()
//   4. If file exists on disk → serve directly
//   5. Otherwise → deferred PG query

void FileServer::do_get(const HttpRequest& req, HttpResponse& resp)
{
    auto req_path = req.path;

    // Safety check
    if (!is_safe_path(req_path)) {
        reply_error(resp, HttpStatus::bad_request, "invalid path");
        return;
    }

    auto [path, name] = parse_file_path(req_path);

    if (name.empty()) {
        reply_error(resp, HttpStatus::not_found, "file not specified");
        return;
    }

    // Determine session
    std::string session;

    if (path.substr(0, 8) == "/public/") {
        // Public path — use bot session
        session = bot_.session();
        if (session.empty()) {
            reply_error(resp, HttpStatus::internal_server_error,
                        "service not ready");
            return;
        }
    } else {
        // Authenticated path
        session = check_auth(req, resp);
        if (session.empty())
            return; // response already set by check_auth()
    }

    // Build local file path
    auto rel_path = path;
    if (!rel_path.empty() && rel_path.front() == '/')
        rel_path = rel_path.substr(1);

    auto local_path = files_path_ / rel_path / name;

    // Fast path: file exists on disk
    if (std::filesystem::exists(local_path)) {
        serve_local_file(local_path, resp);
        return;
    }

    // Slow path: query PG for file data (deferred response)
    resp.set_deferred(true);

    fetch_and_serve(session, name, path, req.connection_ctx);
}

// ─── check_auth ─────────────────────────────────────────────────────────────
//
// Mirrors v1 CFileServer::CheckAuthorization():
//   1. Authorization: Bearer <jwt> → verify_jwt() → sub = session
//   2. Session: <uuid> header → session = uuid
//   3. Cookie SID=<uuid> → session = uuid

std::string FileServer::check_auth(const HttpRequest& req, HttpResponse& resp)
{
    // Try Authorization header first
    auto auth = req.header("Authorization");
    if (!auth.empty()) {
        // Bearer token
        if (auth.size() > 7 && auth.substr(0, 7) == "Bearer ") {
            auto token = auth.substr(7);
            try {
                auto claims = verify_jwt(token, providers_);
                if (!claims.sub.empty())
                    return claims.sub;
                reply_error(resp, HttpStatus::unauthorized, "missing subject in token");
                return {};
            } catch (const JwtExpiredError&) {
                reply_error(resp, HttpStatus::forbidden, "token expired");
                return {};
            } catch (const JwtVerificationError& e) {
                reply_error(resp, HttpStatus::unauthorized, e.what());
                return {};
            } catch (const std::exception& e) {
                reply_error(resp, HttpStatus::bad_request, e.what());
                return {};
            }
        }
    }

    // Try Session header
    auto session_hdr = req.header("Session");
    if (!session_hdr.empty())
        return session_hdr;

    // Try SID cookie
    auto sid = req.cookie("SID");
    if (!sid.empty())
        return sid;

    reply_error(resp, HttpStatus::unauthorized, "Unauthorized");
    return {};
}

// ─── parse_file_path ────────────────────────────────────────────────────────
//
// "/file/some/path/document.pdf" → {"/some/path/", "document.pdf"}
// "/file/document.pdf"           → {"/", "document.pdf"}

std::pair<std::string, std::string>
FileServer::parse_file_path(std::string_view url_path)
{
    // Skip the first component (e.g. "/file")
    // Find second '/'
    auto first_slash = url_path.find('/');
    if (first_slash == std::string_view::npos)
        return {"/", std::string(url_path)};

    auto second_slash = url_path.find('/', first_slash + 1);
    if (second_slash == std::string_view::npos)
        return {"/", std::string(url_path.substr(first_slash + 1))};

    // Everything after the first component
    auto rest = url_path.substr(second_slash);

    // Find last '/' in rest
    auto last_slash = rest.rfind('/');
    if (last_slash == std::string_view::npos || last_slash == 0)
        return {"/", std::string(rest.substr(1))};

    auto path = std::string(rest.substr(0, last_slash + 1));
    auto name = std::string(rest.substr(last_slash + 1));

    return {path, name};
}

// ─── serve_local_file ───────────────────────────────────────────────────────

void FileServer::serve_local_file(const std::filesystem::path& path,
                                  HttpResponse& resp)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        reply_error(resp, HttpStatus::not_found, "file not readable");
        return;
    }

    std::string content((std::istreambuf_iterator<char>(f)), {});
    auto ext = path.extension().string();
    auto mime = std::string(file_mime_type(ext));

    resp.set_status(HttpStatus::ok)
        .set_body(std::move(content), mime);
}

// ─── fetch_and_serve ────────────────────────────────────────────────────────
//
// Deferred response: query PG for file, decode, write to disk, send to client.
// Uses exec_sql() which handles set_deferred + on_exception automatically.
// NOTE: we use pool_.execute() directly here because exec_sql sets deferred=true,
// but do_get() already set it, and we need the raw pool for a 2-statement SQL.

void FileServer::fetch_and_serve(std::string_view session,
                                 std::string_view name, std::string_view path,
                                 std::shared_ptr<void> conn_ctx)
{
    auto conn = std::static_pointer_cast<HttpConnection>(conn_ctx);

    auto sql = fmt::format(
        "SELECT * FROM api.authorize({});\n"
        "SELECT * FROM api.get_file(api.get_file_id({}, {}))",
        pq_quote_literal(std::string(session)),
        pq_quote_literal(std::string(name)),
        pq_quote_literal(std::string(path)));

    // Capture what we need for the async callback
    auto files_path = files_path_;

    pool_.execute(sql,
        [conn, files_path, path = std::string(path),
         name = std::string(name)](std::vector<PgResult> results) {
            HttpResponse r;

            // results[0] = authorize, results[1] = get_file
            if (results.size() < 2 || !results[1].ok()) {
                reply_error(r, HttpStatus::internal_server_error, "query failed");
                conn->send_response(r);
                return;
            }

            auto& file_result = results[1];
            if (file_result.rows() == 0) {
                reply_error(r, HttpStatus::not_found, "file not found");
                conn->send_response(r);
                return;
            }

            // Access columns by name (api.get_file returns SETOF api.file_data)
            auto col = [&](const char* cname) -> std::string {
                int idx = file_result.column_index(cname);
                if (idx < 0) return {};
                const char* v = file_result.value(0, idx);
                return (v && v[0] != '\0') ? std::string(v) : std::string{};
            };

            auto data = col("data");
            auto type = col("type");
            auto file_name = col("name");
            auto file_path = col("path");
            auto mime = col("mime");

            if (type.empty()) type = "-";
            if (file_name.empty()) file_name = name;
            if (file_path.empty()) file_path = path;

            if (data.empty()) {
                r.set_status(HttpStatus::no_content);
                conn->send_response(r);
                return;
            }

            if (type == "-") {
                // Regular file: base64 decode
                try {
                    auto decoded = base64_decode(data);

                    // Determine MIME from extension if not provided by DB
                    if (mime.empty()) {
                        auto ext = std::filesystem::path(file_name).extension().string();
                        mime = std::string(file_mime_type(ext));
                    }

                    // Write to disk for cache
                    auto rel = file_path;
                    if (!rel.empty() && rel.front() == '/')
                        rel = rel.substr(1);
                    auto local = files_path / rel / file_name;
                    write_file(local, decoded);

                    r.set_status(HttpStatus::ok)
                     .set_body(std::move(decoded), mime);
                    conn->send_response(r);
                } catch (const std::exception& e) {
                    reply_error(r, HttpStatus::internal_server_error,
                                fmt::format("decode error: {}", e.what()));
                    conn->send_response(r);
                }
            } else if (type == "l" || type == "s") {
                // Link/S3: data is base64-encoded URL or path reference
                try {
                    auto decoded = base64_decode(data);

                    if (decoded.substr(0, 8) == "https://" ||
                        decoded.substr(0, 7) == "http://") {
                        reply_error(r, HttpStatus::not_found, "file not cached locally");
                        conn->send_response(r);
                    } else {
                        // Local path reference — try to serve it
                        auto ref_path = std::filesystem::path(decoded);
                        if (std::filesystem::exists(ref_path)) {
                            std::ifstream f(ref_path, std::ios::binary);
                            if (f.is_open()) {
                                std::string content((std::istreambuf_iterator<char>(f)), {});
                                if (mime.empty()) {
                                    auto ext = ref_path.extension().string();
                                    mime = std::string(file_mime_type(ext));
                                }
                                r.set_status(HttpStatus::ok)
                                 .set_body(std::move(content), mime);
                                conn->send_response(r);
                                return;
                            }
                        }
                        reply_error(r, HttpStatus::not_found, "referenced file not found");
                        conn->send_response(r);
                    }
                } catch (...) {
                    reply_error(r, HttpStatus::internal_server_error, "decode error");
                    conn->send_response(r);
                }
            } else {
                reply_error(r, HttpStatus::not_found, "unsupported file type");
                conn->send_response(r);
            }
        },
        // on_exception — uses free reply_error (with json_escape, fixing the security bug)
        [conn](std::string_view error) {
            HttpResponse r;
            reply_error(r, HttpStatus::internal_server_error, error);
            conn->send_response(r);
        });
}

} // namespace apostol

#endif // WITH_POSTGRESQL && WITH_SSL
