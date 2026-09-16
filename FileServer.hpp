#pragma once

#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "apostol/bot_session.hpp"
#include "apostol/http.hpp"
#include "apostol/apostol_module.hpp"
#include "apostol/oauth_providers.hpp"
#include "apostol/pg.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace apostol
{

class Application;

// ─── FileServer ──────────────────────────────────────────────────────────────
//
// Worker module that serves files from db.file over HTTP.
//
// Mirrors v1 CFileServer from debt-master.
//
// Request flow:
//   GET /file/some/path/document.pdf
//     → check_location("/file/*")
//     → parse_file_path() → {path="/some/path/", name="document.pdf"}
//     → /public/* uses bot session (no user auth)
//     → other paths: check_auth() (JWT Bearer / Session header / __Host-SID cookie)
//     → file on disk, bot session → sendfile directly
//     → file on disk, user session → api.authorize() → sendfile (deferred)
//     → otherwise: api.authorize() + api.get_file() → decode → write → serve (deferred)
//
// Nothing leaves the disk on a user session before the database has confirmed it:
// api.authorize() is the only barrier this module has, and its result is binding.
//
class FileServer final : public ApostolModule
{
public:
    explicit FileServer(Application& app);

    std::string_view name() const override { return "FileServer"; }
    bool enabled() const override { return enabled_; }
    bool check_location(const HttpRequest& req) const override;

    void on_start() override;
    void on_stop() override;
    void heartbeat(std::chrono::system_clock::time_point now) override;

protected:
    void init_methods() override;

private:
    /// Extract session from JWT Bearer / Session header / __Host-SID cookie.
    /// A header/cookie session is accepted only at its exact length (40); the
    /// value is still unverified here — api.authorize() decides.
    /// Returns empty string on auth failure (response already set).
    std::string check_auth(const HttpRequest& req, HttpResponse& resp);

    /// Handle GET request for a file.
    void do_get(const HttpRequest& req, HttpResponse& resp);

    /// Parse "/file/some/path/filename.ext" → {path="/some/path/", name="filename.ext"}
    static std::pair<std::string, std::string> parse_file_path(std::string_view url_path);

    /// Async: api.authorize() only, then sendfile(2) of a file already on disk.
    void authorize_and_serve(std::string_view session,
                             std::filesystem::path local_path,
                             std::shared_ptr<void> conn_ctx);

    /// Async: DB query → decode → write to disk → send response.
    void fetch_and_serve(std::string_view session,
                         std::string_view name, std::string_view path,
                         std::shared_ptr<void> conn_ctx);

    /// True when the api.authorize() result says authorized = 't';
    /// otherwise fills `message` from the row. Expects a successful result.
    static bool authorized(const PgResult& res, std::string& message);

    PgPool&               pool_;
    BotSession            bot_;
    std::filesystem::path files_path_;
    const OAuthProviders& providers_;
    std::vector<std::string> endpoints_;
    bool                  enabled_;
    std::string           client_id_;
    std::string           client_secret_;
};

} // namespace apostol

#endif // WITH_POSTGRESQL && WITH_SSL
