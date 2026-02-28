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
//     → other paths: check_auth() (JWT Bearer / Session header / SID cookie)
//     → fast path: file exists on disk → serve directly
//     → slow path: PG query → decode → write → serve (deferred response)
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
    /// Extract session from JWT Bearer / Session header / SID cookie.
    /// Returns empty string on auth failure (response already set).
    std::string check_auth(const HttpRequest& req, HttpResponse& resp);

    /// Handle GET request for a file.
    void do_get(const HttpRequest& req, HttpResponse& resp);

    /// Parse "/file/some/path/filename.ext" → {path="/some/path/", name="filename.ext"}
    static std::pair<std::string, std::string> parse_file_path(std::string_view url_path);

    /// Serve a local file: set 200 + MIME type + body.
    static void serve_local_file(const std::filesystem::path& path,
                                 HttpResponse& resp);

    /// Async: DB query → decode → write to disk → send response.
    void fetch_and_serve(std::string_view session,
                         std::string_view name, std::string_view path,
                         std::shared_ptr<void> conn_ctx);

    PgPool&               pool_;
    BotSession            bot_;
    std::filesystem::path files_path_;
    const OAuthProviders& providers_;
    std::vector<std::string> endpoints_;
    int                   timeout_secs_;
    bool                  enabled_;
    std::string           client_id_;
    std::string           client_secret_;
};

} // namespace apostol

#endif // WITH_POSTGRESQL && WITH_SSL
