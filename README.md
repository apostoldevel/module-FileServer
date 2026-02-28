[![ru](https://img.shields.io/badge/lang-ru-green.svg)](README.ru-RU.md)

File Server
-

**Module** for **Apostol CRM**[^crm].

Description
-
**FileServer** serves files stored in the database (via the `file` module of [db-platform](https://github.com/apostoldevel/db-platform)) over HTTP using a direct URL. Access is controlled by user permissions. Requests must comply with the [API access rules](https://github.com/apostoldevel/db-platform/wiki).

> **FileServer** and **PGFile** are complementary modules. PGFile syncs files from the database to the local filesystem; FileServer serves those files over HTTP.

How it works
-
1. An HTTP `GET` request arrives at `/file/<path>/<name>`.
2. The module authenticates the request (Bearer JWT token, session-based authorization, or SID cookie).
3. Paths under `/public/` are served using a bot session — no user authentication required.
4. **Fast path:** If the file already exists on the local filesystem, it is served directly with the correct `Content-Type`.
5. **Slow path:** The file record is fetched from the database via a PG query, base64-decoded, written to disk, and served (deferred response).

URL format
-
```
http[s]://localhost:8080/file/<path>/<name>
```

| Parameter | Required | Description |
|-----------|:--------:|-------------|
| `<path>`  | Yes | File path |
| `<name>`  | Yes | File name |

Examples
-
Fetch a file:

```http
GET /file/doc/report.pdf HTTP/1.1
Host: localhost:8080
Authorization: Bearer <access_token>
```

Fetch a public file (no auth required):

```http
GET /file/public/logo.png HTTP/1.1
Host: localhost:8080
```

Related modules
-
- **[PGFile](https://github.com/apostoldevel/module-PGFile)** — populates the filesystem: listens to PostgreSQL NOTIFY and writes files to disk when `db.file` records change
- **db-platform `file` module** — database layer: `db.file` table, UNIX-like permissions, `api.get_file`, REST endpoints

Installation
-
Follow the build and installation instructions for [Apostol (C++20)](https://github.com/apostoldevel/libapostol#build-and-installation).

[^crm]: **Apostol CRM** — a template project built on the [A-POST-OL](https://github.com/apostoldevel/libapostol) (C++20) and [PostgreSQL Framework for Backend Development](https://github.com/apostoldevel/db-platform) frameworks.
