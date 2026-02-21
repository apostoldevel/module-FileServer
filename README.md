[![ru](https://img.shields.io/badge/lang-ru-green.svg)](README.ru-RU.md)

File Server
-
**FileServer** is a module for [Apostol](https://github.com/apostoldevel/apostol) + [db-platform](https://github.com/apostoldevel/db-platform) — **Apostol CRM**[^crm].

Description
-
**FileServer** serves files stored in the database (via the `file` module of [db-platform](https://github.com/apostoldevel/db-platform)) over HTTP using a direct URL. Access is controlled by user permissions. Requests must comply with the [API access rules](https://github.com/apostoldevel/db-platform/wiki).

> **FileServer** and **PGFile** are complementary modules that share the `FileCommon` base class. PGFile syncs files from the database to the local filesystem; FileServer serves those files over HTTP.

How it works
-
1. An HTTP `GET` request arrives at `/file/<uuid>[/<path>][/<name>]`.
2. The module authenticates the request (Bearer JWT token or session-based authorization).
3. It fetches the file record from the database via `api.get_file(id)`, which checks user permissions.
4. The file content is read from the local filesystem and sent as an HTTP response with the correct `Content-Type`.

URL format
-
```
http[s]://localhost:8080/file/<uuid>[/<path>][/<name>]
```

| Parameter | Required | Description |
|-----------|:--------:|-------------|
| `<uuid>`  | Yes | Object identifier |
| `<path>`  | No  | File path within the object |
| `<name>`  | No  | File name. Defaults to `index.html` |

Examples
-
Fetch the default file for an object:

```http
GET /file/5179f20f-8f17-443c-897c-57c829130b9c HTTP/1.1
Host: localhost:8080
Authorization: Bearer <access_token>
```

Fetch a specific file by path and name:

```http
GET /file/5179f20f-8f17-443c-897c-57c829130b9c/doc/report.pdf HTTP/1.1
Host: localhost:8080
Authorization: Bearer <access_token>
```

Related modules
-
- **PGFile** — populates the filesystem: listens to PostgreSQL NOTIFY and writes files to disk when `db.file` records change
- **db-platform `file` module** — database layer: `db.file` table, UNIX-like permissions, `api.get_file`, REST endpoints
- **FileCommon** (`src/common/FileCommon`) — shared C++ base class: authentication, queue, `CFileHandler`, cURL support

Installation
-
Follow the build and installation instructions for [Apostol](https://github.com/apostoldevel/apostol#build-and-installation).

[^crm]: **Apostol CRM** is an abstract term, not a standalone product. It refers to any project that uses both the [Apostol](https://github.com/apostoldevel/apostol) C++ framework and [db-platform](https://github.com/apostoldevel/db-platform) together through purpose-built modules and processes. Each framework can be used independently; combined, they form a full-stack backend platform.
