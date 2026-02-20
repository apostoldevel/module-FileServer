[![en](https://img.shields.io/badge/lang-en-green.svg)](README.md)

Файл сервер
-
**FileServer** — модуль для [Апостол](https://github.com/apostoldevel/apostol).

Описание
-
**FileServer** позволяет получить [файлы объекта](https://github.com/apostoldevel/db-platform/wiki/%D0%A4%D0%B0%D0%B9%D0%BB%D1%8B-%D0%BE%D0%B1%D1%8A%D0%B5%D0%BA%D1%82%D0%B0), хранящиеся в базе данных, по прямой HTTP-ссылке. Доступ к файлам предоставляется согласно правам пользователя. Запрос должен быть выполнен в соответствии с правилами [доступа к API](https://github.com/apostoldevel/db-platform/wiki/%D0%94%D0%BE%D1%81%D1%82%D1%83%D0%BF-%D0%BA-API).

> **FileServer** и **PGFile** — взаимодополняющие модули на основе общего базового класса `FileCommon`. PGFile синхронизирует файлы из базы данных на локальный диск; FileServer раздаёт эти файлы по HTTP.

Принцип работы
-
1. На адрес `/file/<uuid>[/<path>][/<name>]` поступает HTTP-запрос `GET`.
2. Модуль аутентифицирует запрос (Bearer JWT-токен или сессионная авторизация).
3. Считывает запись файла из базы данных через `api.get_file(id)` с проверкой прав доступа пользователя.
4. Читает содержимое файла с локального диска и отправляет HTTP-ответ с корректным заголовком `Content-Type`.

Формат URL
-
```
http[s]://localhost:8080/file/<uuid>[/<path>][/<name>]
```

| Параметр | Обязательный | Описание |
|----------|:---:|----------|
| `<uuid>` | Да | Идентификатор объекта |
| `<path>` | Нет | Путь к файлу |
| `<name>` | Нет | Наименование файла. По умолчанию: `index.html` |

Примеры
-
Получить файл по умолчанию для объекта:

```http
GET /file/5179f20f-8f17-443c-897c-57c829130b9c HTTP/1.1
Host: localhost:8080
Authorization: Bearer <access_token>
```

Получить конкретный файл по пути и имени:

```http
GET /file/5179f20f-8f17-443c-897c-57c829130b9c/doc/report.pdf HTTP/1.1
Host: localhost:8080
Authorization: Bearer <access_token>
```

Связанные модули
-
- **PGFile** — наполняет файловую систему: слушает PostgreSQL NOTIFY и записывает файлы на диск при изменении записей `db.file`
- **Модуль `file` db-platform** — слой базы данных: таблица `db.file`, UNIX-права доступа, `api.get_file`, REST-эндпоинты
- **FileCommon** (`src/common/FileCommon`) — общий базовый C++-класс: аутентификация, очередь, `CFileHandler`, поддержка cURL

Установка
-
Следуйте указаниям по сборке и установке [Апостол](https://github.com/apostoldevel/apostol#%D1%81%D0%B1%D0%BE%D1%80%D0%BA%D0%B0-%D0%B8-%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0).
