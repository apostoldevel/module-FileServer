[![en](https://img.shields.io/badge/lang-en-green.svg)](README.md)

Файл сервер
-

**Модуль** для **Apostol CRM**[^crm].

Описание
-
**FileServer** позволяет получить файлы, хранящиеся в базе данных (через модуль `file` платформы [db-platform](https://github.com/apostoldevel/db-platform)), по прямой HTTP-ссылке. Доступ к файлам предоставляется согласно правам пользователя. Запрос должен быть выполнен в соответствии с правилами [доступа к API](https://github.com/apostoldevel/db-platform/wiki).

> **FileServer** и **PGFile** — взаимодополняющие модули. PGFile синхронизирует файлы из базы данных на локальный диск; FileServer раздаёт эти файлы по HTTP.

Принцип работы
-
1. На адрес `/file/<path>/<name>` поступает HTTP-запрос `GET`.
2. Модуль аутентифицирует запрос (Bearer JWT-токен, сессионная авторизация или SID cookie).
3. Пути, начинающиеся с `/public/`, обслуживаются с помощью бот-сессии — аутентификация пользователя не требуется.
4. **Быстрый путь:** Если файл уже существует в локальной файловой системе, он отдаётся напрямую с корректным заголовком `Content-Type`.
5. **Медленный путь:** Запись файла извлекается из базы данных, декодируется из base64, записывается на диск и отправляется (отложенный ответ).

Формат URL
-
```
http[s]://localhost:8080/file/<path>/<name>
```

| Параметр | Обязательный | Описание |
|----------|:---:|----------|
| `<path>` | Да | Путь к файлу |
| `<name>` | Да | Наименование файла |

Примеры
-
Получить файл:

```http
GET /file/doc/report.pdf HTTP/1.1
Host: localhost:8080
Authorization: Bearer <access_token>
```

Получить публичный файл (без аутентификации):

```http
GET /file/public/logo.png HTTP/1.1
Host: localhost:8080
```

Связанные модули
-
- **[PGFile](https://github.com/apostoldevel/module-PGFile)** — наполняет файловую систему: слушает PostgreSQL NOTIFY и записывает файлы на диск при изменении записей `db.file`
- **Модуль `file` db-platform** — слой базы данных: таблица `db.file`, UNIX-права доступа, `api.get_file`, REST-эндпоинты

Установка
-
Следуйте указаниям по сборке и установке [Апостол (C++20)](https://github.com/apostoldevel/libapostol#build-and-installation).

[^crm]: **Apostol CRM** — шаблон-проект построенный на фреймворках [A-POST-OL](https://github.com/apostoldevel/libapostol) (C++20) и [PostgreSQL Framework for Backend Development](https://github.com/apostoldevel/db-platform).
