Файл сервер
-
**Модуль** для [Апостол](https://github.com/ufocomp/apostol-aws).

Описание
-
* Сервер для получения [файлов объекта](https://github.com/apostoldevel/db-platform/wiki/%D0%A4%D0%B0%D0%B9%D0%BB%D1%8B-%D0%BE%D0%B1%D1%8A%D0%B5%D0%BA%D1%82%D0%B0) хранящихся в СУБД по прямой ссылке (URL).
* Доступ к файлам предоставляется согласно правам пользователя.
* Запрос должен быть выполнен в соответствии с правилами [доступа к API](https://github.com/apostoldevel/db-platform/wiki/%D0%94%D0%BE%D1%81%D1%82%D1%83%D0%BF-%D0%BA-API).

Формат URL:
````
http[s]://localhost:8080/file/<uuid>[/<path>][/<name>]
````
* Где:
    -  `<uuid>` - **Обязательный**. Идентификатор объекта;
    -  `<path>` - **Необязательный**. Путь к файлу.
    -  `<name>` - **Необязательный**. Наименование файла. По умолчанию: `index.html`.

Пример:
````http request
GET /file/5179f20f-8f17-443c-897c-57c829130b9c HTTP/1.1
Host: localhost:8080
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiIDogImFjY291bnRzLnNoaXAtc2FmZXR5LnJ1IiwgImF1ZCIgOiAid2ViLXNoaXAtc2FmZXR5LnJ1IiwgInN1YiIgOiAiZGZlMDViNzhhNzZiNmFkOGUwZmNiZWYyNzA2NzE3OTNiODZhYTg0OCIsICJpYXQiIDogMTU5MzUzMjExMCwgImV4cCIgOiAxNTkzNTM1NzEwfQ.NorYsi-Ht826HUFCEArVZ60_dEUmYiJYXubnTyweIMg
````

````http request
GET /file/5179f20f-8f17-443c-897c-57c829130b9c/doc/file.pdf HTTP/1.1
Host: localhost:8080
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiIDogImFjY291bnRzLnNoaXAtc2FmZXR5LnJ1IiwgImF1ZCIgOiAid2ViLXNoaXAtc2FmZXR5LnJ1IiwgInN1YiIgOiAiZGZlMDViNzhhNzZiNmFkOGUwZmNiZWYyNzA2NzE3OTNiODZhYTg0OCIsICJpYXQiIDogMTU5MzUzMjExMCwgImV4cCIgOiAxNTkzNTM1NzEwfQ.NorYsi-Ht826HUFCEArVZ60_dEUmYiJYXubnTyweIMg
````

Установка
-
Следуйте указаниям по сборке и установке [Апостол](https://github.com/ufocomp/apostol-aws#%D1%81%D0%B1%D0%BE%D1%80%D0%BA%D0%B0-%D0%B8-%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0)
