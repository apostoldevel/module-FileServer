Файл сервер
-
**Модуль** для [Апостол](https://github.com/ufocomp/apostol-aws).

Описание
-
* Сервер для получения [файлов объекта](https://github.com/apostoldevel/db-platform/wiki/%D0%A4%D0%B0%D0%B9%D0%BB%D1%8B-%D0%BE%D0%B1%D1%8A%D0%B5%D0%BA%D1%82%D0%B0) хранящихся в СУБД по прямой ссылке (URL).

Формат URL:
````
http[s]://localhost:8080/file/<uuid>[/<path>][/<name>]
````
* Где:
-  `<uuid>` - **Обязательный**. Идентификатор объекта;
-  `<path>` - **Необязательный**. Путь к файлу.
-  `<name>` - **Необязательный**. Наименование файла. По умолчанию: `index.html`.

Пример:
````
http://localhost:8080/file/5179f20f-8f17-443c-897c-57c829130b9c
````

````
http://localhost:8080/file/5179f20f-8f17-443c-897c-57c829130b9c/js/script.js
````

Установка
-
Следуйте указаниям по сборке и установке [Апостол](https://github.com/ufocomp/apostol-aws#%D1%81%D0%B1%D0%BE%D1%80%D0%BA%D0%B0-%D0%B8-%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0)

