### Запуск:
```
docker-compose up --build
```
Для работы необходиио начать чат с ботом @Python_JWT_Auth_Bot. 
### Авторизация Яндекс
Для авторизации через Яндес нужно перейти на url "http://localhost:8000/auth/yandex?telegram_chat_id=<user_id>" где user_id - ваш user_id в телеграмме, который можно узнать с помощью бота @getmyid_bot.
сразу после авторизации в чат будет отправлено сообщение.
