## Запуск Celery
```
 celery -A tasks.celery worker --loglevel=info --pool=threads
```
## Запуск API
```
fastapi run src/main.py
```
Для работы необходиио начать чат с ботом @Python_JWT_Auth_Bot. Для авторизации через Яндес нужно перейти на url "http://localhost:8000/auth/yandex?telegram_chat_id=<ваш user id>"
