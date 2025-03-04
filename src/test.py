import requests
from datetime import datetime, UTC

register_payload = {
        "email": 'awesome@gmail.com',
        'name': 'awesome',
        'password': 'awesome',
        'role': 'client',
        'telegram_chat_id':  1451171418,
}

login_payload = {
        "username": "stupid@gmail.com",
        "password": "stupid",
        }

create_training_plan_payload = {
        'name': 'stupid workout',
        'client_id': 10,
        'coach_id': 9,
        'date_start': datetime(2024, 11, 25, 14, 30, 0, tzinfo=UTC).isoformat(),
        'date_end': datetime(2024, 11, 25, 14, 30, 0, tzinfo=UTC).isoformat(),
        'description': 'lol'
}

edit_training_plan_payload = {
        'name': 'jelqing',
}

headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6OSwiZW1haWwiOiJzdHVwaWRAZ21haWwuY29tIiwicm9sZSI6ImNvYWNoIiwiZXhwIjoxNzM5MTEzMjE2fQ.ixA0cve9FHJvfVWYvgP4sfTtPM9hDeefYMozZP1mUpI"
}

response = requests.post('http://127.0.0.1:8000/login/',
                        data=login_payload,
                        )
print(response)
print(response.json())

response = requests.post('http://127.0.0.1:8000/register/',
                        json=register_payload,)

print(response)
print(response.json())
