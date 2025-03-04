from sqlmodel import select
from sqlalchemy.ext.asyncio import create_async_engine,async_sessionmaker, AsyncSession
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import or_, delete, text
from typing import AsyncGenerator, List
from sqlalchemy.orm import aliased, joinedload


from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, OAuth2AuthorizationCodeBearer
from fastapi.responses import RedirectResponse
import httpx

import jwt
import bcrypt
from datetime import timedelta
from fastapi.middleware.cors import CORSMiddleware

from tasks import send_message
from models import *

import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
BROKER_URL = os.getenv("BROKER_URL")

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")

YANDEX_CLIENT_ID = os.getenv("YANDEX_CLIENT_ID")
YANDEX_CLIENT_SECRET = os.getenv("YANDEX_CLIENT_SECRET")
YANDEX_REDIRECT_URL = os.getenv("YANDEX_REDIRECT_URL")

VK_CLIENT_ID = os.getenv("VK_CLIENT_ID")
VK_CLIENT_SECRET = os.getenv("VK_CLIENT_SECRET")
VK_SERVICE_SECRET = os.getenv("VK_SERVICE_SECRET")
VK_REDIRECT_URL = os.getenv("VK_REDIRECT_URL")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

POSTGRES_USER = os.getenv("POSTGRES_USER")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
POSTGRES_DB = os.getenv("POSTGRES_DB")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND")


#database setup
database_URL = "postgresql+asyncpg://postgres:rj40Vt02lB60z@localhost:5432/python"
engine = create_async_engine(database_URL,  echo=True)
Session = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with Session() as session:
        yield session




YANDEX_CLIENT_ID = "e7a7f2f342c74471ba3b9e92e4231dd9"
YANDEX_CLIENT_SECRET = "866bd7b4434146218eb3b34ece811d39"
YANDEX_REDIRECT_URI = "http://localhost:8000/auth/yandex/callback"
YANDEX_AUTHORIZE_URL = "https://oauth.yandex.com/authorize"
YANDEX_TOKEN_URL = "https://oauth.yandex.com/token"
YANDEX_USER_INFO_URL = "https://login.yandex.ru/info"


yandex_oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=YANDEX_AUTHORIZE_URL,
    tokenUrl=YANDEX_TOKEN_URL,
)



#JWT
jwt_key = "pogchamp" #change later
jwt_algorithm = 'HS256'


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/")



app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)




@app.on_event("startup")
async def create_db_and_tables():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

# @app.exception_handler(IntegrityError)
# async def integrity_error_handler(request: Request, exc: IntegrityError):
#     raise HTTPException(status_code=400, detail="Database constraint violated. Please check your data.")


def decode_jwt(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, jwt_key, algorithms=[jwt_algorithm])
        id = payload['id']
        email = payload['email']
        role = payload['role']
        if email is None:
            raise HTTPException(status_code=401, detail='Invalid token')
        return {'id': id, 'email': email, 'role': role}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='Token expired')
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail='Invalid token')

@app.post('/register/', response_model=UsersPublic)# register user
async def register(user: UsersRegister, session: Session = Depends(get_session)):
    email = user.email

    query = select(Users).where(Users.email == email)
    result = await session.execute(query)
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(status_code=409, detail="Email is already registered")

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(user.password.encode(), salt)

    user_data = user.dict(exclude={"password"})
    user_data["hashed_password"] = hashed_password.decode('utf-8')
    user_data['auth_method'] = 'local'

    db_user = Users(**user_data)

    session.add(db_user) #check if exists
    await session.commit()
    await session.refresh(db_user)
    print('start')
    chat_id = user.telegram_chat_id
    send_message.delay(chat_id, "Welcome")
    print('end')
    return db_user


@app.post('/login/')
async def login(user_input: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    query = select(Users).where(Users.email == user_input.username)
    result = await session.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db_email = user.email
    db_password = user.hashed_password

    if not bcrypt.checkpw(user_input.password.encode(), db_password.encode()):
        raise HTTPException(status_code=400, detail='Wrong password')

    token_expiration = timedelta(days=7)
    token = jwt.encode(
        {
            'id': user.id,
            'email': db_email,
            'role': user.role,
            'exp': datetime.now(UTC) + token_expiration
        },
        jwt_key,
        algorithm=jwt_algorithm
    )

    new_login_history = models.LoginHistory(
        user_id=user.id,

    )
    session.add(new_login_history)

    await session.commit()
    await session.refresh(new_login_history)

    return {"token": token, "token_type": "bearer"}


@app.get("/auth/yandex/")
async def auth_yandex(telegram_chat_id: int):
    auth_url = (
        f"{YANDEX_AUTHORIZE_URL}?response_type=code"
        f"&client_id={YANDEX_CLIENT_ID}"
        f"&redirect_uri={YANDEX_REDIRECT_URI}"
        f"&state={telegram_chat_id}"
    )
    return RedirectResponse(url=auth_url)




@app.get("/auth/yandex/callback")
async def auth_yandex_callback(code: str, state: str ,session: Session = Depends(get_session)):
    telegram_chat_id = state
    # Exchange the authorization code for an access token
    async with httpx.AsyncClient() as client:
        response = await client.post(
            YANDEX_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": YANDEX_CLIENT_ID,
                "client_secret": YANDEX_CLIENT_SECRET,
            },
        )
        token_data = response.json()


    if "access_token" not in token_data:
        raise HTTPException(
            status_code=400,
            detail="Failed to get access token (expired)",
        )

    access_token = token_data["access_token"]

    # Get user info using the access token
    async with httpx.AsyncClient() as client:
        user_info_response = await client.get(
            YANDEX_USER_INFO_URL,
            params={"format": "json", "oauth_token": access_token},
        )
        user_info = user_info_response.json()


    query = select(Users).where(Users.email == user_info["default_email"])
    result = await session.execute(query)
    user = result.scalars().first()

    role='default_role'
    if not user:
        new_user = Users(email=user_info["default_email"], role=role, auth_method='yandex', yandex_id=user_info['id'])
        session.add(new_user)
        await session.commit()
        await session.refresh(new_user)
        new_history = LoginHistory(user_id=new_user.id)
        session.add(new_history)
        await session.commit()
        await session.refresh(new_history)
        role = new_user.role
        send_message.delay(telegram_chat_id, "Welcome")
    else:
        new_history = LoginHistory(user_id=user.id)
        session.add(new_history)
        await session.commit()
        await session.refresh(new_history)
        role = user.role

    token_expiration = timedelta(days=7)
    token = jwt.encode(
        {
            'id': user_info['id'],
            'email': user_info.get("default_email", ""),
            'role': role,
            'exp': datetime.now(UTC) + token_expiration
        },
        jwt_key,
        algorithm=jwt_algorithm
    )

    return {"token": token, "token_type": "bearer"}


@app.get('/user/', response_model=UsersPublic)
async def get_user(user_info=Depends(decode_jwt), session: Session = Depends(get_session)):
    query = select(Users).where(Users.id == user_info['id'])
    result = await session.execute(query)
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')

    return user



