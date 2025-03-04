from sqlmodel import SQLModel, Field, Column, TIMESTAMP
from datetime import datetime, UTC
from typing import List



#user
class UsersEmail(SQLModel):
    email: str = Field(max_length=255)


class UsersLogin(UsersEmail):
    password: str


class UsersBase(UsersEmail):
    role: str = Field(max_length=50)


class UsersRegister(UsersBase):
    password: str
    telegram_chat_id: int


class Users(UsersBase, table=True):
    __tablename__ = 'users'
    __table_args__ = {'schema': 'public'}
    id: int | None = Field(default=None, primary_key=True)
    date_joined: datetime = Field(
        default_factory=lambda: datetime.now(UTC), sa_column=Column(TIMESTAMP(timezone=True))
    )
    hashed_password: str
    auth_method: str
    yandex_id: str

class UsersPublic(UsersBase):
    id: int
    date_joined: datetime


class LoginHistory(SQLModel, table=True):
    __tablename__ = "login_history"
    __table_args__ = {'schema': 'public'}
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="public.users.id")
    login_time: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(TIMESTAMP(timezone=True)),
    )
