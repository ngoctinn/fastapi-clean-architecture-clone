import uuid
from pydantic import BaseModel, EmailStr
from typing import List

from src.exceptions import AuthenticationError


class RegisterUserRequest(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    user_id: str | None = None
    roles: List[str] = []

    def get_uuid(self) -> uuid.UUID:
        if self.user_id:
            return uuid.UUID(self.user_id)
        raise AuthenticationError("User ID not found in token_type")

