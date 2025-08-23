import uuid
from pydantic import BaseModel, EmailStr
from typing import List, Optional

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

    def get_uuid(self) ->Optional[uuid.UUID]:
        if self.user_id:
            return uuid.UUID(self.user_id)
        return None