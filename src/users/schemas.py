from pydantic import BaseModel, EmailStr
import uuid

class RoleBase(BaseModel):
    name: str
    description: str

class RoleRead(RoleBase):
    id: int

class UserBase(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str

class UserRead(UserBase):
    id: uuid.UUID
    is_active: bool

class UserReadWithRoles(UserRead):
    roles: list[RoleRead] = []

class PasswordChange(BaseModel):
    current_password: str
    new_password: str
    new_password_confirm: str

