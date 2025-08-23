import uuid
from typing import List, Optional
from sqlmodel import Field, Relationship, SQLModel


class UserRoleLink(SQLModel, table=True):
    """Bảng trung gian kết nối User và Role."""
    user_id: uuid.UUID = Field(foreign_key="user.id", primary_key=True)
    role_id: int = Field(foreign_key="role.id", primary_key=True)

class Role(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    description: str

    users: List["User"] = Relationship(back_populates="roles", link_model=UserRoleLink)

class User(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)
    email: str = Field(unique=True, index=True)
    first_name: str
    last_name: str
    password_hash: str
    is_active: bool = Field(default=True)

    roles: List[Role] = Relationship(back_populates="users", link_model=UserRoleLink)