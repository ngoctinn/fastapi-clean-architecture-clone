from typing import List
from fastapi import APIRouter, Depends, status
from sqlmodel import select

from src.auth import schemas
from src.exceptions import UserNotFoundError
from src.models.rbac import User
from ..database.core import DbSession
from . import schemas as user_schemas
from . import service
from ..auth.service import CurrentUser
from src.auth.dependencies import RoleChecker

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/me", response_model=user_schemas.UserReadWithRoles)
def get_current_user_details(current_user_data: CurrentUser, db: DbSession):
    user_id = current_user_data.get_uuid()
    user = db.get(User, user_id)
    if not user:
        raise UserNotFoundError(user_id)
    return user


@router.get(
    "/",
    response_model=List[user_schemas.UserReadWithRoles],
    dependencies=[Depends(RoleChecker(["admin"]))],
)
def get_all_users(db: DbSession):
    users = db.exec(select(User)).all()
    return users


# Endpoint này dành cho ADMIN hoặc STAFF
@router.get(
    "/staff-info",
    response_model=dict,
    dependencies=[Depends(RoleChecker(["admin", "staff"]))],
)
def get_staff_info():
    return {"message": "This is sensitive staff information."}


@router.put("/change-password", status_code=status.HTTP_200_OK)
def change_password(
    password_change: user_schemas.PasswordChange,
    db: DbSession,
    current_user: CurrentUser,
):
    service.change_password(db, current_user.get_uuid(), password_change)

