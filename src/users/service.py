from uuid import UUID
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql import roles
from . import schemas
from sqlmodel import Session, select
from src.models.rbac import User
from src.exceptions import (
    UserNotFoundError,
    PasswordMismatchError,
)
from src.auth.service import verify_password, get_password_hash
import logging


def get_user_by_id_with_roles(db: Session, user_id: UUID) -> User:
    user = db.exec(
        select(User).where(User.id == user_id).options((selectinload(User.roles)))
    ).first()
    if not user:
        logging.warning(f"User not found with ID: {user_id}")
        raise UserNotFoundError(user_id)
    logging.info(f"Successfull return user with ID:{user_id}")
    return user


def get_user_by_id(db: Session, user_id: UUID) -> User:
    user = db.exec(select(User).where(User.id == user_id)).first()
    if not user:
        logging.warning(f"User not found with ID: {user_id}")
        raise UserNotFoundError(user_id)
    logging.info(f"Successfull retrieved user with ID: {user_id}")
    return user


def change_password(
    db: Session, user_id: UUID, password_change: schemas.PasswordChange
) -> None:
    try:
        user = get_user_by_id(db, user_id)

        if not verify_password(password_change.current_password, user.password_hash):
            logging.warning(
                f"Password mismatch during change attempt for user ID: {user_id}"
            )
            raise PasswordMismatchError()

        user.password_hash = get_password_hash(password_change.new_password)
        db.commit()
        logging.info(f"Successfully changed password for user ID: {user_id}")
    except Exception as e:
        logging.error(f"Error during password change for user ID: {user_id}.")
        raise
