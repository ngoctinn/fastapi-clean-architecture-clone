from datetime import timedelta, datetime, timezone
from typing import Annotated, List
from uuid import UUID, uuid4
from fastapi import Depends, HTTPException
from passlib.context import CryptContext
import jwt
from jwt import PyJWKError
from sqlmodel import Session, select 
from src.models.rbac import User, Role
from . import schemas
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from ..exceptions import AuthenticationError
import logging

SECRET_KEY = '197b2c37c391bed93fe80344fe73b806947a65e36206e05a1a23c2fa12702fe3'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return bcrypt_context.hash(password)

def authenticate_user(session: Session, email: str, password: str) -> User | None:
    user = session.exec(select(User).where(User.email == email)).first()
    if not user or not verify_password(password, user.password_hash):
        logging.warning(f"Failed authentication attempt for email: {email}")
        return None
    return user

def create_access_token(user: User, expires_delta: timedelta) -> str:
    roles = [role.name for role in user.roles]
    encode = {
        'sub': user.email,
        'id': str(user.id),
        'roles': roles,
        'exp': datetime.now(timezone.utc) + expires_delta
    }
    return jwt.encode(encode, SECRET_KEY, algorithm= ALGORITHM)

def verify_token(token: str) -> schemas.TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get('id')
        roles: List[str] = payload.get('roles', [])
        if user_id is None:
            raise AuthenticationError("User ID not in token")
        return schemas.TokenData(user_id=user_id, roles=roles)
    except PyJWKError as e:
        logging.warning(f"Token verification failed: {str(e)}")
        raise AuthenticationError()
    
def register_user(session: Session, register_request: schemas.RegisterUserRequest) -> User:
    try:
        # Tìm vai trò "customer" mặc định
        customer_role = session.exec(select(Role).where(Role.name == "customer")).first()
        if not customer_role:
            raise HTTPException(status_code=500, detail="Default role 'customer' not found.")

        db_user = User(
            email=register_request.email,
            first_name=register_request.first_name,
            last_name=register_request.last_name,
            password_hash=get_password_hash(register_request.password),
            roles=[customer_role] # Gán vai trò mặc định
        )
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        return db_user
    except Exception as e:
        session.rollback()
        logging.error(f"Failed to register user: {register_request.email}. Error: {str(e)}")
        raise

def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]) -> schemas.TokenData:
    return verify_token(token)

CurrentUser = Annotated[schemas.TokenData, Depends(get_current_user)]

def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: Session) -> schemas.Token:
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise AuthenticationError("Incorrect email or password")
    
    token = create_access_token(user, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return schemas.Token(access_token=token, token_type="bearer")

                           