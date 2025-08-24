from fastapi import FastAPI
from contextlib import asynccontextmanager
from sqlmodel import Session, select

from .database.core import create_db_and_tables, engine
from .api import register_routes
from .logging import configure_logging, LogLevels
from .models.rbac import Role


def create_initial_roles():
    """Tạo các vai trò mặc định nếu chúng chưa tồn tại."""
    with Session(engine) as session:
        roles_to_create = [
            {"name": "admin", "description": "Administrator with all permissions"},
            {"name": "staff", "description": "Spa staff member"},
            {"name": "customer", "description": "Registered customer"},
        ]

        for role_data in roles_to_create:
            statement = select(Role).where(Role.name == role_data["name"])
            if not session.exec(statement).first():
                role = Role(**role_data)
                session.add(role)

        session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting up...")
    create_db_and_tables()
    create_initial_roles()
    yield
    print("Shutting down...")


configure_logging(LogLevels.info)

app = FastAPI(lifespan=lifespan)

register_routes(app)

