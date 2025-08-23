from sqlmodel import create_engine, Session, SQLModel
from typing import Generator, Annotated
from fastapi import Depends
import os
from dotenv import load_dotenv

load_dotenv()

# DATABASE_URL = os.getenv("DATABASE_URL")

DATABASE_URL = "sqlite:///./todosapp.db"

# DATABASE_URL="postgresql://postgres:postgres@db:5432/cleanfastapi"

engine = create_engine(DATABASE_URL, echo=True)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session

DbSession = Annotated[Session, Depends(get_session)]