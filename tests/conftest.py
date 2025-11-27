import pytest
from fastapi.testclient import TestClient
from main import app
from app.config import database
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.config.database import Base
import os


TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# override
database.engine = engine
database.SessionLocal = TestingSessionLocal
Base.metadata.create_all(bind=engine)

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c
