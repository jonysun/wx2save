# app/core/database.py
"""
Database connection and session management
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import DATABASE_URL
import logging

logger = logging.getLogger("wecom")

# Create database engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # SQLite specific
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    """
    Database dependency for FastAPI routes
    Yields a database session and ensures it closes after use
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_for_async():
    """
    Get database session for async/background tasks
    Returns a session that must be manually closed
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
