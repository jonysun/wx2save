# app/models/user.py
"""
User model for authentication and authorization
"""
import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from app.models.base import Base


class User(Base):
    """用户模型"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(200), nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    first_login = Column(Boolean, default=True)  # 首次登录标记
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_password_change = Column(DateTime, nullable=True)
    last_login_ip = Column(String(50), nullable=True)
    last_login_time = Column(DateTime, nullable=True)
    token_version = Column(Integer, default=1, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "is_active": self.is_active,
            "is_superuser": self.is_superuser,
            "first_login": self.first_login,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_password_change": self.last_password_change.isoformat() if self.last_password_change else None,
            "last_login_ip": self.last_login_ip,
            "last_login_time": self.last_login_time.isoformat() if self.last_login_time else None
        }

