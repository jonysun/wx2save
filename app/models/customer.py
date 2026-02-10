# app/models/customer.py
"""
Customer model for caching WeCom external contact information
"""
import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from app.models.base import Base

class Customer(Base):
    """微信客户信息缓存"""
    __tablename__ = 'customers'

    id = Column(Integer, primary_key=True)
    external_userid = Column(String(128), unique=True, index=True) # 外部联系人ID
    nickname = Column(String(128), nullable=True) # 微信昵称
    avatar = Column(String(512), nullable=True) # 头像URL
    gender = Column(Integer, nullable=True) # 0-未知 1-男性 2-女性
    
    # 扩展字段 (JSON)
    # 存储 corp_name, corp_full_name, type, etc.
    extra_info = Column(Text, nullable=True) 

    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'external_userid': self.external_userid,
            'nickname': self.nickname,
            'avatar': self.avatar,
            'gender': self.gender,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
