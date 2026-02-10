# app/models/cursor.py
"""
Message cursor and download token models
"""
import datetime
import uuid
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from app.models.base import Base


class MessageCursor(Base):
    """消息游标模型"""
    __tablename__ = 'message_cursors'

    id = Column(Integer, primary_key=True)
    open_kfid = Column(String(64), unique=True, index=True)  # 客服账号ID
    cursor = Column(String(128), nullable=True)  # 当前cursor值
    last_cursor = Column(String(128), nullable=True)  # 上次成功使用的cursor
    last_sync_time = Column(DateTime, default=datetime.datetime.utcnow)  # 最后同步时间
    status = Column(String(20), default='active')  # active, error, disabled
    error_count = Column(Integer, default=0)  # 连续错误次数
    last_error_message = Column(Text, nullable=True)  # 最后错误信息

    def to_dict(self):
        return {
            'open_kfid': self.open_kfid,
            'cursor': self.cursor,
            'last_cursor': self.last_cursor,
            'last_sync_time': self.last_sync_time.isoformat() if self.last_sync_time else None,
            'status': self.status,
            'error_count': self.error_count,
            'last_error_message': self.last_error_message
        }


class DownloadToken(Base):
    """文件下载令牌"""
    __tablename__ = "download_tokens"

    id = Column(Integer, primary_key=True)
    token = Column(String(64), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    message_id = Column(String(64), ForeignKey('messages.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    max_downloads = Column(Integer, default=5)
    current_downloads = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    
    # 关系
    # user = relationship("User")
    # message = relationship("Message")

    def to_dict(self):
        return {
            "token": self.token,
            "expires_at": self.expires_at.isoformat(),
            "max_downloads": self.max_downloads,
            "current_downloads": self.current_downloads
        }

