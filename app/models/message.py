# app/models/message.py
"""
Message models for WeCom message storage
"""
import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime
from app.models.base import Base


class Message(Base):
    """消息模型"""
    __tablename__ = 'messages'

    id = Column(String(64), primary_key=True, default=lambda: f"msg_{datetime.datetime.now().timestamp()}")
    msgid = Column(String(128), unique=True, index=True)  # 企业微信msgid
    open_kfid = Column(String(64), index=True)  # 客服账号ID
    external_userid = Column(String(128), index=True)  # 客户ID
    servicer_userid = Column(String(128), nullable=True)  # 接待人员ID
    msgtype = Column(String(32), index=True)  # 消息类型

    # 文件专用字段
    original_filename = Column(String(512), nullable=True)  # 原始文件名
    file_extension = Column(String(10), nullable=True)  # 文件扩展名
    file_size = Column(Integer, nullable=True)  # 文件大小（字节）
    file_mime_type = Column(String(100), nullable=True)  # MIME类型
    file_hash = Column(String(64), nullable=True)  # 文件哈希值

    # 下载统计字段
    download_count = Column(Integer, default=0)  # 成功下载次数
    download_status = Column(String(20), default='pending')  # 下载状态
    download_error = Column(Text, nullable=True)  # 下载错误信息
    last_download_time = Column(DateTime, nullable=True)  # 最后下载时间

    send_time = Column(DateTime, index=True)  # 发送时间
    origin = Column(Integer)  # 消息来源：3-客户 4-事件 5-接待人员
    content = Column(Text, nullable=True)  # 文本内容
    media_id = Column(String(128), nullable=True)  # 媒体ID
    media_path = Column(String(512), nullable=True)  # 本地存储路径
    media_url = Column(String(512), nullable=True)  # 访问URL

    extra_data = Column(Text, nullable=True)  # 额外数据（JSON字符串）
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'msgid': self.msgid,
            'open_kfid': self.open_kfid,
            'external_userid': self.external_userid,
            'servicer_userid': self.servicer_userid,
            'msgtype': self.msgtype,
            'send_time': self.send_time.isoformat() if self.send_time else None,
            'origin': self.origin,
            'content': self.content,
            'media_id': self.media_id,
            'media_path': self.media_path,
            'media_url': self.media_url,

            # 文件信息
            'original_filename': self.original_filename,
            'file_extension': self.file_extension,
            'file_size': self.file_size,
            'file_mime_type': self.file_mime_type,
            'file_hash': self.file_hash,

            # 下载统计
            'download_count': self.download_count,
            'download_status': self.download_status,
            'download_error': self.download_error,
            'last_download_time': self.last_download_time.isoformat() if self.last_download_time else None,

            'extra_data': self.extra_data,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class DeletedMessage(Base):
    """已删除消息记录（用于去重）"""
    __tablename__ = "deleted_messages"

    id = Column(Integer, primary_key=True, index=True)
    msgid = Column(String, unique=True, index=True)
    deleted_at = Column(DateTime, default=datetime.datetime.utcnow)
    note = Column(String, nullable=True)  # 可选：记录是谁删除的，或者备注

