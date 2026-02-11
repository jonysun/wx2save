# app/services/__init__.py
"""
Business Services

This module provides backwards compatibility with the old services.py
by re-exporting functions that are still needed by legacy code.
"""
import os
import logging
import datetime
import requests
import time
import json
import mimetypes
import re
import hashlib
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from passlib.context import CryptContext
from jose import jwt
from app.models import User, Message, MessageCursor
from app.core.config import (
    CORP_ID, CORP_SECRET, SECRET_KEY, ALGORITHM, MEDIA_STORAGE_PATH, DATABASE_URL,
    WECOM_API_BASE_URL, WECOM_API_PROXY_TOKEN
)

logger = logging.getLogger("wecom")

# ----------------------
# 全局启动时间 (用于强制登出)
# ----------------------
APP_START_TIME = str(datetime.datetime.utcnow().timestamp())

# ----------------------
# 全局缓存
# ----------------------
_access_token_cache = {
    'token': None,
    'expires_at': 0
}

# ----------------------
# 文件存储配置
# ----------------------
os.makedirs(MEDIA_STORAGE_PATH, exist_ok=True)

# ----------------------
# 数据库会话管理 (backwards compatibility)
# ----------------------
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))


def get_db_for_async():
    """获取用于异步操作的数据库会话 - 修正为生成器模式"""
    db = SessionLocal()
    try:
        yield db  # 🔥 确保这是生成器
    finally:
        db.close()


# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict):
    """创建JWT token"""
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# ---- WeCom API Functions ----

def _get_api_headers():
    """获取API请求头 (包含安全Token)"""
    headers = {}
    if WECOM_API_PROXY_TOKEN:
        headers['X-Antigrv-Token'] = WECOM_API_PROXY_TOKEN
    return headers


def get_cached_access_token():
    """获取企业微信access_token（带缓存）"""
    global _access_token_cache
    
    now = time.time()
    if _access_token_cache['token'] and now < _access_token_cache['expires_at']:
        logger.debug(f"Using cached access_token")
        return _access_token_cache['token']
    
    url = f"{WECOM_API_BASE_URL}/cgi-bin/gettoken?corpid={CORP_ID}&corpsecret={CORP_SECRET}"
    
    try:
        response = requests.get(url, headers=_get_api_headers(), timeout=10)
        result = response.json()
        
        if result.get('errcode') == 0:
            token = result['access_token']
            expires_in = result.get('expires_in', 7200)
            
            _access_token_cache['token'] = token
            _access_token_cache['expires_at'] = now + expires_in - 300
            
            logger.info(f"✅ Got new access_token (expires in {expires_in}s)")
            return token
        else:
            logger.error(f"❌ Failed to get access_token: {result}")
            return None
    except Exception as e:
        logger.error(f"❌ Exception getting access_token: {str(e)}")
        return None


def download_media_file(media_id, msgtype=None):
    """
    下载媒体文件
    Returns: (content, filename)
    """
    access_token = get_cached_access_token()
    if not access_token:
        logger.error("❌ Failed to get access_token for media download")
        return None, None
        
    url = f"{WECOM_API_BASE_URL}/cgi-bin/media/get?access_token={access_token}&media_id={media_id}"
    
    try:
        response = requests.get(url, headers=_get_api_headers(), timeout=30)
        
        if response.status_code == 200:
            # 尝试从Content-Disposition获取文件名 (支持中文 filename*=utf-8'')
            filename = ""
            if "Content-Disposition" in response.headers:
                cd = response.headers["Content-Disposition"]
                
                # 1. 优先尝试 RFC 5987 标准 (filename*=utf-8''...)
                if "filename*=" in cd:
                    try:
                        # 示例: attachment; filename*=utf-8''%E4%B8%AD%E6%96%87.txt
                        file_star = cd.split("filename*=")[1].split(";")[0].strip('"').strip()
                        if file_star.lower().startswith("utf-8''"):
                            from urllib.parse import unquote
                            filename = unquote(file_star[7:])
                    except Exception as e:
                        logger.warning(f"Failed to parse filename*: {e}")
                
                # 2. 如果没获取到，尝试标准 filename="..."
                if not filename and 'filename="' in cd:
                    try:
                        filename = cd.split('filename="')[1].split('"')[0]
                        # 此时可能是被 urlencoded 的 ASCII 乱码 (如 %E4%...)
                        if "%" in filename:
                             from urllib.parse import unquote
                             try:
                                 decoded_name = unquote(filename)
                                 # 简单的启发式检查：解码后变短了且没有乱码特征？
                                 # 这里主要应对部分服务器把中文直接urlencode放入filename的情况
                                 filename = decoded_name
                             except:
                                 pass
                        
                        # 处理 ISO-8859-1 误读 (常见的中文乱码来源: åä...)
                        try:
                            # 尝试将其视为 latin1 读取 bytes，再按 utf-8 解码
                            # 注意: 这是一种猜测，不一定对，但能解决很多 requests 默认 latin1 解码导致的问题
                            filename_bytes = filename.encode('latin1')
                            filename_utf8 = filename_bytes.decode('utf-8')
                            filename = filename_utf8
                        except:
                            pass # 转换失败则保持原样

                    except Exception as parse_e:
                        logger.warning(f"Failed to parse filename section: {parse_e}")

                # 3. 最后的降级 filename=...
                elif not filename and 'filename=' in cd:
                    filename = cd.split('filename=')[1].split(';')[0].strip()
            
            logger.info(f"✅ Downloaded media {media_id}: {len(response.content)} bytes, filename={filename}")
            return response.content, filename
            
            logger.info(f"✅ Downloaded media {media_id}: {len(response.content)} bytes, filename={filename}")
            return response.content, filename
        else:
            # Mask token in URL for logging
            safe_url = url.replace(access_token, "******")
            logger.error(f"❌ Failed to download media {media_id}: Status={response.status_code}, URL={safe_url}, Response={response.text[:200]}")
            return None, None
    except Exception as e:
        safe_url = url.replace(access_token, "******") if 'access_token' in locals() and access_token else "unknown"
        logger.error(f"❌ Exception downloading media {media_id}: {str(e)} | URL={safe_url}")
        return None, None


def save_media_file(media_content, file_info):
    """
    保存媒体文件到本地
    
    Args:
        media_content: 文件二进制内容
        file_info: 文件信息字典，包含 filename, extension, mime_type 等
    
    Returns:
        dict: 包含 path 和 url 的字典
    """
    try:
        # 生成唯一文件名
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        random_str = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:8]
        filename = file_info.get('filename', f'file_{timestamp}_{random_str}')
        extension = file_info.get('extension', '')
        
        # 确保文件名有扩展名
        if extension and not filename.endswith(f'.{extension}'):
            filename = f"{filename}.{extension}"
        
        # 保存到对应类型的子目录
        msgtype = file_info.get('msgtype', 'file')
        type_dir = os.path.join(MEDIA_STORAGE_PATH, msgtype)
        os.makedirs(type_dir, exist_ok=True)
        
        # 完整文件路径
        file_path = os.path.join(type_dir, filename)
        
        # 写入文件
        with open(file_path, 'wb') as f:
            f.write(media_content)
        
        # 生成访问URL（相对路径）
        relative_path = os.path.join(msgtype, filename).replace('\\', '/')
        media_url = f"/media/{relative_path}"
        
        logger.info(f"✅ Saved media file: {file_path}")
        
        return {
            'path': file_path,
            'url': media_url,
            'size': len(media_content)
        }
    except Exception as e:
        logger.error(f"❌ Failed to save media file: {str(e)}")
        return None


# ---- Message Cursor Functions ----

def get_cursor_for_kfid(open_kfid, db):
    """获取指定客服账号的cursor"""
    cursor_obj = db.query(MessageCursor).filter(MessageCursor.open_kfid == open_kfid).first()
    if cursor_obj:
        return cursor_obj.cursor
    return None


def update_cursor_for_kfid(open_kfid, new_cursor, db):
    """更新指定客服账号的cursor"""
    cursor_obj = db.query(MessageCursor).filter(MessageCursor.open_kfid == open_kfid).first()
    
    if cursor_obj:
        cursor_obj.last_cursor = cursor_obj.cursor
        cursor_obj.cursor = new_cursor
        cursor_obj.last_sync_time = datetime.datetime.utcnow()
        cursor_obj.status = 'active'
        cursor_obj.error_count = 0
        cursor_obj.last_error_message = None
    else:
        cursor_obj = MessageCursor(
            open_kfid=open_kfid,
            cursor=new_cursor,
            last_cursor=None,
            last_sync_time=datetime.datetime.utcnow(),
            status='active',
            error_count=0
        )
        db.add(cursor_obj)
    
    db.commit()
    logger.info(f"✅ Updated cursor for {open_kfid}: {new_cursor[:20]}...")
    return True


def reload_wecom_config():
    """
    热加载：刷新本模块中缓存的 WeCom 配置变量，清空 access_token 缓存。
    """
    global CORP_ID, CORP_SECRET, WECOM_API_BASE_URL, WECOM_API_PROXY_TOKEN
    global _access_token_cache

    from app.core.config import (
        CORP_ID as _cid, CORP_SECRET as _cs,
        WECOM_API_BASE_URL as _url, WECOM_API_PROXY_TOKEN as _pt
    )
    CORP_ID = _cid
    CORP_SECRET = _cs
    WECOM_API_BASE_URL = _url
    WECOM_API_PROXY_TOKEN = _pt

    # 清空旧的 access_token（旧凭据已失效）
    _access_token_cache = {'token': None, 'expires_at': 0}

    logger.info("🔄 WeCom config reloaded (services/__init__.py), access_token cache cleared.")


__all__ = [
    "APP_START_TIME",
    "get_db_for_async",
    "verify_password",
    "get_password_hash",
    "create_access_token",
    "get_cached_access_token",
    "download_media_file",
    "save_media_file",
    "get_cursor_for_kfid",
    "update_cursor_for_kfid",
    "reload_wecom_config",
    "engine",
    "SessionLocal"
]
