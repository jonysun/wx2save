# app/main.py
import logging
import os
import datetime
import json
import time
import sys
import threading
import string  # 🔥 关键添加：用于密码生成
from typing import List, Optional
from fastapi import FastAPI, Request, HTTPException, status, Depends, Response, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse, StreamingResponse
from pydantic import BaseModel
from app.models import Base, Message, MessageCursor, User, DownloadToken
from app import __version__

# ...




# ----------------------
# CSRF 令牌端点
# ... (rest of file)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
import requests
import xml.etree.ElementTree as ET
from urllib.parse import quote
from fastapi.security import OAuth2PasswordRequestForm
import secrets
import secrets
from jose import jwt, JWTError

# ----------------------
# 配置和数据库
# ----------------------
from app.core.config import (
    TOKEN, ENCODING_AES_KEY, CORP_ID, DATABASE_URL, MEDIA_STORAGE_PATH, 
    SECRET_KEY, ALGORITHM, CALLBACK_STATUS,
    LOG_LEVEL, LOG_ROTATION, LOG_MAX_BYTES, LOG_BACKUP_COUNT, LOG_DIR, _config,
    save_config, SHOW_DEBUG_INFO
)
from app.models import Base, Message, MessageCursor, User, DeletedMessage, DownloadToken, Customer
from app.services import get_cached_access_token, get_db_for_async, verify_password, get_password_hash
from app.services.storage_service import storage
from app.services.wecom_service import verify_url, parse_xml_message, handle_customer_service_event, batch_get_customer_info
from app.utils.crypto import WXBizMsgCrypt
# auth routes are now inline, no separate setup

# ----------------------
# 日志配置
# ----------------------
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

# Docker环境/本地环境统一使用配置文件中的 LOG_DIR
# 在 config.py 中已处理了 LOG_DIR 的生成 (默认 app/logs 或 环境变量 LOG_DIR)
# 且已确保目录存在: os.makedirs(LOG_DIR, exist_ok=True)
log_file = os.path.join(LOG_DIR, "wecom.log")

# 配置日志级别
log_level = getattr(logging, LOG_LEVEL, logging.INFO)

# 创建日志处理器
handlers = []

# 1. 控制台处理器（实时输出到Docker日志和终端）
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(log_level)
console_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
console_handler.setFormatter(console_formatter)
handlers.append(console_handler)

# 2. 文件处理器（带轮转，使用 .log.1 格式）
if LOG_ROTATION == 'size':
    # 按大小轮转 - 使用 RotatingFileHandler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    # RotatingFileHandler 默认就是 .log.1, .log.2 格式
else:
    # 按天轮转 - 使用自定义格式
    # TimedRotatingFileHandler 默认是 .YYYY-MM-DD，我们改为 .log.1 格式
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=LOG_MAX_BYTES,  # 同样设置大小限制
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8'
    )

file_handler.setLevel(log_level)
file_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
file_handler.setFormatter(file_formatter)
handlers.append(file_handler)

# 配置根日志器
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=handlers,
    force=True  # 强制重新配置
)

logger = logging.getLogger("wecom")
logger.info("="*60)
logger.info(f"🚀 WeCom Message Management System Starting...")
logger.info(f"📊 Log Level: {LOG_LEVEL}")
logger.info(f"📋 Log Rotation: {LOG_ROTATION} (max {LOG_BACKUP_COUNT} backups)")
logger.info(f"📁 Log File: {log_file}")
logger.info("="*60)

# ----------------------
# 数据库配置
# ----------------------
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base.metadata.create_all(bind=engine)


# ----------------------
# 依赖项
# ----------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ----------------------
# FastAPI 应用
# ----------------------
from app import __version__
app = FastAPI(title="企业微信消息管理平台", version=__version__)

# secret_key = os.environ.get("SESSION_SECRET_KEY")
import secrets
# Session Secret Key
# If not set in env, generate a random one on startup.
# This ensures that all existing sessions are invalidated on server restart (Security Feature).
SECRET_KEY = os.environ.get("SESSION_SECRET_KEY") or secrets.token_urlsafe(32)
secret_key = SECRET_KEY # Alias for compatibility

# Cookie Security Flag (Default to False for local dev, set SECURE_AUTH=true for prod)
SECURE_COOKIES = os.getenv("SECURE_AUTH", "False").lower() == "true"

@app.on_event("startup")
async def startup_event():
    """System Startup Tasks"""
    logger.info("🚀 System starting up...")
    
    # 1. Invalidate all download tokens on restart
    db = SessionLocal()
    try:
        # Import model locally to avoid circular imports if any (though usually defined)
        # Assuming DownloadToken is available via imports at top or can be imported from app.models
        from app.models.cursor import DownloadToken
        
        # Mark all active tokens as expired/inactive
        count = db.query(DownloadToken).filter(DownloadToken.is_active == True).update({DownloadToken.is_active: False})
        db.commit()
        logger.info(f"🔒 Invalidated {count} leftover download tokens from previous session")
        
        # 2. Check S3 Connection (Optional, but good for logs)
        if _config.get('storage', {}).get('s3_enabled'):
            asyncio.create_task(monitor_s3_connection())

        # 3. Restore Last Sync Time from DB
        # Query the most recent sync time from MessageCursor
        from app.models.cursor import MessageCursor
        # Use first() since typically we have one active cursor, or order by last_sync_time
        cursor_record = db.query(MessageCursor).order_by(MessageCursor.last_sync_time.desc()).first()
        if cursor_record and cursor_record.last_sync_time:
            CALLBACK_STATUS['last_check'] = cursor_record.last_sync_time
            logger.info(f"🔄 Restored last sync time: {cursor_record.last_sync_time}")
            
            
    except Exception as e:
        logger.error(f"⚠️ Startup cleanup failed: {e}")
    finally:
        db.close()


# ----------------------
# Middleware: Security Headers & Rate Limiting
# ----------------------
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict
import time

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ----------------------
# Middleware: CORS & Trusted Host
# ----------------------
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

# 1. Trusted Host (Prevent Host Header Injection)
# In production, restrict this to your actual domain(s)
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["*"] # TODO: Change to specific domains in production, e.g. ["example.com", "*.example.com"]
)

# 2. CORS (Cross-Origin Resource Sharing)
# Restrict which domains can make API calls to us
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple Rate Limiting (Global Store)
# IP -> [timestamp1, timestamp2, ...]
rate_limit_store = defaultdict(list)
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 60  # seconds

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # 排除 WebSocket 握手请求 (Upgrade header)
        if request.headers.get("upgrade", "").lower() == "websocket":
             return await call_next(request)

        client_ip = request.client.host
        now = time.time()
        
        # Clean up old requests
        rate_limit_store[client_ip] = [t for t in rate_limit_store[client_ip] if now - t < RATE_LIMIT_WINDOW]
        
        # Check limit
        if len(rate_limit_store[client_ip]) >= RATE_LIMIT_REQUESTS:
             return JSONResponse(status_code=429, content={"detail": "Too many requests"})
             
        rate_limit_store[client_ip].append(now)
        return await call_next(request)

app.add_middleware(RateLimitMiddleware)


# 挂载静态文件
app.mount("/static", StaticFiles(directory="static"), name="static")


from fastapi import WebSocket, WebSocketDisconnect

# WebSocket 连接管理器
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"🔌 Client connected: {websocket.client}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"🔌 Client disconnected: {websocket.client}")

    async def broadcast(self, message: str):
        logger.info(f"📢 Broadcasting message to {len(self.active_connections)} clients")
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass

manager = ConnectionManager()

@app.websocket("/ws/notifications")
async def websocket_endpoint(websocket: WebSocket):
    logger.info("⚡ WebSocket connection attempt...")
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"❌ WebSocket error: {e}")
        manager.disconnect(websocket)

@app.get("/media/{file_path:path}")
async def secure_media_access(request: Request, file_path: str):
    """带鉴权的媒体文件访问 (用于图片/视频预览)"""
    not_found_exception = HTTPException(status_code=404, detail="File not found")
    
    token = request.session.get("access_token") or request.cookies.get("access_token")
    if not token:
        raise not_found_exception
        
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except:
        raise not_found_exception

    # 防止路径遍历 (Path Traversal Protection)
    # 1. Basic check for '..'
    if ".." in file_path:
        raise not_found_exception
        
    # 2. Strict absolute path check
    # os.path.join ignores previous components if a component is an absolute path
    # So we must sanitize or check the final result
    base_dir = os.path.abspath(MEDIA_STORAGE_PATH)
    full_path = os.path.abspath(os.path.join(base_dir, file_path))
    
    # Ensure the resolved path starts with the expected base directory
    if not full_path.startswith(base_dir):
        logger.warning(f"⚠️ Path traversal attempt detected: {file_path} -> {full_path}")
        raise not_found_exception

    if not os.path.exists(full_path):
        raise not_found_exception

    return FileResponse(full_path)


@app.post("/api/messages/batch/delete")
async def batch_delete_messages(request: Request):
    """批量删除消息"""
    data = await request.json()
    msg_ids = data.get("msg_ids", [])
    delete_files = data.get("delete_files", False)
    
    if not msg_ids:
         raise HTTPException(status_code=400, detail="No message IDs provided")
         
    db = SessionLocal()
    try:
        deleted_count = 0
        from app.models import DeletedMessage
        
        for msg_id in msg_ids:
            message = db.query(Message).filter(Message.msgid == msg_id).first()
            if message:
                # 1. 物理文件删除
                if delete_files and message.media_path and os.path.exists(message.media_path):
                    try:
                        os.remove(message.media_path)
                    except Exception as e:
                        logger.error(f"Failed to delete file {message.media_path}: {e}")
                
                # 2. 数据库删除
                db.delete(message)
                
                # 3. 添加到黑名单 (防止重新同步)
                if not db.query(DeletedMessage).filter(DeletedMessage.msgid == msg_id).first():
                    dm = DeletedMessage(msgid=msg_id, note="Batch deleted")
                    db.add(dm)
                    
                deleted_count += 1
        
        db.commit()
        return {"status": "success", "deleted_count": deleted_count}
    finally:
        db.close()

@app.post("/api/messages/batch/download")
async def batch_download_messages(request: Request):
    """批量下载 (打包成ZIP)"""
    data = await request.json()
    msg_ids = data.get("msg_ids", [])
     
    if not msg_ids:
         raise HTTPException(status_code=400, detail="No message IDs provided")

    import zipfile
    import io
    
    db = SessionLocal()
    try:
        # 创建内存ZIP
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for msg_id in msg_ids:
                message = db.query(Message).filter(Message.msgid == msg_id).first()
                if message and message.media_path:
                    file_path = message.media_path
                    
                    # 1. 尝试直接访问
                    if not os.path.exists(file_path):
                        # 2. 如果是绝对路径且在Windows下 (e.g. /app/media_files/...)
                        # 尝试移除 /app 前缀，或者映射到本地 media_files
                        if file_path.startswith("/app/"):
                            # 尝试相对路径: media_files/2026/...
                            # 假设 /app/media_files -> ./media_files
                            rel_path = file_path.replace("/app/", "./")
                            if os.path.exists(rel_path):
                                file_path = rel_path
                            else:
                                # 尝试直接取文件名在 media_files 下查找
                                basename = os.path.basename(file_path)
                                candidate = os.path.join(MEDIA_STORAGE_PATH, basename)
                                if os.path.exists(candidate):
                                    file_path = candidate
                                else:
                                    # 尝试在 media_files/file 下查找 (部分旧数据)
                                    candidate_file = os.path.join(MEDIA_STORAGE_PATH, "file", basename)
                                    if os.path.exists(candidate_file):
                                        file_path = candidate_file
                    
                    if os.path.exists(file_path):
                        # 使用原始文件名或UUID文件名
                        filename = message.original_filename or os.path.basename(message.media_path)
                        # 避免重名
                        arcname = f"{msg_id}_{filename}"
                        zf.write(file_path, arcname)
                    else:
                        logger.warning(f"⚠️ Batch download: File not found for msg {msg_id}: {message.media_path}")
        
        memory_file.seek(0)
        return Response(
            content=memory_file.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename=batch_download_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.zip"}
        )
    finally:
        db.close()

@app.post("/api/messages/{msg_id}/retry_download")
async def retry_download_message(request: Request, msg_id: str):
    """重试下载消息媒体文件"""
    db = SessionLocal()
    try:
        message = db.query(Message).filter(Message.msgid == msg_id).first()
        if not message:
             raise HTTPException(status_code=404, detail="Message not found")
        
        if not message.media_id:
             raise HTTPException(status_code=400, detail="Message has no media_id to download")

        # 重置状态
        message.download_status = 'pending'
        message.download_error = None
        db.commit()

        # 启动后台任务下载 (复用 wecom_service 中的逻辑)
        # 注意：这里需要构造类似 msg_data 的结构
        from app.services.wecom_service import async_download_media, get_file_info_from_message
        
        # 重新构造 info
        # 注意: message.extra_data 存的是 raw msg json
        raw_msg = json.loads(message.extra_data) if message.extra_data else {}
        if not raw_msg:
             # 如果 extra_data 丢失，尝试从 message 字段恢复最基本的结构
             raw_msg = {
                 'msgid': message.msgid,
                 'msgtype': message.msgtype,
                 'open_kfid': message.open_kfid,
                 message.msgtype: {'media_id': message.media_id, 'filename': message.original_filename}
             }

        file_info = get_file_info_from_message(raw_msg)
        
        msg_data = {
            'media_id': message.media_id,
            'msgtype': message.msgtype,
            'msgid': message.msgid,
            'open_kfid': message.open_kfid,
            'file_info': file_info
        }

        # 启动异步线程
        thread = threading.Thread(
            target=async_download_media,
            args=(msg_data,),
            daemon=True
        )
        thread.start()
        
        return {"status": "success", "message": "Download task started"}
    except Exception as e:
        logger.error(f"Retry download failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

# 模板目录
templates = Jinja2Templates(directory="templates")

def from_json(value):
    if not value:
        return None
    try:
        return json.loads(value)
    except:
        return None

templates.env.filters["from_json"] = from_json



# ----------------------
# 会话中间件
# ----------------------
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    max_age=3600,  # 1小时
    same_site="lax",  # 允许重定向时携带cookie
    https_only=False  # 开发环境
)

# setup_auth_routes(app)  # auth routes are now inline
# ----------------------
# 认证相关函数 - 🔥 关键修复：修正函数签名和参数
# ----------------------
def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


# 🔥 关键修复：正确的函数签名和参数名
def create_access_token(data: dict, secret_key: str, algorithm: str) -> str:
    """创建访问令牌"""
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    return encoded_jwt



async def get_current_user_from_token(token: str):
    """从令牌获取当前用户及版本"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        version: int = payload.get("v")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email, version
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ----------------------
# 认证依赖
# ----------------------
from fastapi.security import OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login/submit", auto_error=False)

async def get_token_from_cookie_or_header(
    request: Request,
    token: str = Depends(oauth2_scheme)
):
    if token:
        return token
    return request.cookies.get("access_token")

async def get_current_active_user(
    token: str = Depends(get_token_from_cookie_or_header),
    db: Session = Depends(get_db)
):
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 获取邮箱及版本
    email, token_version = await get_current_user_from_token(token)
    
    # 获取用户
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
        
    # 验证 Token 版本 (单点登录核心逻辑)
    # 如果 Token 中没有版本号 (version is None), 视为旧版 Token -> 失效
    # 如果版本号不匹配 -> 失效
    if token_version is None or token_version != user.token_version:
         raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired (logged in from another location)",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return user


# ----------------------
# 应用启动初始化
# ----------------------
@app.on_event("startup")
async def startup_event():
    """应用启动时执行的初始化任务"""
    logger.info("🚀 启动企业微信消息管理平台...")

    # 1. 初始化数据库
    logger.info("🔧 初始化数据库表结构...")
    logger.info(f"💾 Database URL: {DATABASE_URL}")
    db_path = os.path.abspath("wecom_messages.db")
    logger.info(f"📂 Absolute DB Path: {db_path}")

    # 1.5 数据库迁移 (自动修复缺失列)
    from sqlalchemy import inspect, text
    try:
        inspector = inspect(engine)
        if 'users' in inspector.get_table_names():
            columns = [col['name'] for col in inspector.get_columns('users')]
            if 'token_version' not in columns:
                logger.warning("⚠️  'token_version' column missing in 'users' table. Migrating...")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 1 NOT NULL"))
                logger.info("✅ Migration 'add_token_version' completed.")
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")

    # 2. 初始化管理员账户
    logger.info("👮 初始化管理员账户...")
    # 内联初始化管理员账户
    db = SessionLocal()
    try:
        # 检查管理员账户
        admin = db.query(User).filter(User.email == "admin@example.com").first()
        if not admin:
            # 生成强随机密码
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
            random_password = ''.join(secrets.choice(alphabet) for i in range(16))

            # 创建管理员
            admin = User(
                email="admin@example.com",
                hashed_password=get_password_hash(random_password),
                is_superuser=True,
                is_active=True,
                first_login=True
            )
            db.add(admin)
            db.commit()

            logger.info("✅ 管理员账户初始化完成")
            logger.info("========================================")
            logger.info("🔑 首次登录凭证:")
            logger.info(f"   用户名: admin@example.com")
            logger.info(f"   密码: {random_password}")
            logger.info("========================================")
            logger.info("⚠️  请复制密码，首次登录后系统会强制要求修改密码")
            logger.info("⚠️  出于安全考虑，此密码只会显示一次！")
            logger.info("========================================")
        else:
             logger.info("✅ Admin account already exists. Skipping initialization.")
    finally:
        db.close()

    # 3. 创建必要的目录
    os.makedirs(MEDIA_STORAGE_PATH, exist_ok=True)
    logger.info(f"📁 媒体文件存储目录: {MEDIA_STORAGE_PATH}")
    logger.info(f"📄 日志文件位置: {log_file}")

    logger.info("✅ 应用启动完成！访问 http://localhost:8000/login 开始使用")


# ----------------------
# 根路径重定向
# ----------------------
@app.get("/", response_class=RedirectResponse)
async def root():
    """根路径重定向到登录页"""
    return RedirectResponse(url="/login", status_code=302)


# ----------------------
# 企业微信回调 URL 验证（GET）- 无需认证
# ----------------------
@app.get("/wecom/callback")
async def wecom_verify(
        msg_signature: str,
        timestamp: str,
        nonce: str,
        echostr: str
):
    """企业微信URL验证 - 无需登录认证"""
    logger.info(
        "🎯 Received verify request: sig=%s, ts=%s, nonce=%s, echostr=%s",
        msg_signature,
        timestamp,
        nonce,
        echostr[:20] + "..."
    )

    try:
        # URL解码
        wxcpt = WXBizMsgCrypt(TOKEN, ENCODING_AES_KEY, CORP_ID)
        ret, sEchoStr = wxcpt.VerifyURL(msg_signature, timestamp, nonce, echostr)

        if ret != 0:
            logger.error(f"❌ VerifyURL failed with code: {ret}")
            raise HTTPException(status_code=403, detail="invalid request")

        logger.info("✅ URL verify success, decrypted msg: %r", sEchoStr)
        return sEchoStr

    except Exception as e:
        logger.error("❌ URL verify failed: %s", str(e), exc_info=True)
        raise HTTPException(status_code=403, detail="invalid request")


# ----------------------
# 企业微信消息接收（POST）- 无需认证
# ----------------------
@app.post("/wecom/callback")
async def wecom_message(
    request: Request,
    msg_signature: str,
    timestamp: str,
    nonce: str,
    db: Session = Depends(get_db)
):
    """企业微信消息接收"""
    try:
        body_bytes = await request.body()
        xml_content = body_bytes.decode('utf-8')

        logger.info(
            "📩 Received message callback: sig=%s, ts=%s, nonce=%s, len=%d",
            msg_signature, timestamp, nonce, len(xml_content)
        )

        # 1. 解密消息
        wxcpt = WXBizMsgCrypt(TOKEN, ENCODING_AES_KEY, CORP_ID)
        ret, decrypted_xml = wxcpt.DecryptMsg(xml_content, msg_signature, timestamp, nonce)

        if ret != 0:
            logger.error(f"❌ DecryptMsg failed with code: {ret}")
            raise HTTPException(status_code=403, detail="decrypt failed")

        logger.info("🔓 Message decrypted successfully")

        # 2. 解析XML
        msg_data = parse_xml_message(decrypted_xml.decode('utf-8'))
        logger.info("📄 Parsed message data: %s", json.dumps(msg_data, ensure_ascii=False))

        # 3. 处理消息/事件
        # 这是一个异步处理过程，或者是快速处理
        # 注意：微信要求在5秒内响应，所以耗时操作应该放入后台任务
        
        # 这里直接调用处理函数，如果处理函数中包含耗时操作（如大文件下载），
        # 已经在 handle_customer_service_event -> process_messages_async 中使用了线程
        result = handle_customer_service_event(msg_data, db)
        
        # Update callback status on success
        CALLBACK_STATUS['last_success'] = datetime.datetime.now()
        CALLBACK_STATUS['last_error'] = None
        CALLBACK_STATUS['error_count'] = 0
        CALLBACK_STATUS['last_check'] = datetime.datetime.now()
        
        logger.debug("✅ Message processed result: %s", result)
        
        # 广播新消息通知
        await manager.broadcast("new_message")

        return "success"

    except Exception as e:
        # Track callback error
        CALLBACK_STATUS['last_error'] = f"Message processing error: {str(e)}"
        CALLBACK_STATUS['error_count'] = CALLBACK_STATUS.get('error_count', 0) + 1
        CALLBACK_STATUS['last_check'] = datetime.datetime.now()
        
        logger.error("❌ Process message failed: %s", str(e), exc_info=True)
        # 即使失败也返回success，避免微信重复重试
        return "success"


# ----------------------
# 登录页面
# ----------------------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """登录页面"""
    # 如果用户已登录，直接跳转到仪表板
    token = request.session.get("access_token") or request.cookies.get("access_token")
    if token:
        try:
            jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return RedirectResponse(url="/dashboard", status_code=302)
        except:
            pass # Token无效，继续显示登录页

    error = request.query_params.get("error")
    message = request.query_params.get("message")

    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    is_docker = "DOCKER" in os.environ
    client_ip = request.client.host if request.client else None

    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "message": message,
        "current_time": current_time,
        "is_docker": is_docker,
        "client_ip": client_ip,
        "show_debug_info": SHOW_DEBUG_INFO,
        "version": __version__
    })



# ----------------------
# 登录表单提交 - 🔥 修正：使用正确的参数名
# ----------------------
# python
@app.post("/login/submit")
async def login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...)
):
    """处理登录表单提交（已加入 user_id 和 first_login_required 到 session）"""
    try:
        logger.info(f"🔍 Login attempt for user: {username} from IP: {request.client.host}")

        form_data = OAuth2PasswordRequestForm(
            username=username,
            password=password,
            scope="",
            client_id=None,
            client_secret=None
        )

        db = SessionLocal()
        try:
            user = authenticate_user(db, form_data.username, form_data.password)
            if not user:
                logger.warning(f"❌ Authentication failed for user: {username}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # 更新 token 版本，使旧 token 失效
            user.token_version += 1
            db.commit()

            access_token = create_access_token(
                {"sub": user.email, "v": user.token_version},
                SECRET_KEY,
                ALGORITHM
            )

            logger.info(
                f"✅ Login successful for {username}, redirecting to {'/first-login' if user.first_login else '/dashboard'}")

            redirect_url = "/first-login" if user.first_login else "/dashboard"
            response = RedirectResponse(url=redirect_url, status_code=302)

            response.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                secure=SECURE_COOKIES, # Configured via env var
                samesite="lax",
                max_age=30 * 60,
                path="/"
            )

            # 写入会话：token、csrf，以及 user_id/email/first_login_required
            request.session["access_token"] = access_token
            request.session["email"] = user.email
            request.session["user_id"] = user.id
            if user.first_login:
                request.session["first_login_required"] = True

            csrf_token = secrets.token_urlsafe(32)
            request.session["csrf_token"] = csrf_token

            logger.info("✅ Login successful - Cookie and Session set")
            return response

        finally:
            db.close()

    except HTTPException as e:
        error_detail = str(e.detail) if hasattr(e, 'detail') else str(e)
        logger.warning(f"❌ Login failed: {error_detail}")
        encoded_error = quote(error_detail, safe='')
        return RedirectResponse(
            url=f"/login?error={encoded_error}",
            status_code=303
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(f"❌ Unexpected error during login: {error_msg}", exc_info=True)
        encoded_error = quote(error_msg, safe='')
        return RedirectResponse(
            url=f"/login?error={encoded_error}",
            status_code=303
        )


# ----------------------
# 首次登录页面 - 🔥 修正：添加 datetime 到模板上下文
# ----------------------
@app.get("/first-login", response_class=HTMLResponse)
async def first_login_page(
        request: Request
):
    """首次登录页面"""
    try:
        session_token = request.session.get("access_token")
        cookie_token = request.cookies.get("access_token")

        logger.info(
            f"🔍 Session token: {'exists' if session_token else 'None'}, Cookie token: {'exists' if cookie_token else 'None'}")

        token = session_token or cookie_token
        if not token:
            logger.error("❌ No token found in session or cookie")
            return RedirectResponse(url="/login?error=Session expired, please login again", status_code=303)

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email: str = payload.get("sub")
            if email is None:
                raise HTTPException(status_code=401, detail="Invalid token payload")
        except Exception as e:
            logger.error(f"❌ Token validation failed: {str(e)}")
            request.session.clear()
            return RedirectResponse(url="/login?error=Invalid session token", status_code=303)

        try:
            user = db.query(User).filter(User.email == email).first()
            if user is None:
                logger.warning(f"⚠️ User not found for email: {email} (Token valid but user missing - likely renamed/deleted)")
                request.session.clear()
                return RedirectResponse(url="/login?error=User not found", status_code=303)

            if not user.first_login:
                logger.info(f"✅ User {email} is not first login, redirecting to dashboard")
                return RedirectResponse(url="/dashboard", status_code=302)

            csrf_token = request.session.get('csrf_token')
            if not csrf_token:
                csrf_token = secrets.token_urlsafe(32)
                request.session['csrf_token'] = csrf_token
                logger.info("✅ Generated CSRF token for first login page")

            logger.info(f"✅ First login page loaded for user: {email}")

            # 🔥 关键修复：添加当前时间到模板上下文
            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            is_docker = "DOCKER" in os.environ

            return templates.TemplateResponse("first_login.html", {
                "request": request,
                "user": user,
                "csrf_token": csrf_token,
                "current_time": current_time,  # ✅ 添加当前时间
                "is_docker": is_docker,  # ✅ 添加环境信息
                "client_ip": request.client.host if request.client else None,  # ✅ 添加客户端IP
                "version": __version__
            })

        finally:
            db.close()

    except Exception as e:
        logger.error(f"❌ First login page failed: {str(e)}", exc_info=True)
        request.session.clear()
        return RedirectResponse(url="/login?error=Internal server error", status_code=303)


# ----------------------
# 首次登录密码修改提交
# ----------------------
@app.post("/auth/first-login/password/submit")
async def first_login_password_submit(request: Request):
    """处理首次登录密码修改表单提交：更新密码并在响应中设置新的 access_token Cookie"""
    try:
        data = await request.json()
        current_password = data.get("current_password")
        new_password = data.get("new_password")
        confirm_password = data.get("confirm_password")

        token = request.session.get("access_token")
        if not token:
            logger.error("❌ No access token found in session")
            return JSONResponse(
                status_code=401,
                content={"detail": "Session expired, please login again", "success": False}
            )

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email: str = payload.get("sub")
            if email is None:
                raise Exception("Invalid token payload")
        except Exception as e:
            logger.error(f"❌ Token validation failed: {str(e)}")
            request.session.clear()
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid session token", "success": False}
            )

        try:
            user = db.query(User).filter(User.email == email).first()
            if user is None:
                logger.warning(f"⚠️ User not found for email: {email}")
                request.session.clear()
                return JSONResponse(
                    status_code=404,
                    content={"detail": "User not found", "success": False}
                )

            # CSRF 校验（视情况）
            csrf_token = request.headers.get("X-CSRF-Token")
            session_csrf = request.session.get("csrf_token")
            if not csrf_token or not session_csrf or csrf_token != session_csrf:
                logger.warning(f"❌ CSRF validation failed: header={csrf_token}, session={session_csrf}")
                return JSONResponse(status_code=403, content={"detail": "Invalid CSRF token", "success": False})

            if not current_password or not new_password or not confirm_password:
                return JSONResponse(status_code=400, content={"detail": "Missing password fields", "success": False})

            if not verify_password(current_password, user.hashed_password):
                logger.warning(f"❌ Current password verification failed for user: {email}")
                return JSONResponse(status_code=400, content={"detail": "Current password is incorrect", "success": False})

            if new_password != confirm_password:
                return JSONResponse(status_code=400, content={"detail": "New password and confirm password do not match", "success": False})

            # 密码规则校验（同现有逻辑）
            if len(new_password) < 12:
                return JSONResponse(status_code=400, content={"detail": "密码长度至少12位", "success": False})
            if not any(c.islower() for c in new_password):
                return JSONResponse(status_code=400, content={"detail": "密码必须包含小写字母", "success": False})
            if not any(c.isupper() for c in new_password):
                return JSONResponse(status_code=400, content={"detail": "密码必须包含大写字母", "success": False})
            if sum(c.isdigit() for c in new_password) < 2:
                return JSONResponse(status_code=400, content={"detail": "密码必须包含至少2个数字", "success": False})
            if sum(not c.isalnum() for c in new_password) < 2:
                return JSONResponse(status_code=400, content={"detail": "密码必须包含至少2个特殊字符", "success": False})

            # 更新密码并写入DB
            user.hashed_password = get_password_hash(new_password)
            user.first_login = False
            user.last_password_change = datetime.datetime.utcnow()

            # 🔥 新增：修改用户名 (可选)
            new_username = data.get("new_username")
            if new_username and new_username.strip():
                logger.info(f"User {email} renaming to {new_username}")
                user.username = new_username.strip()

            # 更新 token 版本
            user.token_version += 1
            db.commit()

            # 颁发新 token 并写入 session 与响应 Cookie（保持与 login_submit 一致）
            new_access_token = create_access_token({"sub": user.email, "v": user.token_version}, SECRET_KEY, ALGORITHM)
            request.session["access_token"] = new_access_token
            request.session.pop("csrf_token", None)
            request.session.pop("first_login_required", None)

            payload = {"message": "密码修改成功，首次登录完成", "redirect": "/login", "success": True}
            response = JSONResponse(status_code=200, content=payload)

            # 在响应上设置与 login_submit 相同属性的 Cookie，确保浏览器持有 token
            response.set_cookie(
                key="access_token",
                value=new_access_token,
                httponly=True,
                secure=False,   # 生产环境使用 True
                samesite="lax",
                max_age=30 * 60,
                path="/"
            )

            logger.info(f"✅ User {email} successfully updated password, first login completed (cookie set)")
            return response

        finally:
            db.close()

    except Exception as e:
        logger.error(f"❌ First login password submit failed: {str(e)}", exc_info=True)
        return JSONResponse(status_code=500, content={"detail": f"Internal server error: {str(e)}", "success": False})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """仪表板（需要登录）——增加会话/Cookie 日志以便调试会话丢失问题"""
    try:
        # 调试日志：打印 session 与 cookies，后续可删除
        # 调试日志
        logger.debug(f"📍 Dashboard - Session data: {request.session}")
        logger.debug(f"📍 Dashboard - Cookies: {request.cookies}")

        token = request.session.get("access_token") or request.cookies.get("access_token")
        if not token:
            return RedirectResponse(url="/login?error=Session expired, please login again", status_code=303)

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email = payload.get("sub")
            if not email:
                return RedirectResponse(url="/login?error=Invalid token", status_code=303)
        except Exception:
            return RedirectResponse(url="/login?error=Invalid session", status_code=303)

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == email).first()
            if user is None:
                logger.warning(f"⚠️ User not found for email: {email} (Token valid but user missing)")
                request.session.clear()
                return RedirectResponse(url="/login?error=User not found", status_code=303)

            # 修正：total_messages 应该查询 Message 表
            total_messages = db.query(Message).count()
            today = datetime.datetime.now().date()
            today_messages = db.query(Message).filter(Message.send_time >= datetime.datetime.combine(today, datetime.time.min)).count()
            
            # 统计发送人数
            from sqlalchemy import distinct
            total_senders = db.query(distinct(Message.external_userid)).count()
            
            yesterday = datetime.datetime.now() - datetime.timedelta(hours=24)
            recent_senders = db.query(distinct(Message.external_userid)).filter(Message.send_time >= yesterday).count()

            # 获取最近消息
            recent_messages = db.query(Message).order_by(Message.send_time.desc()).limit(10).all()

            # 简单的回调状态摘要
            # 注意：CALLBACK_STATUS 是在内存中的，重启后会丢失，除非有持久化机制
            from app.core.config import CALLBACK_STATUS
            last_sync_time = CALLBACK_STATUS.get('last_check')
            
            # 🔥 关键修复：如果内存中没有（重启后），从 DB 中获取最近的一次同步时间
            if not last_sync_time:
                 try:
                     # 获取所有 cursor 中最大的 last_sync_time
                     from sqlalchemy import func
                     last_sync_time = db.query(func.max(MessageCursor.last_sync_time)).scalar()
                     # 可选：回填到内存，避免每次都查 DB (这也回显到 log/status)
                     if last_sync_time:
                         CALLBACK_STATUS['last_check'] = last_sync_time
                         # 为了 UI 显示一致性，也可以设 last_success (虽然不完全准确，但比 Never 好)
                         if not CALLBACK_STATUS.get('last_success'):
                             CALLBACK_STATUS['last_success'] = last_sync_time
                 except Exception as e:
                     logger.warning(f"⚠️ Failed to fetch last sync time from DB: {e}")

            if last_sync_time:
                if isinstance(last_sync_time, datetime.datetime):
                    # 转换为本地时间 (假设 DB 存的是 UTC，或者已经处理过 naive)
                    # existing logic was just strftime
                    last_sync_time_str = last_sync_time.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    last_sync_time_str = str(last_sync_time)
            else:
                last_sync_time_str = None

            # ---------------------------------------------------------
            # 获取部分发送者的昵称 (Optimization: fetch only for recent messages or top senders)
            # ---------------------------------------------------------
            # 收集 userid list
            user_ids = set()
            for msg in recent_messages:
                if msg.external_userid:
                    user_ids.add(msg.external_userid)
                    # 如果是名片，也尝试解析名片里的 userid
                    if msg.msgtype == 'business_card' and msg.extra_data:
                         try:
                             extra = json.loads(msg.extra_data)
                             card_userid = extra.get('userid')
                             if card_userid:
                                 user_ids.add(card_userid)
                         except:
                             pass

            # 获取昵称映射
            customer_map = {}
            if user_ids:
                 try:
                     # 1. 查库
                     cached_customers = db.query(Customer).filter(Customer.external_userid.in_(user_ids)).all()
                     customer_map = {c.external_userid: c for c in cached_customers}
                     
                     # 2. 找出缺失的 (或者过期的? 暂不处理过期，依赖 webhook 更新或定期任务)
                     missing_ids = [uid for uid in user_ids if uid not in customer_map]
                     
                     if missing_ids:
                         # 3. 调用 API 获取 (Lazy Fetch)
                         # 注意：这可能会阻塞 dashboard 加载，如果 ID 很多的话。
                         # 但对于 dashboard (10条消息)，通常只有几个 ID，应该很快。
                         from app.services.wecom_service import batch_get_customer_info
                         fetched_map = batch_get_customer_info(missing_ids, db) # Pass DB to save
                         
                         # 合并结果 (注意：batch_get 返回的是 dict，我们需要转为对象或统一格式传给前端)
                         # 这里我们简单把 fetched data (dict) 混入 customer_map (object)
                         # 前端需要统一处理 .nickname 属性 accessing
                         for uid, info in fetched_map.items():
                              # 构造临时对象或字典
                              customer_map[uid] = info # dict
                              
                 except Exception as e:
                     logger.error(f"Error fetching customer info: {e}")

            return templates.TemplateResponse("dashboard.html", {
                "request": request,
                "total_messages": total_messages,
                "today_messages": today_messages,
                "total_senders": total_senders,
                "recent_senders": recent_senders,
                "recent_messages": recent_messages,
                "last_sync_time": last_sync_time_str,
                "user": {"email": email, "first_login": False},
                "customer_map": customer_map, # 传递给模板
                "version": __version__
            })
        finally:
            db.close()

    except Exception as e:
        logger.error(f"❌ Dashboard failed: {str(e)}", exc_info=True)
        request.session.clear()
        return RedirectResponse(url="/login?error=Internal server error", status_code=303)
# ----------------------
# 消息列表页
# ----------------------
from typing import Optional
from fastapi import Depends
from sqlalchemy.orm import Session
from sqlalchemy import or_

@app.get("/messages", response_class=HTMLResponse)
async def messages_page(
    request: Request,
    page: int = 1,
    page_size: int = 20,
    msgtype: Optional[str] = None,
    download_status: Optional[str] = None,
    search: Optional[str] = None,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """消息列表页面"""
    
    # 鉴权
    token = request.session.get("access_token") or request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login")
        
    try:
        await get_current_user_from_token(token)
    except:
        return RedirectResponse(url="/login")

    # page_size passed from query param
    query = db.query(Message)

    # 过滤条件
    start_date = request.query_params.get("start_date")
    end_date = request.query_params.get("end_date")

    if msgtype:
        query = query.filter(Message.msgtype == msgtype)
    if download_status:
        query = query.filter(Message.download_status == download_status)
    if customer_id:
        query = query.filter(Message.external_userid.contains(customer_id))
    if search:
        # 支持搜索内容和文件名
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                Message.content.like(search_term),
                Message.original_filename.like(search_term)
            )
        )
    if start_date:
        try:
            s_date = datetime.datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(Message.send_time >= s_date)
        except ValueError:
            pass
    if end_date:
        try:
            # 结束日期包含当天，所以+1天或设置时间为23:59:59
            e_date = datetime.datetime.strptime(end_date, '%Y-%m-%d') + datetime.timedelta(days=1)
            query = query.filter(Message.send_time < e_date)
        except ValueError:
            pass

    # 排序和分页
    total_count = query.count()
    total_pages = (total_count + page_size - 1) // page_size
    
    messages = query.order_by(Message.send_time.desc()).offset((page - 1) * page_size).limit(page_size).all()

    # ---------------------------------------------------------
    # 获取发送者的昵称
    # ---------------------------------------------------------
    user_ids = set()
    for msg in messages:
        if msg.external_userid:
            user_ids.add(msg.external_userid)
        if msg.msgtype == 'business_card' and msg.extra_data:
             try:
                 extra = json.loads(msg.extra_data)
                 card_userid = extra.get('userid')
                 if card_userid:
                     user_ids.add(card_userid)
             except:
                 pass
    
    customer_map = {}
    if user_ids:
         try:
             # 1. 查库
             cached_customers = db.query(Customer).filter(Customer.external_userid.in_(user_ids)).all()
             customer_map = {c.external_userid: c for c in cached_customers}
             
             # 2. 找出缺失的
             missing_ids = [uid for uid in user_ids if uid not in customer_map]
             
             if missing_ids:
                 # 3. 调用 API 获取
                 fetched_map = batch_get_customer_info(missing_ids, db)
                 for uid, info in fetched_map.items():
                      customer_map[uid] = info
         except Exception as e:
             logger.error(f"Error fetching customer info in messages_page: {e}")

    return templates.TemplateResponse("messages.html", {
        "customer_map": customer_map, # Pass to template
        "request": request,
        "messages": messages,
        "page": page,
        "total_pages": total_pages,
        "msgtype": msgtype,
        "download_status": download_status,
        "search": search,
        "customer_id": customer_id,
        "page_size": page_size,
        "version": __version__
    })



# ----------------------
# 批量操作 API
# ----------------------
class BatchActionRequest(BaseModel):
    message_ids: List[str]

@app.post("/api/messages/batch_delete")
async def batch_delete_messages(request: BatchActionRequest, current_user: User = Depends(get_current_active_user)):
    """批量删除消息"""
    try:
        logger.info(f"Batch delete requested. User: {current_user.email}, IDs: {len(request.message_ids)}")
        
        if not current_user.is_superuser:
            logger.warning("Batch delete denied: User not superuser")
            raise HTTPException(status_code=403, detail="需要管理员权限")
        
        db = SessionLocal()
        try:
            # 查询要删除的消息
            messages_to_delete = db.query(Message).filter(Message.id.in_(request.message_ids)).all()
            logger.info(f"Found {len(messages_to_delete)} messages to delete")
            
            count = 0
            for msg in messages_to_delete:
                # 如果有文件，尝试删除文件 (可选，根据需求)
                # if msg.local_path and os.path.exists(msg.local_path):
                #     try:
                #         os.remove(msg.local_path)
                #     except Exception:
                #         pass
                
                db.delete(msg)
                count += 1
                
            db.commit()
            db.commit()
            logger.info(f"✅ [Batch Delete] COMPLETED - Successfully deleted {count} messages")
            return {"success": True, "count": count}
        except Exception as e:
            db.rollback()
            logger.error(f"Batch delete DB error: {e}", exc_info=True)
            return {"success": False, "message": f"Database error: {str(e)}"}
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Batch delete unhandled error: {e}", exc_info=True)
        # 如果是 HTTPException 直接抛出
        if isinstance(e, HTTPException):
            raise e
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"Server error: {str(e)}"}
        )

# ----------------------
# 异步批量下载逻辑
# ----------------------
import uuid
import shutil

# 全局任务状态存储 (内存中，重启丢失)
# Structure: { job_id: { status: 'processing', progress: 0, total: 0, current: 0, message: '', file_path: '', error: '' } }
download_jobs = {}

def process_batch_download_task(job_id: str, message_ids: List[str], db_session_factory):
    """后台处理批量下载任务"""
    job = download_jobs.get(job_id)
    if not job:
        return

    db = db_session_factory()
    try:
        job['status'] = 'processing'
        job['message'] = 'Querying database...'
        
        messages = db.query(Message).filter(Message.id.in_(message_ids)).all()
        total_count = len(messages)
        job['total'] = total_count
        
        if not messages:
            job['status'] = 'failed'
            job['error'] = 'No messages found'
            return

        # 创建临时文件
        import tempfile
        temp_dir = tempfile.gettempdir()
        zip_filename = f"Wx2save_batch_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{job_id}.zip"
        zip_filepath = os.path.join(temp_dir, zip_filename)
        
        import zipfile
        has_content = False
        
        with zipfile.ZipFile(zip_filepath, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for idx, msg in enumerate(messages):
                # 更新进度
                job['current'] = idx + 1
                job['progress'] = int((idx + 1) / total_count * 100)
                job['message'] = f"Processing {idx + 1}/{total_count}..."
                
                try:
                    # 定义通用 helper
                    def add_txt_to_zip(zip_f, msg_id, suffix, text_content):
                        fname = f"{msg_id}_{suffix}.txt"
                        zip_f.writestr(fname, text_content)

                    # 1. 文本消息
                    if msg.msgtype == 'text':
                        content = f"Time: {msg.send_time}\nSender: {msg.external_userid or msg.open_kfid or 'Unknown'}\n\n{msg.content or '[Empty]'}"
                        add_txt_to_zip(zip_file, msg.id, "text", content)
                        has_content = True
                        continue
                    
                    # 2. 媒体文件 (image, voice, video, file, emotion)
                    if msg.msgtype in ['image', 'voice', 'video', 'file', 'emotion']:
                        file_path = getattr(msg, 'media_path', None)
                        original_name = msg.original_filename or os.path.basename(file_path) if file_path else f"unknown_{msg.msgtype}"
                        
                        # 补全扩展名
                        if '.' not in original_name:
                            ext_map = {'image': '.jpg', 'voice': '.amr', 'video': '.mp4', 'emotion': '.gif'}
                            original_name += ext_map.get(msg.msgtype, '')

                        # 防止重名: 使用完整ID而不是前8位
                        arcname = f"{msg.id}_{original_name}"
                        
                        # A. 尝试本地文件
                        if file_path and os.path.exists(file_path):
                            try:
                                zip_file.write(file_path, arcname)
                                has_content = True
                                continue
                            except Exception as e:
                                logger.error(f"Failed to zip local file {file_path}: {e}")
                                add_txt_to_zip(zip_file, msg.id, "error", f"Failed to pack local file: {str(e)}")
                                has_content = True
                                continue
                        
                        # B. 尝试 S3/存储服务 (如果是本地丢失但S3有的情况)
                        # get_file_stream 会自动处理绝对路径转相对key
                        if file_path:
                            try:
                                stream, _, _ = storage.get_file_stream(file_path)
                                if stream:
                                    file_content = stream.read()
                                    zip_file.writestr(arcname, file_content)
                                    has_content = True
                                    continue
                            except Exception as e:
                                logger.error(f"Failed to retrieve/zip S3 file {file_path}: {e}")
                                
                        # C. 文件确实丢失
                        info = f"Type: {msg.msgtype}\nStatus: File not found (Local & S3).\nOriginal Name: {msg.original_filename}\nSize: {msg.file_size}"
                        if msg.media_url:
                            info += f"\nURL: {msg.media_url}"
                        if file_path:
                             info += f"\nPath: {file_path}"
                        add_txt_to_zip(zip_file, msg.id, "missing", info)
                        has_content = True
                        continue

                    # 3. 链接/小程序/位置/聊天记录/会议/日程 等复杂类型
                    # 统一导出为详情文本
                    details = [f"Type: {msg.msgtype}", f"Time: {msg.send_time}", f"Sender: {msg.external_userid or msg.open_kfid}"]
                    
                    if msg.content:
                        details.append(f"Content: {msg.content}")
                    
                    if msg.media_url:
                        details.append(f"URL: {msg.media_url}")
                        
                    # 尝试解析 extra_data
                    if msg.extra_data:
                        try:
                            extra = json.loads(msg.extra_data)
                            details.append(f"Details: {json.dumps(extra, indent=2, ensure_ascii=False)}")
                        except:
                            details.append(f"Raw Extra Data: {msg.extra_data}")
                    
                    add_txt_to_zip(zip_file, msg.id, "info", "\n".join(details))
                    has_content = True
                    
                except Exception as e:
                    logger.error(f"Error processing msg {msg.id}: {e}")
                    # Don't fail the whole batch
        
        if not has_content:
            job['status'] = 'failed'
            job['error'] = 'No downloadable content found in selected messages'
            # Clean up empty zip
            if os.path.exists(zip_filepath):
                os.remove(zip_filepath)
            return

        job['status'] = 'completed'
        job['progress'] = 100
        job['message'] = 'Compression finished. Ready to download.'
        job['file_path'] = zip_filepath
        job['filename'] = zip_filename
        
    except Exception as e:
        logger.error(f"Async batch download failed: {e}", exc_info=True)
        job['status'] = 'failed'
        job['error'] = str(e)
    finally:
        db.close()


@app.post("/api/messages/batch_download/start")
async def start_batch_download(request: BatchActionRequest, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_active_user)):
    """启动批量下载任务"""
    job_id = str(uuid.uuid4())
    download_jobs[job_id] = {
        'status': 'pending',
        'progress': 0, 
        'total': len(request.message_ids),
        'current': 0,
        'message': 'Initializing...',
        'created_at': datetime.datetime.now()
    }
    
    # 传递 SessionLocal 工厂函数，避免传递 Session 对象到线程中
    background_tasks.add_task(process_batch_download_task, job_id, request.message_ids, lambda: SessionLocal())
    
    return {"success": True, "job_id": job_id}

@app.get("/api/messages/batch_download/progress/{job_id}")
async def get_batch_download_progress(job_id: str, current_user: User = Depends(get_current_active_user)):
    """获取下载任务进度"""
    job = download_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job

@app.get("/api/messages/batch_download/file/{job_id}")
async def get_batch_download_file(job_id: str, background_tasks: BackgroundTasks):
    """获取下载好的文件"""
    # 这里不强制鉴权，因为可能是浏览器直接访问 (虽然 cookie 应该在)。
    # 为了安全最好鉴权，但为了简单起见，且 job_id 是 UUID，暂视为一次性 token。
    
    job = download_jobs.get(job_id)
    if not job or job['status'] != 'completed' or not job.get('file_path'):
        raise HTTPException(status_code=404, detail="File not ready or expired")
    
    file_path = job['file_path']
    filename = job['filename']
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File deleted from server")

    # 下载后清理文件
    background_tasks.add_task(lambda p: os.remove(p) if os.path.exists(p) else None, file_path)
    # 清理 job 记录
    background_tasks.add_task(lambda j: download_jobs.pop(j, None), job_id)

    return FileResponse(
        file_path, 
        media_type="application/zip", 
        filename=filename,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# 保留旧接口但不处理业务，防止前端未更新时报错 (前端将更新调用 /start)
@app.post("/api/messages/batch_download")
async def batch_download_messages_legacy(request: BatchActionRequest, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_active_user)):
    """(Legacy) 批量下载"""
    return await start_batch_download(request, background_tasks, current_user)



# ----------------------
# 系统设置页 (原系统状态)
# ----------------------
@app.post("/api/storage/test")
async def test_storage_connection(current_user: User = Depends(get_current_active_user)):
    """测试存储连接"""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="需要管理员权限")
    
    # 重新加载配置以确保使用最新的（虽然后端重启前可能还是旧的，但storage service读的是内存config）
    # 注意：这里我们测试的是当前的 storage service 实例
    
    try:
        success, msg = storage.check_connection()
        return {"success": success, "message": msg}
    except Exception as e:
        logger.error(f"S3 Connection Test Error: {e}")
        return {"success": False, "message": str(e)}

@app.get("/system/settings", response_class=HTMLResponse)
async def system_settings_page(request: Request):
    """系统设置页"""
    # 加载当前配置 (从内存中config模块读取)
    from app.core.config import _config, CALLBACK_STATUS

    token = request.session.get("access_token") or request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login?error=Session expired", status_code=303)

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except Exception:
        return RedirectResponse(url="/login?error=Invalid session", status_code=303)

    db_status = "ok"
    try:
        db = SessionLocal()
        db.execute("SELECT 1")
        db.close()
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    # S3 Status Check
    s3_status = "disabled"
    s3_msg = "未启用"
    if _config.get('storage', {}).get('s3_enabled'):
        is_connected, msg = storage.check_connection()
        if is_connected:
             s3_status = "connected"
             s3_msg = "已连接"
        else:
             s3_status = "error"
             s3_msg = msg

    status = {
        "database": db_status,
        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "version": __version__
    }

    # 加载当前配置 (从内存中config模块读取，注意：它反映的是启动时的配置)
    # 为了显示最新保存的YAML，最好重新读取一下YAML?
    # 这里直接用config模块的变量可能无法反映YAML文件的修改（如果没重启）
    # 但我们希望用户看到的是当前生效的，或者是文件里的。
    # 简单起见，我们构造一个 config 字典传给模板
    # 加载当前配置
    # 构建显示用的配置副本
    display_config = _config.copy()
    
    # 简单的回调状态摘要
    callback_info = {
        "status": "success" if CALLBACK_STATUS['last_success'] and (not CALLBACK_STATUS['last_error'] or CALLBACK_STATUS['last_success'] > CALLBACK_STATUS.get('last_error_time', datetime.datetime.min)) else "error" if CALLBACK_STATUS['last_error'] else "pending",
        "last_success": CALLBACK_STATUS['last_success'],
        "last_error": CALLBACK_STATUS['last_error']
    }

    return templates.TemplateResponse("system_settings.html", {
        "request": request,
        "config": display_config,
        "status": status,
        "callback_info": callback_info,
        "s3_status": s3_status,
        "s3_msg": s3_msg,
        "s3_status": s3_status,
        "s3_msg": s3_msg,
        "user": {"email": email, "first_login": False},
        "version": __version__
    })

@app.post("/api/settings/update")
async def api_system_settings_update(
    request: Request,
    setting_data: dict
):
    """更新系统设置 (JSON API)"""
    token = request.session.get("access_token") or request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Untitled")

    # 简单判断如果不包含 wecom/storage 顶层key，且包含 corp_id，则认为是旧版wecom配置
    if 'wecom' not in setting_data and 'storage' not in setting_data and 'corp_id' in setting_data:
        success = save_config({"wecom": setting_data})
    else:
        # 新版通用配置 (包含 wecom 或 storage 键)
        success = save_config(setting_data)
    
    if success:
         return JSONResponse({"status": "success", "message": "配置已保存，请重启服务生效。"})
    else:
         raise HTTPException(status_code=500, detail="保存配置失败")

@app.post("/api/system/restart")
async def restart_system(request: Request):
    """重启系统 - 触发容器/进程重启"""
    token = request.session.get("access_token") or request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        # 验证token
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    logger.info("🔄 System restart requested by user")
    
    # 启动异步任务在2秒后退出进程
    async def delayed_exit():
        import asyncio
        await asyncio.sleep(2)  # 给客户端足够时间接收响应
        logger.info("🛑 Shutting down for restart...")
        os._exit(1)  # 退出进程（使用状态码1触发Docker重启策略）
    
    import asyncio
    asyncio.create_task(delayed_exit())
    
    return JSONResponse({
        "status": "success", 
        "message": "系统将在2秒后重启，请稍候..."
    })


# ----------------------
# 消息详情页
# ----------------------
@app.get("/messages/{msg_id}", response_class=HTMLResponse)
async def message_detail(request: Request, msg_id: str):
    """消息详情页"""
    token = request.session.get("access_token") or request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login?error=Session expired", status_code=303)

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except Exception:
        return RedirectResponse(url="/login?error=Invalid session", status_code=303)

    db = SessionLocal()
    try:
        # 优先按 msgid (WeCom ID) 查找
        message = db.query(Message).filter(Message.msgid == msg_id).first()
        
        # 如果没找到，按主键 ID 查找 (它是字符串)
        if not message:
            message = db.query(Message).filter(Message.id == msg_id).first()
        
        if not message:
            return RedirectResponse(url="/messages?error=Message not found", status_code=303)

        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 解析 raw extra_data JSON
        parsed_extra_data = {}
        if message.extra_data:
            try:
                parsed_extra_data = json.loads(message.extra_data)
            except Exception:
                 parsed_extra_data = {"error": "Failed to parse JSON"}

        # 动态生成媒体URL (适配S3预签名或本地静态)
        if message and message.media_path:
            # 临时赋给对象用于模板渲染 (不提交DB)
            message.media_url = storage.get_file_url(message.media_path)

        # 获取发送者昵称
        nickname = None
        if message.external_userid:
            # 尝试从 Customer 表缓存获取
            # 需要导入 Customer 模型 ( ensure it is imported at top or here)
            from app.models.customer import Customer
            try:
                cust = db.query(Customer).filter(Customer.external_userid == message.external_userid).first()
                if cust:
                     nickname = cust.nickname
                else:
                     # 尝试实时获取 (可选，为了详情页速度可能只读缓存，或者调用 batch_get 但只有1个)
                     # 为简单起见，这里复用 batch_get_customer_info 如果没缓存
                     from app.services.wecom_service import batch_get_customer_info
                     res = batch_get_customer_info([message.external_userid], db)
                     if res and message.external_userid in res:
                         nickname = res[message.external_userid].get('nickname')
            except Exception as e:
                logger.error(f"Error fetching nickname for detail: {e}")

        return templates.TemplateResponse("message_detail.html", {
            "request": request,
            "message": message,
            "nickname": nickname, # Pass nickname
            "raw_data": parsed_extra_data,
            "user": {"email": email, "first_login": False},
            "current_time": current_time,
            "version": __version__
        })
    finally:
        db.close()

# ----------------------
# 安全文件下载接口
# ----------------------

@app.post("/api/files/generate_token/{msg_id}")
async def generate_download_token(request: Request, msg_id: str):
    """生成一次性/限次下载令牌"""
    disposition = request.query_params.get('disposition', 'attachment') # attachment or inline

    token = request.session.get("access_token") or request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
        
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == user_email).first()
        if not user:
             raise HTTPException(status_code=401, detail="User not found")
             
        message = db.query(Message).filter(Message.id == msg_id).first()
        if not message:
             # 尝试msgid
             message = db.query(Message).filter(Message.msgid == msg_id).first()
             
        if not message or not message.media_path:
             raise HTTPException(status_code=404, detail="File not found")

        # 创建下载令牌
        # 有效期 5 分钟
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        download_token = DownloadToken(
            message_id=message.id,
            user_id=user.id,
            expires_at=expires_at,
            max_downloads=5
        )
        db.add(download_token)
        db.commit()
        db.refresh(download_token)
        
        return {"token": download_token.token, "url": f"/files/download/{download_token.token}?disposition={disposition}"}
    finally:
        db.close()


@app.get("/files/download/{token}")
async def download_file(request: Request, token: str):
    """通过令牌下载文件"""
    # 检查 Referer 防盗链
    referer = request.headers.get("referer")
    if referer:
        from urllib.parse import urlparse
        ref_host = urlparse(referer).hostname
        # 允许的域名列表 (包括当前请求的主机名)
        allowed_hosts = [request.url.hostname, "localhost", "127.0.0.1"]
        
        if ref_host and ref_host not in allowed_hosts:
             logger.warning(f"⚠️ Hotlink blocked from {referer}")
             raise HTTPException(status_code=403, detail="Access denied (hotlink protection)")
        
    db = SessionLocal()
    try:
        dt = db.query(DownloadToken).filter(DownloadToken.token == token).first()
        
        if not dt:
             msg = "Invalid download link"
             logger.warning(f"❌ Download failed: {msg}")
             raise HTTPException(status_code=404, detail=msg)
             
        if not dt.is_active:
             msg = "Download link expired (revoked)"
             raise HTTPException(status_code=410, detail=msg)
             
        if datetime.datetime.utcnow() > dt.expires_at:
             msg = "Download link expired (time)"
             raise HTTPException(status_code=410, detail=msg)
             
        if dt.current_downloads >= dt.max_downloads:
             msg = "Download limit reached"
             raise HTTPException(status_code=403, detail=msg)

        # 更新计数
        dt.current_downloads += 1
        db.commit()
        
        # 获取文件信息
        message = db.query(Message).filter(Message.id == dt.message_id).first()
        if not message or not message.media_path:
             raise HTTPException(status_code=404, detail="File record lost")
             
        file_path = message.media_path
        
        if os.path.exists(file_path):
             # 本地文件存在 -> 直接发送
             # 强制文件名
             filename = message.original_filename or f"file_{message.id}"
             dt.current_downloads += 1
             db.commit()
             
             # 获取 disposition 参数 (默认 attachment)
             disposition = request.query_params.get('disposition', 'attachment')
             
             # 简单的防止头部注入
             if disposition not in ['attachment', 'inline']:
                 disposition = 'attachment'

             return FileResponse(
                 file_path, 
                 filename=filename,
                 # headers={"Content-Disposition": f"attachment; filename=\"{filename}\""} 
                 headers={"Content-Disposition": f"{disposition}; filename=\"{filename}\""}
             )
        elif storage.s3_client: # 检查S3是否启用 (通过 storage 实例判断)
             # 本地不存在，尝试 S3
             # 本地不存在，尝试 S3
             # 此时 file_path 可能是 S3 Key
             
             # 本地不存在，尝试 S3
             # 此时 file_path 可能是 S3 Key
             
             # -------------------------------------------------------------
             # 🧠 智能 S3 策略 (Smart S3 Strategy)
             # -------------------------------------------------------------
             # 目标：安全第一，兼顾性能
             # 1. 如果 S3 Endpoint 是内网 IP (192.168/10/172/localhost) -> 强制代理 (Client 无法访问内网)
             # 2. 如果配置强制开启代理 -> 代理
             # 3. 否则 -> 直连 (Redirect to Presigned URL)
             
             from urllib.parse import urlparse
             import socket
             import ipaddress

             def is_private_host(url):
                 try:
                     hostname = urlparse(url).hostname
                     if not hostname: return False
                     if hostname in ['localhost', '127.0.0.1', '::1']: return True
                     # 尝试解析 IP
                     try:
                         ip = ipaddress.ip_address(hostname)
                     except ValueError:
                         # 可能是域名，尝试解析为 IP (注意：这可能阻塞，但在 endpoint 确定时通常很快)
                         # 简单起见，如果不是 IP 格式，暂定为公网 (除非它是 .local?)
                         # 为避免 DNS 阻塞，我们在配置层建议用户填 IP，或者这里仅检测纯 IP 格式
                         return False 
                     
                     return ip.is_private
                 except:
                     return False

             # 获取 S3 Endpoint
             s3_endpoint = _config.get('storage', {}).get('s3_endpoint_url', '')
             is_internal_s3 = is_private_host(s3_endpoint)
             
             # 获取用户偏好
             user_pref_proxy = _config.get('storage', {}).get('s3_proxy_mode', True)
             
             # 决策
             should_use_proxy = is_internal_s3 or user_pref_proxy
             
             logger.info(f"🔍 S3 Strategy Check: Endpoint={s3_endpoint}, Internal={is_internal_s3}, UserPref={user_pref_proxy} -> Mode={'PROXY' if should_use_proxy else 'DIRECT'}")

             # ❌ 决策执行: 直连模式
             if not should_use_proxy:
                  logger.info(f"☁️ Redirecting to S3 (Direct Mode) for {file_path}")
                  s3_url = storage.get_file_url(file_path)
                  if s3_url and s3_url.startswith("http"):
                       return RedirectResponse(url=s3_url)
                  else:
                       logger.warning(f"⚠️ Failed to get S3 URL in Direct Mode, falling back to Proxy Mode")
                       # Fallback...

             # ✅ 决策执行: 代理模式 (默认 / 强制)
             logger.info(f"☁️ Fetching from S3 (Proxy Mode) for {file_path}")
             
             # 使用代理模式：后端直接从 S3 拉流转发给前端
             # 解决内网 S3 IP 无法被外网访问的问题
             stream, s3_content_type, s3_content_length = storage.get_file_stream(file_path)
             
             if stream:
                  # 构造流式响应
                  # 需要重新组装 headers (Content-Disposition 已在下方定义，这里只需返回 Response)
                  # 但 StreamingResponse 需要在这里直接返回，或者让后续代码处理？
                  # 为了复用后续的 Content-Disposition 逻辑，我们可以把 stream 赋值给 content_iterator?
                  # FileResponse 只能处理本地文件。StreamingResponse 处理流。
                  # 所以我们需要在这里直接 return StreamingResponse, 并把下方的 Header 逻辑搬上来。
                  
                  # ----------------------------------------------------------------
                  # COPY HEADER LOGIC (Simplified for Proxy)
                  # ----------------------------------------------------------------
                  # 强制文件名
                  filename = message.original_filename or f"file_{message.id}"
                  disposition = request.query_params.get('disposition', 'attachment')
                  
                  # 编码文件名
                  from urllib.parse import quote
                  encoded_filename = quote(filename)
                  safe_filename = filename.encode('ascii', 'ignore').decode('ascii') or "file"
                  
                  headers = {
                      "Content-Disposition": f"{disposition}; filename=\"{safe_filename}\"; filename*=utf-8''{encoded_filename}",
                      "Access-Control-Expose-Headers": "Content-Disposition"
                  }
                  if s3_content_length:
                      headers["Content-Length"] = str(s3_content_length)
                  
                  # 增加下载计数
                  dt.current_downloads += 1
                  db.commit()
                  
                  from fastapi.responses import StreamingResponse
                  return StreamingResponse(
                      content=stream, 
                      media_type=s3_content_type or "application/octet-stream", 
                      headers=headers
                  )
             else:
                  # 获取流失败
                  logger.error(f"❌ Failed to get S3 stream for {file_path}")
                  # 不直接抛异常，继续走 Auto-Restore 逻辑 (如果配置了S3但文件丢了)
                  
                  # raise HTTPException(status_code=404, detail="File missing on storage")
        # -------------------------------------------------------
        # 🔥 文件存在性检查与自动修复 (Auto-Restore)
        # -------------------------------------------------------
        # -------------------------------------------------------
        if not os.path.exists(message.media_path):
             # 如果标记为“已删除”，也可以选择是否尝试恢复？
             # 用户逻辑：主动删除的，不应静默下载。
             # 我们假设如果 download_status == 'deleted'，则不进行恢复
             if message.download_status == 'deleted':
                  logger.info(f"⏭️ File marked as deleted (manual), skipping auto-restore: {message.id}")
             else:
                 logger.warning(f"⚠️ File missing on disk: {message.media_path}")
                 
                 # 检查消息时间，如果在3天内 (WeCom 媒体保留72小时)，尝试重新下载
                 # import datetime (Removed)
                 cutoff_time = datetime.datetime.now() - datetime.timedelta(days=3)
                 
                 if message.send_time and message.send_time > cutoff_time and message.media_id:
                      logger.info(f"🔄 Attempting to auto-restore file for message {message.id} (within 3 days)")
                      try:
                           # 修复 ImportError: 这些函数定义在 services/__init__.py 中，直接从 app.services 导入
                           from app.services import download_media_file, save_media_file
                           content, _ = download_media_file(message.media_id, message.msgtype)
                           if content:
                                # 重新保存
                                os.makedirs(os.path.dirname(message.media_path), exist_ok=True)
                                with open(message.media_path, 'wb') as f:
                                     f.write(content)
                                logger.info(f"✅ Auto-restored file success: {message.media_path}")
                           else:
                                logger.error("❌ Auto-restore failed: download returned no content")
                      except Exception as e:
                           logger.error(f"❌ Auto-restore exception: {e}")
                 else:
                      # 超过3天，无法恢复
                      logger.warning(f"❌ File missing and expired (>3 days), cannot restore. Send time: {message.send_time}")
                      # 更新状态为过期/丢失
                      if message.download_status != 'expired':
                           message.download_status = 'expired'
                           db.commit()

        if not os.path.exists(message.media_path):
              # 再次检查
              raise HTTPException(status_code=404, detail="File missing on server (expired or deleted)")
        
        # -------------------------------------------------------

        # 强制文件名 (UUID 已经在磁盘上，但下载时我们可能想给用户原始文件名？)
        filename = message.original_filename or f"file_{message.id}"
        
        # Bug fix: Voice messages usually don't have extension in original_filename if it's just 'voice' or empty
        if message.msgtype == 'voice' and not filename.lower().endswith('.amr'):
             filename += ".amr"

        # 增加下载计数
        dt.current_downloads += 1
        db.commit()

        disposition = request.query_params.get('disposition', 'attachment')
        
        # 尝试使用 FileResponse 发送文件
        # 如果是 inline，尽量让浏览器直接打开（需要正确的 media_type）
        media_type = None
        import mimetypes
        if message.file_extension:
             media_type = mimetypes.types_map.get(f".{message.file_extension}")
        
        # 修正: 使用 RFC 5987 标准编码 filename* 处理中文文件名
        from urllib.parse import quote
        encoded_filename = quote(filename)
        # 定义 safe_filename (ASCII fallback)
        safe_filename = filename.encode('ascii', 'ignore').decode('ascii') or "file"

        # 优先使用 filename*，兼容旧浏览器使用 filename (ASCII), 确保双引号包围
        headers = {
            "Content-Disposition": f"{disposition}; filename=\"{safe_filename}\"; filename*=utf-8''{encoded_filename}",
            "Access-Control-Expose-Headers": "Content-Disposition"
        }

        return FileResponse(
            path=message.media_path, 
            filename=filename if disposition == 'attachment' else None, # FastAPI 自动设置 attachment 如果 filename 存在
            media_type=media_type,
            headers=headers
        )

    finally:
        db.close()


# ----------------------
# CSRF 令牌端点
# ----------------------
@app.get("/csrf-token")
async def get_csrf_token(request: Request):
    """获取CSRF令牌"""
    if not hasattr(request, 'session') or request.session is None:
        logger.error("❌ Session not available for CSRF token")
        raise HTTPException(status_code=500, detail="Session not available")

    csrf_token = request.session.get('csrf_token')
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
        request.session['csrf_token'] = csrf_token
        logger.info("✅ Generated new CSRF token")
    else:
        logger.info("✅ Using existing CSRF token")

    return {"csrf_token": csrf_token}


# ----------------------
# 用户管理 API
# ----------------------
class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

@app.post("/api/user/password")
async def change_password(
    password_data: PasswordChangeRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """修改当前用户密码"""
    # 验证当前密码
    if not verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="当前密码错误")
    
    # 更新密码
    current_user.hashed_password = get_password_hash(password_data.new_password)
    # 标记已不再是首次登录
    current_user.first_login = False
    db.commit()
    
    logger.info(f"User {current_user.email} changed password successfully.")
    
    # 强制重新登录
    current_user.token_version += 1
    db.commit()
    
    # Clear server-side session
    request.session.clear()
    
    response = JSONResponse({"status": "success", "message": "密码修改成功，请重新登录"})
    response.delete_cookie("access_token")
    return response


class UsernameChangeRequest(BaseModel):
    current_password: str
    new_username: str

@app.post("/api/user/username")
async def change_username(
    username_data: UsernameChangeRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """修改用户名"""
    # 1. 验证当前密码
    if not verify_password(username_data.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="当前密码错误")

    new_username = username_data.new_username.strip()
    if not new_username:
         raise HTTPException(status_code=400, detail="用户名不能为空")

    logger.info(f"Attempting to change username from {current_user.email} to {new_username}")

    # Check if username already exists
    existing_user = db.query(User).filter(User.email == new_username).first()
    if existing_user and existing_user.id != current_user.id:
        logger.warning(f"Username change failed: '{new_username}' already taken by ID {existing_user.id}")
        raise HTTPException(status_code=400, detail="该用户名已存在")
         
    # 2. 更新用户名 (实际上是邮箱/登录ID)
    try:
        current_user.email = new_username
        current_user.token_version += 1 # 强制下线
        db.add(current_user)
        db.commit()
        db.refresh(current_user)
        db.refresh(current_user)
        logger.info(f"User changed email (username) to {new_username} successfully.")
        
        # Clear server-side session to remove old user data
        request.session.clear()

        # Create response and clear cookie to force re-login and avoid redirect loop
        response = JSONResponse({"status": "success", "message": "用户名修改成功，请重新登录", "new_username": new_username})
        response.delete_cookie(key="access_token")
        return response
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to change username: {e}")
        raise HTTPException(status_code=500, detail="修改失败")


# ----------------------
# 系统管理 API
# ----------------------
@app.post("/api/system/restart")
async def restart_system(
    current_user: User = Depends(get_current_active_user)
):
    """重启系统 (通过退出进程让 Docker 自动重启)"""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="需要管理员权限")
    
    def _restart():
        import time
        time.sleep(1) # 给一点时间让响应发送完毕
        logger.warning("🔄 System restarting via process exit...")
        os._exit(1) # 强制退出，依赖 Docker restart policy

    # 在后台线程执行重启，确保当前请求能返回响应
    import threading
    threading.Thread(target=_restart).start()
    
    return {"status": "success", "message": "系统正在重启..."}


@app.post("/auth/logout")
async def logout(request: Request, response: Response):
    """退出登录"""
    # 1. 尝试获取当前用户以进行清理（即使失败也不影响注销流程）
    try:
        token = request.session.get("access_token") or request.cookies.get("access_token")
        if token:
             payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
             email = payload.get("sub")
             
             db = SessionLocal()
             try:
                 user = db.query(User).filter(User.email == email).first()
                 if user:
                     # 🔒 安全增强：注销时立即使所有相关的下载令牌失效
                     # 这样即使链接泄露，一旦用户退出，链接也作废
                     from app.models.cursor import DownloadToken
                     count = db.query(DownloadToken).filter(
                         DownloadToken.user_id == user.id, 
                         DownloadToken.is_active == True
                     ).update({DownloadToken.is_active: False})
                     db.commit()
                     logger.info(f"🔒 User {email} logged out. Invalidated {count} download tokens.")
             finally:
                 db.close()
    except Exception as e:
        logger.warning(f"Logout cleanup warning: {e}")

    # 2. 清除会话和Cookie
    request.session.clear()
    response = JSONResponse({"status": "success"})
    response.delete_cookie("access_token")
    return response

# ----------------------
# 启动入口
# ----------------------
if __name__ == "__main__":
    import uvicorn
    import logging
    
    # 配置 Uvicorn 日志级别
    # 减少访问日志噪音（304, 200等HTTP请求）
    uvicorn_log_level = "warning" if LOG_LEVEL == "INFO" else "info"
    
    # 设置 uvicorn.access 日志为更高级别，避免每个请求都记录
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    
    logger.info("🌐 Starting Uvicorn server on http://0.0.0.0:8000")
    logger.info(f"📡 Uvicorn access log level: {uvicorn_log_level.upper()}")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000,
        log_level=uvicorn_log_level,
        access_log=True  # 保留访问日志，但级别调高了
    )
