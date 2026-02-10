# app/config.py
import os
import yaml
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("config")

# 加载 config.yaml
# 配置存储目录（使得 Docker 挂载目录而不是文件，避免 "Is a directory" 错误）
DATA_DIR = os.getenv("DATA_DIR", "data")
os.makedirs(DATA_DIR, exist_ok=True)

# 加载 config.yaml (现在位于 data/config.yaml)
CONFIG_FILE = os.path.join(DATA_DIR, "config.yaml")

_config = {}

if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            _config = yaml.safe_load(f) or {}
        logger.info(f"✅ Loaded configuration from {CONFIG_FILE}")
    except Exception as e:
        logger.error(f"❌ Failed to load {CONFIG_FILE}: {e}")
        _config = {}
else:
    logger.warning(f"⚠️ {CONFIG_FILE} not found, generating default config...")
    # 默认配置模板
    _default_config = {
        'wecom': {
            'corp_id': '',
            'corp_secret': '',
            'token': '',
            'encoding_aes_key': ''
        },
        'security': {
            'secret_key': "change_me_in_prod_" + os.urandom(12).hex(),
            'algorithm': "HS256",
            'access_token_expire_minutes': 30
        },
        'logging': {
            'level': "INFO",
            'rotation': "daily",
            'max_bytes': 10485760,
            'backup_count': 7
        },
        'database': {
            # 数据库也移入 data 目录
            'url': f"sqlite:///{DATA_DIR}/wecom_messages.db"
        },
        'storage': {
            # 媒体文件也建议移入 data/media，但保持 media_files 也没问题，这里统一一下
            'media_path': f"{DATA_DIR}/media_files",
            's3_enabled': False,
            's3_endpoint_url': '',
            's3_access_key': '',
            's3_secret_key': '',
            's3_bucket_name': '',
            's3_region_name': '',
            's3_bucket_name': '',
            's3_region_name': '',
            's3_presigned_expiration': 3600,
            's3_proxy_mode': True  # 默认开启代理模式 (解决内网穿透/隐藏后端)，设为 False 则使用 Redirect 302 跳转直连
        },
        'rate_limit': {
            'max_login_attempts': 5,
            'login_timeout_minutes': 10
        },
        'ui': {
            'show_debug_info': False  # Default hidden
        }
    }
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            yaml.dump(_default_config, f, default_flow_style=False, allow_unicode=True)
        _config = _default_config
        logger.info(f"✅ Generated default configuration at {CONFIG_FILE}")
    except Exception as e:
        logger.error(f"❌ Failed to create default config: {e}")
        _config = {}

        
    # ⚠️ 强制每次启动生成新的 SECRET_KEY，确保重启后旧 Session 失效 (User Requirement)
    # 如果想保持 Session 持久化，请注释掉下面这行
    if 'security' not in _config:
        _config['security'] = {}
    _config['security']['secret_key'] = "dynamic_" + os.urandom(16).hex()
    logger.info("🔐 Generated ephemeral SECRET_KEY for this session (Old sessions will be invalid)")

# 获取配置的辅助函数 (优先级: Env Var > YAML > Default)
def get_config(env_key, section, key, default=None):
    # 1. 尝试从环境变量获取
    env_val = os.getenv(env_key)
    if env_val:
        return env_val
    # 2. 尝试从 YAML 获取
    return _config.get(section, {}).get(key, default)

# ==========================================
# 企业微信配置
# ==========================================
wecom_cfg = _config.get('wecom', {})
CORP_ID = get_config("WECOM_CORP_ID", 'wecom', 'corp_id', "wwa63b837649300e8f")
CORP_SECRET = get_config("WECOM_CORP_SECRET", 'wecom', 'corp_secret', "_5Blt0T1-9ceSMS-Wf7N29d9hqj54TbPXvbaikO8auc")
TOKEN = get_config("WECOM_TOKEN", 'wecom', 'token', "OOCcdxsqinuB4Nw82qdFj5iKhp")
ENCODING_AES_KEY = get_config("WECOM_ENCODING_AES_KEY", 'wecom', 'encoding_aes_key', "lJxY4WMTXhocR1K7vfO17hd0mzvE790vOX0YXEanUt2")
# API 代理配置
WECOM_API_BASE_URL = get_config("WECOM_API_BASE_URL", 'wecom', 'api_base_url', "https://qyapi.weixin.qq.com")
# 移除末尾的斜杠(如果存在)
if WECOM_API_BASE_URL.endswith('/'):
    WECOM_API_BASE_URL = WECOM_API_BASE_URL[:-1]

WECOM_API_PROXY_TOKEN = get_config("WECOM_API_PROXY_TOKEN", 'wecom', 'api_proxy_token', "")

# ==========================================
# 安全配置
# ==========================================
sec_cfg = _config.get('security', {})
# 优先级: Env Var > YAML > Default
SECRET_KEY = get_config("SECRET_KEY", 'security', 'secret_key', "your_very_strong_secret_key_here")
ALGORITHM = get_config("ALGORITHM", 'security', 'algorithm', "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(get_config("ACCESS_TOKEN_EXPIRE_MINUTES", 'security', 'access_token_expire_minutes', 30))
ADMIN_PASSWORD = get_config("ADMIN_PASSWORD", 'security', 'admin_password', None)

# ==========================================
# 数据库配置
# ==========================================
db_cfg = _config.get('database', {})
DATABASE_URL = get_config("DATABASE_URL", 'database', 'url', f"sqlite:///{DATA_DIR}/wecom_messages.db")

# 如果在Docker中运行（检测 /app 目录），且配置的URL看起来像是Windows路径或者没有指向 /app/data
if os.path.exists('/app') and 'sqlite' in DATABASE_URL:
    # 简单的启发式检查：如果URL不包含 /app/data（且是sqlite），则强制修正
    # 这能解决用户把 Windows 生成的 config.yaml (含 d:/... 路径) 挂载到 Docker 的情况
    if '/app/data' not in DATABASE_URL:
        # 保留原文件名，但强制路径到 /app/data
        # 尝试从原URL提取文件名
        try:
             import re
             # 匹配最后的文件名 (假设以 .db 结尾)
             match = re.search(r'[^/\\]+\.db$', DATABASE_URL)
             db_name = match.group(0) if match else "wecom_messages.db"
        except:
             db_name = "wecom_messages.db"
             
        old_url = DATABASE_URL
        DATABASE_URL = f"sqlite:////app/data/{db_name}"
        logger.warning(f"⚠️ Detected Docker environment with potentially incorrect DB path: {old_url}")
        logger.warning(f"🔧 Automatically fixed DATABASE_URL to: {DATABASE_URL}")

# ==========================================
# 文件存储
# ==========================================
# ==========================================
# 文件存储 (支持本地和S3)
# ==========================================
store_cfg = _config.get('storage', {})
MEDIA_STORAGE_PATH = get_config("MEDIA_STORAGE_PATH", 'storage', 'media_path', "media_files")

# S3 配置
# 修复：先转字符串再 lower，防止 yaml 解析为 bool 类型导致报错
S3_ENABLED = str(get_config("S3_ENABLED", 'storage', 's3_enabled', "False")).lower() == "true"
S3_ENDPOINT_URL = get_config("S3_ENDPOINT_URL", 'storage', 's3_endpoint_url', None)
S3_ACCESS_KEY = get_config("S3_ACCESS_KEY", 'storage', 's3_access_key', "")
S3_SECRET_KEY = get_config("S3_SECRET_KEY", 'storage', 's3_secret_key', "")
S3_BUCKET_NAME = get_config("S3_BUCKET_NAME", 'storage', 's3_bucket_name', "")
S3_REGION_NAME = get_config("S3_REGION_NAME", 'storage', 's3_region_name', "")
S3_PRESIGNED_EXPIRATION = int(get_config("S3_PRESIGNED_EXPIRATION", 'storage', 's3_presigned_expiration', 3600))

# ==========================================
# 速率限制
# ==========================================
rate_cfg = _config.get('rate_limit', {})
MAX_LOGIN_ATTEMPTS = int(get_config("MAX_LOGIN_ATTEMPTS", 'rate_limit', 'max_login_attempts', 5))
LOGIN_TIMEOUT_MINUTES = int(get_config("LOGIN_TIMEOUT_MINUTES", 'rate_limit', 'login_timeout_minutes', 10))

# ==========================================
# UI 配置
# ==========================================
ui_cfg = _config.get('ui', {})
SHOW_DEBUG_INFO = get_config("SHOW_DEBUG_INFO", 'ui', 'show_debug_info', False)
if isinstance(SHOW_DEBUG_INFO, str):
    SHOW_DEBUG_INFO = SHOW_DEBUG_INFO.lower() == 'true'

# ==========================================
# 日志配置
# ==========================================
logging_cfg = _config.get('logging', {})
LOG_LEVEL = get_config("LOG_LEVEL", 'logging', 'level', 'INFO').upper()
LOG_ROTATION = get_config("LOG_ROTATION", 'logging', 'rotation', 'daily')
LOG_MAX_BYTES = int(get_config("LOG_MAX_BYTES", 'logging', 'max_bytes', 10485760))  # 10MB
LOG_BACKUP_COUNT = int(get_config("LOG_BACKUP_COUNT", 'logging', 'backup_count', 7))

logger.info(f"📊 Log Level: {LOG_LEVEL}")
logger.info(f"📋 Log Rotation: {LOG_ROTATION}")

# 日志路径（从环境变量或配置文件读取）
LOG_DIR = get_config("LOG_DIR", 'logging', 'log_dir', 'app/logs')
os.makedirs(LOG_DIR, exist_ok=True)

# 重新保存配置的函数（用于更新设置）
def save_config(new_config):
    try:
        current = _config.copy()
        
        # 深度更新
        if 'wecom' not in current: current['wecom'] = {}
        current['wecom'].update(new_config.get('wecom', {}))
        
        if 'storage' not in current: current['storage'] = {}
        current['storage'].update(new_config.get('storage', {}))
        
        # 暂时只允许修改 wecom/storage 配置，增加安全性
        # if 'security' not in current: current['security'] = {}
        # current['security'].update(new_config.get('security', {}))
        
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            yaml.dump(current, f, default_flow_style=False, allow_unicode=True)
            
        return True
    except Exception as e:
        logger.error(f"❌ Failed to save config: {e}")
        return False

# ==========================================
# 运行时状态监测
# ==========================================
CALLBACK_STATUS = {
    "last_success": None, # datetime
    "last_error": None,   # str
    "error_count": 0,
    "last_check": None
}