import os
import secrets
import yaml

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

CONFIG_FILE = os.path.join(DATA_DIR, "config.yaml")

DEFAULT_CONFIG = {
    'wecom': {
        'corp_id': '',
        'corp_secret': '',
        'token': '',
        'encoding_aes_key': ''
    },
    'security': {
        # Generate a secure random key
        'secret_key': secrets.token_hex(32),
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
        # Docker-first default. Local runtime is auto-corrected in app.core.config when needed.
        'url': "sqlite:////app/data/wecom_messages.db"
    },
    'storage': {
        'media_path': "media_files", # Relative path, works for both Docker (/app/media_files) and Local
        's3_enabled': False,
        's3_endpoint_url': '',
        's3_access_key': '',
        's3_secret_key': '',
        's3_bucket_name': '',
        's3_region_name': '',
        's3_presigned_expiration': 3600
    },
    'rate_limit': {
        'max_login_attempts': 5,
        'login_timeout_minutes': 10
    }
}


def safe_print(message):
    try:
        print(message)
    except UnicodeEncodeError:
        fallback = message.encode('ascii', errors='ignore').decode('ascii')
        print(fallback)

def init_config():
    if os.path.exists(CONFIG_FILE):
        if os.path.isdir(CONFIG_FILE):
            safe_print(f"[ERROR] '{CONFIG_FILE}' exists but is a DIRECTORY. Please remove it first.")
            return
        safe_print(f"[OK] '{CONFIG_FILE}' already exists. Skipping generation.")
    else:
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, allow_unicode=True)
            safe_print(f"[OK] Successfully created default '{CONFIG_FILE}'")
            safe_print("[INFO] Please edit it to fill in your WeCom credentials, or set them via Environment Variables.")
        except Exception as e:
            safe_print(f"[ERROR] Failed to create config file: {e}")

    # Check and create database file to prevent Docker directory mount issue
    DB_FILE = os.path.join(DATA_DIR, "wecom_messages.db")
    if os.path.exists(DB_FILE):
        if os.path.isdir(DB_FILE):
            safe_print(f"[ERROR] '{DB_FILE}' exists but is a DIRECTORY. Please remove it first.")
        else:
            safe_print(f"[OK] '{DB_FILE}' already exists. Skipping generation.")
    else:
        try:
            with open(DB_FILE, 'w') as f:
                pass # Create empty file
            safe_print(f"[OK] Successfully created empty database file '{DB_FILE}'")
        except Exception as e:
            safe_print(f"[ERROR] Failed to create database file: {e}")


if __name__ == "__main__":
    init_config()
