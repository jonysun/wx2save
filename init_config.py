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
        # Update URL to match Docker container path (mapped from host ./data to /app/data)
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

def init_config():
    if os.path.exists(CONFIG_FILE):
        if os.path.isdir(CONFIG_FILE):
            print(f"❌ Error: '{CONFIG_FILE}' exists but is a DIRECTORY. Please remove it first.")
            return
        print(f"✅ '{CONFIG_FILE}' already exists. Skipping generation.")
    else:
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, allow_unicode=True)
            print(f"✅ Successfully created default '{CONFIG_FILE}'")
            print("👉 Please edit it to fill in your WeCom credentials, or set them via Environment Variables.")
        except Exception as e:
            print(f"❌ Failed to create config file: {e}")

    # Check and create database file to prevent Docker directory mount issue
    DB_FILE = os.path.join(DATA_DIR, "wecom_messages.db")
    if os.path.exists(DB_FILE):
        if os.path.isdir(DB_FILE):
            print(f"❌ Error: '{DB_FILE}' exists but is a DIRECTORY. Please remove it first.")
        else:
            print(f"✅ '{DB_FILE}' already exists. Skipping generation.")
    else:
        try:
            with open(DB_FILE, 'w') as f:
                pass # Create empty file
            print(f"✅ Successfully created empty database file '{DB_FILE}'")
        except Exception as e:
            print(f"❌ Failed to create database file: {e}")


if __name__ == "__main__":
    init_config()
