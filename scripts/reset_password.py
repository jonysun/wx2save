# app/reset_password.py
import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
import secrets
import string
import logging
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models import User, Base
from app.services import get_password_hash
from app.core.config import DATABASE_URL

def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            sum(c.isdigit() for c in password) >= 2 and
            sum(not c.isalnum() for c in password) >= 2):
            return password

def reset_admin_password():
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
    db = SessionLocal()
    
    try:
        Base.metadata.create_all(bind=engine)
        
        admin = db.query(User).filter(User.email == "admin@example.com").first()
        
        random_password = generate_strong_password(16)
        
        if not admin:
            admin = User(
                email="admin@example.com",
                hashed_password=get_password_hash(random_password),
                is_superuser=True,
                is_active=True,
                first_login=True
            )
            db.add(admin)
            print("✅ 创建了新的管理员账户")
        else:
            admin.hashed_password = get_password_hash(random_password)
            admin.first_login = True
            print("✅ 重置了现有管理员账户")
        
        db.commit()
        
        print("✅ 管理员密码重置完成")
        print("========================================")
        print("🔑 新的登录凭证:")
        print(f"   用户名: admin@example.com")
        print(f"   密码: {random_password}")
        print("========================================")
        print("⚠️  请复制密码，首次登录后系统会强制要求修改密码")
        print("⚠️  出于安全考虑，此密码只会显示一次！")
        print("========================================")
        
        return True
        
    except Exception as e:
        print(f"❌ 重置密码失败: {str(e)}")
        return False
    finally:
        if 'db' in locals():
            db.close()

if __name__ == "__main__":
    reset_admin_password()