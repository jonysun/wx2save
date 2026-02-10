# app/routers/auth_router.py
"""
Authentication routes: login, logout, first-login
"""
from fastapi import APIRouter, Request, Response, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel
import logging
import datetime
import jwt

from app.core.database import get_db
from app.core.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, ADMIN_PASSWORD, MAX_LOGIN_ATTEMPTS, LOGIN_TIMEOUT_MINUTES
from app.core.security import verify_password, get_password_hash, create_access_token
from app.models import User
from app.services import APP_START_TIME

logger = logging.getLogger("wecom")

router = APIRouter(tags=["auth"])
templates = Jinja2Templates(directory="templates")


# Rate limiting for login
from collections import defaultdict
import time as time_module

login_attempts = defaultdict(list)
MAX_ATTEMPTS = MAX_LOGIN_ATTEMPTS
TIMEOUT_MINUTES = LOGIN_TIMEOUT_MINUTES


class LoginRequest(BaseModel):
    email: str
    password: str


class PasswordChangeRequest(BaseModel):
    new_password: str
    confirm_password: str


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """登录页面"""
    # 如果已登录，重定向到dashboard
    token = request.session.get("access_token") or request.cookies.get("access_token")
    if token:
        try:
            jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return RedirectResponse(url="/dashboard", status_code=302)
        except:
            pass
    
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login/submit")
async def login_submit(
    login_data: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """处理登录请求"""
    client_ip = request.client.host
    now = time_module.time()
    
    # 清理过期的登录尝试记录
    login_attempts[client_ip] = [t for t in login_attempts[client_ip] if now - t < TIMEOUT_MINUTES * 60]
    
    # 检查登录尝试次数
    if len(login_attempts[client_ip]) >= MAX_ATTEMPTS:
        logger.warning(f"🚫 Login rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=429,
            detail=f"登录尝试次数过多，请{TIMEOUT_MINUTES}分钟后再试"
        )
    
    # 查询用户
    user = db.query(User).filter(User.email == login_data.email).first()
    
    if not user or not verify_password(login_data.password, user.hashed_password):
        login_attempts[client_ip].append(now)
        logger.warning(f"❌ Failed login attempt for {login_data.email} from {client_ip}")
        raise HTTPException(status_code=401, detail="邮箱或密码错误")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="账户已被禁用")
    
    # 清除该IP的失败记录
    login_attempts[client_ip] = []
    
    # 创建token
    token_data = {
        "sub": user.email,
        "user_id": user.id,
        "app_start_time": APP_START_TIME
    }
    access_token = create_access_token(token_data)
    
    # 更新登录信息
    user.last_login_ip = client_ip
    user.last_login_time = datetime.datetime.utcnow()
    db.commit()
    
    logger.info(f"✅ User {user.email} logged in from {client_ip}")
    
    # 检查是否首次登录
    if user.first_login:
        response = JSONResponse(content={
            "status": "success",
            "message": "首次登录，需要修改密码",
            "redirect": "/first-login",
            "access_token": access_token
        })
        response.set_cookie(key="access_token", value=access_token, httponly=True, samesite="lax")
        return response
    
    # 正常登录
    response = JSONResponse(content={
        "status": "success",
        "message": "登录成功",
        "redirect": "/dashboard",
        "access_token": access_token
    })
    response.set_cookie(key="access_token", value=access_token, httponly=True, samesite="lax")
    return response


@router.get("/first-login", response_class=HTMLResponse)
async def first_login_page(request: Request, db: Session = Depends(get_db)):
    """首次登录修改密码页面"""
    token = request.session.get("access_token") or request.cookies.get("access_token")
    
    if not token:
        return RedirectResponse(url="/login", status_code=302)
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        
        if not email:
            return RedirectResponse(url="/login", status_code=302)
        
        user = db.query(User).filter(User.email == email).first()
        if not user or not user.first_login:
            return RedirectResponse(url="/dashboard", status_code=302)
        
        return templates.TemplateResponse("first_login.html", {
            "request": request,
            "email": email
        })
    except Exception as e:
        logger.error(f"❌ First login page error: {str(e)}")
        return RedirectResponse(url="/login", status_code=302)


@router.post("/auth/first-login/password/submit")
async def first_login_password_submit(
    password_data: PasswordChangeRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """处理首次登录密码修改"""
    token = request.session.get("access_token") or request.cookies.get("access_token")
    
    if not token:
        raise HTTPException(status_code=401, detail="未登录")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        
        if not email:
            raise HTTPException(status_code=401, detail="Token无效")
        
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="用户不存在")
        
        # 验证密码
        if password_data.new_password != password_data.confirm_password:
            raise HTTPException(status_code=400, detail="两次密码不一致")
        
        if len(password_data.new_password) < 12:
            raise HTTPException(status_code=400, detail="密码长度至少12位")
        
        # 更新密码
        user.hashed_password = get_password_hash(password_data.new_password)
        user.first_login = False
        user.last_password_change = datetime.datetime.utcnow()
        db.commit()
        
        logger.info(f"✅ User {email} completed first login password change")
        
        return JSONResponse(content={
            "status": "success",
            "message": "密码修改成功，即将跳转到仪表板",
            "redirect": "/dashboard"
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Password change error: {str(e)}")
        raise HTTPException(status_code=500, detail="密码修改失败")


@router.post("/logout")
async def logout(response: Response):
    """登出"""
    response = JSONResponse(content={"status": "success", "message": "已登出"})
    response.delete_cookie("access_token")
    return response
