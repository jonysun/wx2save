# 阶段一：构建环境 (Builder)
FROM python:3.10-alpine as builder

WORKDIR /app

# 安装构建依赖 (编译 cryptography, cffi, pycryptodome 等需要)
RUN apk add --no-cache \
    gcc \
    musl-dev \
    python3-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    make

# 复制依赖文件
COPY requirements.txt .

# 编译并安装依赖到 /install 目录
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# -------------------------------------------

# 阶段二：运行环境 (Runner)
FROM python:3.10-alpine

WORKDIR /app

# 设置环境变量
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Shanghai \
    PYTHONPATH=/usr/local/lib/python3.10/site-packages

# 安装运行时必需的系统库 (如 libffi 用于 cryptography)
# tzdata 用于设置时区
# 安装运行时必需的系统库 (如 libffi 用于 cryptography)
# tzdata 用于设置时区
# bash 用于终端访问
RUN apk add --no-cache \
    libffi \
    tzdata \
    bash \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone

# 从构建阶段复制已安装的 Python 包
COPY --from=builder /install /usr/local

# 复制项目代码
# 注意：只复制必要文件，利用 .dockerignore 排除无关文件
COPY . .

# 创建 reset_password 命令别名
RUN echo '#!/bin/sh' > /usr/local/bin/reset_password && \
    echo 'python /app/scripts/reset_password.py' >> /usr/local/bin/reset_password && \
    chmod +x /usr/local/bin/reset_password

# 创建必要的目录并设置权限
# 使用非 root 用户运行更安全（可选，这里为了简单仍用# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/media_files && \
    chmod 777 /app/data /app/logs /app/media_files

# 复制入口脚本
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# 暴露端口
EXPOSE 8000

# 启动命令
ENTRYPOINT ["/bin/sh", "entrypoint.sh"]
