#!/bin/sh
# entrypoint.sh

# 检查数据库文件是否存在，不存在通过 touch 创建，确保是文件而不是目录
# 数据目录现在是 /app/data
if [ ! -f /app/data/wecom_messages.db ]; then
    echo "Creating empty database file in /app/data..."
    touch /app/data/wecom_messages.db
fi

# config.yaml 将由应用在启动时自动生成（如果不存在）


# 启动应用
exec python main.py
