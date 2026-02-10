# 安装配置指南 (Installation & Configuration Guide)

本文档详细介绍了如何部署和配置 **企业微信消息管理平台**。

---

## 📋 前置要求

- **操作系统**: Windows / Linux / macOS
- **环境**:
  - **Docker** (推荐): 只需要安装 Docker Desktop 或 Docker Engine。
  - **Python** (传统方式): 需要 Python 3.9 或更高版本。

---

## 🚀 部署方式

### 方式一：Docker 部署（推荐）

1. **配置环境**:
   - 首次运行建议先创建持久化目录：
   ```bash
   mkdir -p data
   mkdir -p media_files
   ```
   后续docker会在data目录下创建config.yaml配置文件，并挂载到容器中。
   - 也可以先手动创建config.yaml文件，并填好企业微信的配置信息。

  - 推荐docker compose 部署:
  ```bash
  version: '3.8'
  services:
    wx2save:
      image: jonysun/wx2save:latest
      container_name: wx2save
      restart: unless-stopped
      ports:
        - "8000:8000"
      volumes:
        - ./data:/app/data                 # 配置文件目录config.yaml
        - ./media_files:/app/media_files   # 下载的目录
      environment:
        - TZ=Asia/Shanghai
        - LOG_DIR=/app/app/logs
        - DATABASE_URL=sqlite:////app/wecom_messages.db
      healthcheck:
        test: [ "CMD", "curl", "-f", "http://localhost:8000/login" ]
        interval: 30s
        timeout: 10s
        retries: 3
      logging:
        driver: "json-file"
        options:
          max-size: "10m"
          max-file: "3"
  ```

2. **启动服务**:
   ```bash
   docker-compose up -d
   ```

3. **访问控制台**:
   打开浏览器访问 `http://localhost:8000`。
   *默认管理员账号会在首次启动日志中生成，请注意查看。*
   - 首次登录后，会提示强制修改默认密码，也可以修改用户名（可选）。

4. **配置企业微信**:
   - 登录后，进入“系统设置”页面，填入企业微信的配置信息并保存。

5.  **接收消息**:
    - 检查项目中的企业微信相关配置与企业微信后台配置一致，且企业微信后台回调成功后，尝试发送消息到客服，成功后即在web界面看到消息。

---

### 方式二：手动源码部署

如果你希望在本地直接运行或进行二次开发，可以使用此方式。

1.  **创建虚拟环境**:
    ```bash
    python -m venv .venv
    # 激活环境
    # Windows:
    .venv\Scripts\activate
    # Linux/Mac:
    source .venv/bin/activate
    ```

2.  **安装依赖**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **初始化配置**:
    运行初始化脚本，它会在 `data/` 目录下生成 `config.yaml` 和数据库文件。
    ```bash
    python init_config.py
    ```

4.  **启动服务**:
    ```bash
    python main.py
    ```
    或者使用 `uvicorn`:
    ```bash
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    ```

---

## ⚙️ 配置详解

配置文件位于 `data/config.yaml`。只有配置了正确的企业微信参数，系统才能正常接收消息。

### 1. 企业微信参数 (`wecom` 部分)

登录 [企业微信管理后台](https://work.weixin.qq.com/wework_admin/frame)，进入 **应用管理** -> **创建应用** (或选择已有应用)。

| 参数名 | 说明 | 获取方式 |
| :--- | :--- | :--- |
| `corp_id` | 企业 ID | "我的企业" -> "企业信息" 最下方 |
| `corp_secret` | 应用 Secret | 点击具体应用，查看 Secret |
| `token` | 回调 Token | 应用详情页 -> "接收消息" -> "设置 API 接收" |
| `encoding_aes_key` | 回调 AES Key | 同上 |

**`data/config.yaml` 示例**:

```yaml
wecom:
  corp_id: "你的企业微信的corp_id"
  corp_secret: "你的应用Secret"
  token: "你的Token"
  encoding_aes_key: "你的AESKey"
```

### 2. 回调 URL 配置

在企业微信后台的 "接收消息" 设置中，填写以下信息：

- **URL**: `http://你的服务器IP或域名:8000/wecom/callback`
- **Token**: 与配置文件一致
- **EncodingAESKey**: 与配置文件一致

> **注意**: 企业微信要求 URL 必须是公网可访问的。如果你在本地测试，需要使用内网穿透工具 (如 ngrok, frp) 将本地 8000 端口映射到公网。

### 3. 安全与数据库 (`security`, `database`)

通常保持默认即可。

```yaml
security:
  # 用于加密 Session 的密钥，首次启动会自动生成随机值
  secret_key: "..." 


database:
  # SQLite 数据库路径
  url: "sqlite:////app/data/wecom_messages.db" # Docker 环境
  # url: "sqlite:///data/wecom_messages.db"   # 本地环境
```

---

## 📁 目录结构说明

- `app/`: 核心代码逻辑。
- `data/`: **存储重要数据**。
    - `config.yaml`: 配置文件。
    - `wecom_messages.db`: SQLite 数据库文件。
- `media_files/`: **存储媒体资源** (图片、视频、文件等)，挂载到容器 `/app/media_files`。
- `logs/`: 运行日志，排查问题时查看 `wecom.log`。

---

## ❓ 常见问题

**Q: 启动后无法访问？**
A: 检查防火墙是否放行了 8000 端口（或设定的其他端口）。如果是云服务器，还需要在安全组中开放端口。

**Q: 企业微信后台提示 "URL验证失败"？**
A: 
1. 确保服务器能被公网访问。
2. 确保 `token` 和 `encoding_aes_key` 与后台完全一致。
3. 检查日志 `logs/wecom.log` 看是否有具体的报错信息。

**Q: 如何重置管理员密码？**
A: 删除 `data/wecom_messages.db` (警告：会丢失所有数据！) 后重启，系统会重新初始化并生成新密码。或者通过命令行执行python reset_password.py。