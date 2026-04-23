# 微信转存助手 (Wx2save)

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-green.svg)
![Docker](https://img.shields.io/badge/docker-supported-blue.svg)

**微信转存助手** 是一个基于 FastAPI 构建的高性能消息接收、解密、存储和管理系统。它能够对接企业微信（wework）的 API 回调，实时接收消息并持久化存储，同时提供这就好了一个现代化的 Web 控制台供管理员查看、搜索和管理消息。

---
## 使用前务必先阅读
    1.必须有企业微信的管理员账号

    2.必须有公网IPV4或者云服务器（建议云服务器，家用IPV4动态IP，需经常更新企业微信应用的可信IP），或其他人提供的企微公益转发服务。

    3.必须有域名，并解析到公网IP，反代本项目端口（默认8000）

    4.会企业微信应用的回调接口配置。

    5.提供几个可行的方案。
      A.公网动态IPV4+域名+反代，MP的插件来更新企业微信应用的可信ip。
      B.云服务器+域名+反代，直接部署在云服务器上，文件可以保存在云服务器，也可以保存在nas端部署的S3储存。
      C.云服务器+域名+反代，项目部署在nas端，通过云服务器转发数据包到企业微信api。
      D.nas本地本身就有固定公网ipv4（土豪专用）。

## 🚀 主要功能

- **⚡ 高性能解密**: 使用 C++ 编写的 `WXBizMsgCrypt` 官方库封装，确保高并发下的消息解密性能。
- **💾 消息持久化**: 自动将接收到的 XML 消息解析并存储到 SQLite 数据库（后续支持平滑迁移到 MySQL/PostgreSQL）。
- **📊 Web 管理控制台**:
  - **仪表盘**: 实时查看消息统计和最新消息。
  - **消息检索**: 根据时间、发送者、消息类型进行全文检索。
  - **多类型支持**: 完美展示文本、图片、文件、链接、外部联系人等多种消息类型。
- **🛡️ 安全可靠**:
  - 完整的登录认证机制。
  - 自动 CSRF 保护和安全标头。
  - 敏感配置加密存储。
- **📦 批量操作**: 支持消息的批量删除和批量打包下载（ZIP 格式）。
- **🐳 Docker 支持**: 提供一键部署的 Docker 镜像和 `docker-compose` 配置。
- **💾 对象存储**: 支持将文件存储到S3对象存储（如 MinIO、阿里云OSS等），实现文件储存和项目分离。

## 🛠️ 技术栈

- **后端**: [FastAPI](https://fastapi.tiangolo.com/) (Python 3.9+)
- **数据库**: SQLAlchemy (ORM) + SQLite (Default)
- **模板引擎**: Jinja2
- **前端**: Bootstrap 5 + Vanilla JS
- **部署**: Docker + Docker Compose

## 🏁 快速开始

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
        - ./data:/app/data
        - ./logs:/app/app/logs
        - ./media_files:/app/media_files
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


### 方式二：本地运行

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 初始化配置
python init_config.py

# 3. 启动服务
python main.py
```

更详细的安装和配置指南，请参阅 [安装配置指南 (INSTALL.md)](./INSTALL.md)。

## 📝 配置说明

核心配置文件位于 `data/config.yaml`。你需要填入企业微信后台提供的以下信息：

```yaml
wecom:
  corp_id: "ww..."          # 企业ID，在企业微信管理后台->我的企业->企业信息中查看
  corp_secret: "..."        # 应用Secret，在企业微信管理后台->应用与服务->应用管理->自建应用->点击应用->管理->Secret中查看
  token: "..."              # 回调Token，在企业微信管理后台->应用与服务->应用管理->自建应用->点击应用->管理->接收消息->设置api接收中查看
  encoding_aes_key: "..."   # 回调AESKey，同上。
```

企业微信后台设置步骤：

1、创建企业微信应用，进入接收消息->设置api接收

2、随机生成或自己填写token、encoding_aes_key

3、本项目config.yaml或者前端页面填入上述token、encoding_aes_key、corp_id、corp_secret并保存生效。

4、企业微信应用->配置回调接口,填入你的域名+端口+回调接口路径（默认：http://你的域名:端口/wecom/callback）

5、点击保存后，企业微信会向你的回调接口发送一个GET请求，验证回调接口是否可用，如果验证失败，请检查回调接口是否可用，是否可以被公网访问，防火墙是否放行该端口。

6、企业微信后台->应用管理->微信客服->客服账号->创建客服账号，然后在微信客服最下面，通过API管理会话消息-> 绑定前面创建的应用。

7、企业微信后台->应用管理->微信客服->客服账号->刚刚创建的客服账号-> 里的连接，用常用微信号点开，就是添加了客服，然后就可以在常用微信号里给客服发消息了。本项目后台即可自动保存消息内容、文件。



## 📸 运行截图

![ScreenShot 2026 02 10 113232 489](https://origin.picgo.net/2026/02/10/ScreenShot_2026-02-10_113232_48940e7255cb4b50918.png)
![ScreenShot 2026 02 10 113327 034](https://origin.picgo.net/2026/02/10/ScreenShot_2026-02-10_113327_0345c5f9b5ac8c44200.png)


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Wx2save
