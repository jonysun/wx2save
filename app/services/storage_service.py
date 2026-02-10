import os
import logging
import boto3
from botocore.exceptions import ClientError
from app.core.config import (
    MEDIA_STORAGE_PATH,
    S3_ENABLED, S3_ENDPOINT_URL, S3_ACCESS_KEY, S3_SECRET_KEY, 
    S3_BUCKET_NAME, S3_REGION_NAME, S3_PRESIGNED_EXPIRATION
)

logger = logging.getLogger("storage")

class StorageService:
    def __init__(self):
        self.s3_client = None
        if S3_ENABLED:
            # 自动补全协议头 (boto3 必须要求 http:// 或 https://)
            endpoint = S3_ENDPOINT_URL
            if endpoint and not endpoint.startswith(('http://', 'https://')):
                endpoint = f"http://{endpoint}"
                logger.warning(f"⚠️ S3 Endpoint missing protocol, auto-fixed to: {endpoint}")

            # Log Proxy Information
            http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
            https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
            if http_proxy or https_proxy:
                logger.info(f"🌐 Proxy Detected - HTTP: {http_proxy}, HTTPS: {https_proxy}")
            else:
                logger.info("🌐 No System Proxy detected (HTTP_PROXY/HTTPS_PROXY not set)")

            logger.info(f"🔧 Initializing S3 Client... Endpoint: {endpoint}, Region: {S3_REGION_NAME}, Bucket: {S3_BUCKET_NAME}")
            try:
                self.s3_client = boto3.client(
                    's3',
                    endpoint_url=endpoint,
                    aws_access_key_id=S3_ACCESS_KEY,
                    aws_secret_access_key=S3_SECRET_KEY,
                    region_name=S3_REGION_NAME
                )
                logger.info(f"✅ S3 Storage initialized (Bucket: {S3_BUCKET_NAME})")
            except Exception as e:
                logger.error(f"❌ Failed to initialize S3 client: {e}", exc_info=True)
                self.s3_client = None
        else:
            logger.info("ℹ️ S3 Storage is DISABLED in config.")

    def check_connection(self) -> tuple[bool, str]:
        """
        检查S3连接是否正常
        Returns: (success, message)
        """
        if not S3_ENABLED or not self.s3_client:
            return False, "S3 not enabled or client init failed"
        
        try:
            # 尝试列出 bucket (HEAD 请求，开销极小)
            # 或者列出对象 (ListObjectsV2 with limit 1)
            # 某些权限可能不允许 ListBucket，尝试 HeadBucket
            try:
                self.s3_client.head_bucket(Bucket=S3_BUCKET_NAME)
                return True, "Connected"
            except ClientError as e:
                # 404 Not Found (Bucket不存在) -> Error
                # 403 Forbidden (无权限) -> Error
                error_code = e.response.get("Error", {}).get("Code")
                if error_code == "404":
                    return False, f"Bucket '{S3_BUCKET_NAME}' does not exist"
                elif error_code == "403":
                    return False, f"Access denied to bucket '{S3_BUCKET_NAME}'"
                else:
                    raise e
                    
        except Exception as e:
            logger.error(f"S3 Connection Check Failed: {e}")
            return False, str(e)

    def save_file(self, content: bytes, filename: str) -> str:
        """
        保存文件到存储系统 (本地 or S3)
        Returns: strict filename or relative path
        """
        # 1. 始终保存到本地 (作为缓存/最新文件)
        local_path = self._save_to_local(content, filename)
        
        # 2. 如果启用了 S3，则同步上传 (作为归档/历史)
        if S3_ENABLED:
             if self.s3_client:
                 logger.info(f"📤 Uploading to S3: {filename}")
                 self._save_to_s3(content, filename)
             else:
                 logger.error(f"⚠️ S3 ENABLED but client is None. Init failed? Check logs.")
        else:
             logger.debug("S3 is disabled, skipping upload.")

        if S3_ENABLED and self.s3_client:
             # 返回相对路径 (既是 S3 Key，也是本地相对路径)
            # 注意: _save_to_local 返回的是绝对路径，所以这里要处理一下
            # 但实际上 _save_to_s3 返回的就是 key (filename)
            # 为了保持一致性，我们返回 filename (作为相对路径/key)
            return filename
        else:
            return local_path # 如果只用本地，返回绝对路径以便 current logic works? 
            # 等等，之前的代码里 _save_to_local 返回了绝对路径
            # 而 _save_to_s3 返回了 key (relative)
            # 为了兼容性，如果 S3 没启用，保持原样返回绝对路径
            # 如果 S3 启用了，我们返回 Key (relative)，因为 main.py 里的 hybrid logic
            # 是根据 path 是否存在来判断的。
            # 如果返回绝对路径，main.py 也能处理。
            # 让我们统一返回相对路径 (filename) 比较好？
            # 不，_save_to_local 返回绝对路径是为了让 wecom_service 知道存哪了。
            # 让我们看看 wecom_service 怎么用返回值的。
            # answer: message.media_path = saved_path
            # 如果是绝对路径 -> main.py check os.path.exists -> True -> serve local
            # 如果是相对路径 -> main.py check os.path.exists -> False (unless chdir) -> check S3 -> redirect
            # 所以:
            # 策略 A: 始终返回绝对路径。
            #   - main.py check exists -> True -> serve local.
            #   - 如果本地删除了 (清理缓存)， absolute path check False -> check S3 ? 
            #   - 问题: main.py 怎么知道 S3 key? 是 absolute path 吗? No.
            #   - S3 key is usually relative.
            # 策略 B: 始终返回相对路径 (Key).
            #   - main.py check exists (need join MEDIA_PATH) -> True/False.
            #   - check S3 (using relative path) -> Redirect.
            #   - 这要求 main.py 懂得拼接 MEDIA_PATH。
            #   - 现在的 main.py 逻辑: if os.path.isabs(filename)... in get_file_url
            #   - 让我们看看 main.py 的 download_file:
            #       file_path = message.media_path
            #       if os.path.exists(file_path): serve
            #       elif storage.s3: storage.get_file_url(file_path)
            #   - 所以如果 message.media_path 是绝对路径，且文件被清理了，
            #     storage.get_file_url(abs_path) 会被调用。
            #     storage.get_file_url 现在的逻辑: if isabs -> try relpath -> get url.
            #     所以返回绝对路径是可行的！即便文件被删除了，get_file_url 也能算出 relative key。
            
            return local_path

    def _save_to_local(self, content: bytes, filename: str) -> str:
        try:
            filepath = os.path.join(MEDIA_STORAGE_PATH, filename)
            
            # 🔥 确保父目录存在 (例如 image/ 子目录)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # 如果文件已存在，避免覆盖? 或者直接覆盖
            with open(filepath, 'wb') as f:
                f.write(content)
            
            logger.info(f"💾 Saved to local disk: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"❌ Failed to save to local disk: {e}")
            return None

    def _save_to_s3(self, content: bytes, filename: str) -> str:
        try:
            # S3 Key - 可以加日期前缀等，这里简单保持文件名
            s3_key = filename 
            
            self.s3_client.put_object(
                Bucket=S3_BUCKET_NAME,
                Key=s3_key,
                Body=content
            )
            logger.info(f"☁️ Uploaded to S3: {s3_key}")
            return s3_key
        except Exception as e:
            logger.error(f"❌ Failed to upload to S3: {e}")
            # 降级到本地存储? 或者直接返回失败
            return None

    def get_file_stream(self, filename: str):
        """
        获取文件流 (用于代理下载，解决内网S3无法外部访问的问题)
        Returns: (stream, content_type, content_length) or (None, None, None)
        """
        if not S3_ENABLED or not self.s3_client:
            return None, None, None

        # 如果传入的是绝对路径，尝试转为相对路径(Key)
        if os.path.isabs(filename):
            try:
                filename = os.path.relpath(filename, MEDIA_STORAGE_PATH).replace('\\', '/')
            except ValueError:
                pass

        try:
            response = self.s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=filename)
            return response['Body'], response.get('ContentType'), response.get('ContentLength')
        except Exception as e:
            logger.error(f"❌ Failed to get S3 object stream: {e}")
            return None, None, None

    def get_file_url(self, filename: str) -> str:
        """
        获取文件访问链接 (S3预签名URL or 本地静态文件链接)
        """
        if not filename:
            return ""

        # 优先检查是否为存在的本地绝对路径 (兼容旧数据或混合存储)
        if os.path.isabs(filename) and os.path.exists(filename):
            try:
                # 计算相对路径: /app/data/media_files/img/1.jpg -> img/1.jpg
                rel_path = os.path.relpath(filename, MEDIA_STORAGE_PATH).replace('\\', '/')
                return f"/media/{rel_path}"
            except ValueError:
                # 路径不在 MEDIA_STORAGE_PATH 下? 直接返回 filename 或者是其他逻辑
                pass

        if S3_ENABLED and self.s3_client:
            try:
                url = self.s3_client.generate_presigned_url(
                    'get_object',
                    Params={
                        'Bucket': S3_BUCKET_NAME,
                        'Key': filename
                    },
                    ExpiresIn=S3_PRESIGNED_EXPIRATION
                )
                return url
            except Exception as e:
                logger.error(f"❌ Failed to generate presigned URL: {e}")
                return ""
        else:
            # 本地文件链接 (假设前端可以通过 /media/filename 访问)
            return f"/media/{filename}"

# 单例实例
storage = StorageService()
