# app/services/wecom_service.py
import xmltodict
import json
import logging
import datetime
import threading
import os
import mimetypes
import re
from sqlalchemy.orm import Session

from app.models import Message, MessageCursor, DeletedMessage, Customer
from app.services import (
    get_cursor_for_kfid, update_cursor_for_kfid, get_cached_access_token,
    download_media_file, get_db_for_async
)
from app.services.storage_service import storage
from app.utils.crypto import WXBizMsgCrypt
from app.core.config import (
    CORP_ID, TOKEN, ENCODING_AES_KEY, CALLBACK_STATUS,
    WECOM_API_BASE_URL, WECOM_API_PROXY_TOKEN
)


def reload_wecom_service_config():
    """
    热加载：刷新本模块中缓存的 WeCom 配置变量。
    WXBizMsgCrypt 在每次请求时重新创建，所以无需额外处理。
    """
    global CORP_ID, TOKEN, ENCODING_AES_KEY, WECOM_API_BASE_URL, WECOM_API_PROXY_TOKEN
    from app.core.config import (
        CORP_ID as _cid, TOKEN as _tk, ENCODING_AES_KEY as _aes,
        WECOM_API_BASE_URL as _url, WECOM_API_PROXY_TOKEN as _pt
    )
    CORP_ID = _cid
    TOKEN = _tk
    ENCODING_AES_KEY = _aes
    WECOM_API_BASE_URL = _url
    WECOM_API_PROXY_TOKEN = _pt
    logging.getLogger("wecom").info("🔄 WeCom service config reloaded (wecom_service.py)")


def batch_get_customer_info(external_userid_list, db: Session):
    """
    批量获取客户详情 (使用 batchget 接口)
    API: https://developer.work.weixin.qq.com/document/path/95159
    """
    if not external_userid_list:
        return {}
    
    # 去重 & 过滤空值
    external_userid_list = list(set([uid for uid in external_userid_list if uid]))
    if not external_userid_list:
        return {}

    # 1. 优先从数据库缓存查
    results_map = {}
    
    # Check cache (Optional: add expiry logic later)
    cached_customers = db.query(Customer).filter(Customer.external_userid.in_(external_userid_list)).all()
    for cust in cached_customers:
        results_map[cust.external_userid] = cust.to_dict()
        
    # Filter out what we already have
    # (For now, we trust cache. In future, we might want to refresh if old)
    missing_ids = [uid for uid in external_userid_list if uid not in results_map]
    
    if not missing_ids:
        return results_map

    # 2. 调用 API 获取缺失的
    access_token = get_cached_access_token()
    url = f"{WECOM_API_BASE_URL}/cgi-bin/kf/customer/batchget?access_token={access_token}"
    
    # WeCom Limit: max 100 per request
    chunk_size = 100
    import requests
    
    for i in range(0, len(missing_ids), chunk_size):
        chunk = missing_ids[i:i + chunk_size]
        payload = {
            "external_userid_list": chunk
        }
        
        try:
            logger.info(f"🔍 Batch getting customer info for {len(chunk)} users")
            headers = {}
            if WECOM_API_PROXY_TOKEN:
                headers['X-Antigrv-Token'] = WECOM_API_PROXY_TOKEN

            response = requests.post(url, json=payload, headers=headers, timeout=10)
            res_json = response.json()
            
            if res_json.get('errcode') == 0:
                customer_list = res_json.get('customer_list', [])
                for cust_data in customer_list:
                    uid = cust_data.get('external_userid')
                    if not uid: continue
                    
                    nickname = cust_data.get('nickname')
                    avatar = cust_data.get('avatar')
                    gender = cust_data.get('gender')
                    
                    # Store/Update DB
                    customer = db.query(Customer).filter(Customer.external_userid == uid).first()
                    if not customer:
                        customer = Customer(external_userid=uid)
                        db.add(customer)
                    
                    customer.nickname = nickname
                    customer.avatar = avatar
                    customer.gender = gender
                    customer.extra_info = json.dumps(cust_data)
                    customer.updated_at = datetime.datetime.utcnow()
                    
                    results_map[uid] = customer.to_dict()
                
                db.commit()
            else:
                logger.error(f"❌ Failed to batch get customers: {res_json}")
                
        except Exception as e:
            logger.error(f"❌ Exception in batch_get_customer_info: {e}")
            
    return results_map


logger = logging.getLogger("wecom")


def verify_url(msg_signature, timestamp, nonce, echostr):
    """企业微信URL验证"""
    try:
        wxcpt = WXBizMsgCrypt(TOKEN, ENCODING_AES_KEY, CORP_ID)
        ret, sEchoStr = wxcpt.VerifyURL(msg_signature, timestamp, nonce, echostr)
        if ret != 0:
            CALLBACK_STATUS['last_error'] = f"VerifyURL failed: code={ret}"
            CALLBACK_STATUS['error_count'] = CALLBACK_STATUS.get('error_count', 0) + 1
            CALLBACK_STATUS['last_check'] = datetime.datetime.now()
            raise ValueError(f"VerifyURL failed with code {ret}")
        
        # Success
        CALLBACK_STATUS['last_success'] = datetime.datetime.now()
        CALLBACK_STATUS['last_error'] = None
        CALLBACK_STATUS['error_count'] = 0
        CALLBACK_STATUS['last_check'] = datetime.datetime.now()
        return sEchoStr
    except Exception as e:
        CALLBACK_STATUS['last_error'] = f"VerifyURL exception: {str(e)}"
        CALLBACK_STATUS['error_count'] = CALLBACK_STATUS.get('error_count', 0) + 1
        CALLBACK_STATUS['last_check'] = datetime.datetime.now()
        raise


def parse_xml_message(xml_content):
    """解析XML格式的消息"""
    try:
        return xmltodict.parse(xml_content)['xml']
    except Exception as e:
        logger.error("Parse XML failed: %s", str(e), exc_info=True)
        raise Exception(f"Parse XML failed: {str(e)}")


def sync_customer_service_messages(access_token, token, open_kfid, cursor=None, limit=1000, db=None):
    """
    同步微信客服消息 - 支持增量拉取
    注意：此函数不再自动更新数据库cursor，而是返回数据由调用者决定何时更新
    """
    import requests
    url = f"{WECOM_API_BASE_URL}/cgi-bin/kf/sync_msg?access_token={access_token}"

    payload = {
        "open_kfid": open_kfid,
        "limit": limit
    }

    if token:
        payload["token"] = token
    if cursor:
        payload["cursor"] = cursor

    logger.debug("Syncing messages with payload: %s", json.dumps(payload, ensure_ascii=False, indent=2))
    
    # 构造请求头
    headers = {}
    if WECOM_API_PROXY_TOKEN:
        headers['X-Antigrv-Token'] = WECOM_API_PROXY_TOKEN

    logger.info(f"🚀 Sending Sync Request to: {url} | Headers: {headers}")  # Debug Log

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        result = response.json()

        # logger.info("Sync messages result: %s", json.dumps(result, ensure_ascii=False, indent=2))

        if result.get('errcode') == 0:
            msg_list = result.get('msg_list', [])
            logger.info(f"✅ Synced {len(msg_list)} messages (has_more={result.get('has_more')})")
            return result
        else:
            raise Exception(f"Sync messages failed: {result.get('errmsg')}")
    except Exception as e:
        logger.error("Sync messages error: %s", str(e), exc_info=True)
        raise Exception(f"Sync messages error: {str(e)}")


def handle_customer_service_event(event_data, db: Session):
    """
    处理微信客服事件 - 支持增量拉取
    """
    try:
        event_type = event_data.get('Event', '')
        token = event_data.get('Token', '')
        open_kfid = event_data.get('OpenKfId', '')

        logger.debug("Handling customer service event: type=%s, token=%s, open_kfid=%s",
                    event_type, token, open_kfid)

        if event_type == 'kf_msg_or_event':
            access_token = get_cached_access_token()
            # logger.info("Got access_token for message sync")

            # 获取当前cursor
            current_cursor = get_cursor_for_kfid(open_kfid, db)
            logger.debug(f"Current cursor for {open_kfid}: {current_cursor}")

            # 同步消息
            messages_data = sync_customer_service_messages(
                access_token=access_token,
                token=token,
                open_kfid=open_kfid,
                cursor=current_cursor,
                db=db
            )

            # 处理获取到的消息
            processed_result = process_messages_async(messages_data, db)
            processed_count = processed_result.get('processed_count', 0)
            
            # 🔥 关键修改：只有在成功处理消息后，才更新 cursor
            if 'next_cursor' in messages_data and messages_data['next_cursor']:
                update_success = update_cursor_for_kfid(
                    open_kfid, 
                    messages_data['next_cursor'], 
                    db
                )
                if update_success:
                    logger.info(f"✅ Cursor updated successfully for {open_kfid}")
                else:
                    logger.error(f"❌ Failed to update cursor for {open_kfid}")

            # 如果还有更多消息，继续同步（递归调用）
            if messages_data.get('has_more') == 1:
                logger.info(f"More messages available for {open_kfid}, continuing sync...")
                return handle_customer_service_event(event_data, db)

            # 🔥 更新回调状态 (Sync Success)
            CALLBACK_STATUS['last_success'] = datetime.datetime.now()
            CALLBACK_STATUS['last_error'] = None
            CALLBACK_STATUS['error_count'] = 0
            CALLBACK_STATUS['last_check'] = datetime.datetime.now()

            return processed_result

        return {"status": "event_handled", "event_type": event_type}

    except Exception as e:
        logger.error("Handle customer service event failed: %s", str(e), exc_info=True)
        return {"error": str(e), "status": "failed"}


def process_messages_async(messages_data, db: Session):
    """
    处理拉取到的消息 - 保存到数据库
    """
    try:
        msg_list = messages_data.get('msg_list', [])
        logger.info(f"Processing {len(msg_list)} messages")

        results = []
        processed_count = 0

        for msg in msg_list:
            msg_type = msg.get('msgtype', '')
            msg_id = msg.get('msgid')
            
            # 检查是否已在黑名单（已删除）中
            if db.query(DeletedMessage).filter(DeletedMessage.msgid == msg_id).first():
                logger.info(f"⏭️ Skipping deleted message: {msg_id}")
                processed_count += 1 # 视为已处理，这样可以推进 cursor
                continue

            # 检查是否已存在 (避免重复插入报错)
            if db.query(Message).filter(Message.msgid == msg_id).first():
                logger.info(f"⏭️ Skipping existing message: {msg_id}")
                processed_count += 1
                continue

            logger.debug(f"Processing message type: {msg_type}")
            logger.debug(f"Raw message  %s", json.dumps(msg, ensure_ascii=False, indent=2))

            # 创建消息记录
            # 修正时间：WeCom返回的是UTC时间戳，我们需要转换为UTC+8显示
            tz_sha = datetime.timezone(datetime.timedelta(hours=8))
            

            # 提取消息内容摘要
            content_summary = None
            if msg_type == 'text':
                content_summary = msg.get('text', {}).get('content')
            elif msg_type == 'image':
                content_summary = '[图片] ' + (msg.get('image', {}).get('filename') or 'image')
            elif msg_type == 'voice':
                content_summary = '[语音] ' + (msg.get('voice', {}).get('filename') or 'voice message')
            elif msg_type == 'video':
                content_summary = '[视频] ' + (msg.get('video', {}).get('filename') or 'video message')
            elif msg_type == 'file':
                content_summary = '[文件] ' + (msg.get('file', {}).get('filename') or 'file')
            elif msg_type == 'location':
                loc = msg.get('location', {})
                content_summary = f"[位置] {loc.get('address')} ({loc.get('name')})"
            elif msg_type == 'link':
                link = msg.get('link', {})
                content_summary = f"[链接] {link.get('title')} - {link.get('desc')}"
            elif msg_type == 'business_card':
                card = msg.get('business_card', {})
                content_summary = f"[名片] UserID: {card.get('userid')}"
            elif msg_type == 'miniprogram':
                mini = msg.get('miniprogram', {})
                content_summary = f"[小程序] {mini.get('title')}"
            elif msg_type == 'merged_msg':
                merged = msg.get('merged_msg', {})
                content_summary = f"[聊天记录] {merged.get('title')}"
            
            message = Message(
                msgid=msg_id,
                open_kfid=msg.get('open_kfid'),
                external_userid=msg.get('external_userid'),
                servicer_userid=msg.get('servicer_userid', ''),
                msgtype=msg_type,
                send_time=datetime.datetime.fromtimestamp(msg.get('send_time', 0), tz_sha).replace(tzinfo=None), # 存为naive time但其实是UTC+8
                origin=msg.get('origin', 0),
                content=content_summary,  # 存储摘要内容
                media_id=get_media_id_from_message(msg),
                extra_data=json.dumps(msg),  # 保存原始数据
                download_status='success' if msg_type in ['text', 'location', 'link', 'business_card', 'miniprogram', 'merged_msg'] else 'pending'
            )

            # 保存消息到数据库
            db.add(message)
            processed_count += 1
            results.append({
                'msgid': message.msgid,
                'status': 'saved'
            })

        # 提交数据库事务
        db.commit()
        logger.info(f"Successfully saved {processed_count} messages to database")

        # 为所有支持的消息类型启动异步下载
        SUPPORTED_MEDIA_TYPES = ['image', 'voice', 'video', 'file']

        for msg in msg_list:
            msg_type = msg.get('msgtype', '')
            if msg_type in SUPPORTED_MEDIA_TYPES:
                media_id = get_media_id_from_message(msg)
                if media_id:
                    file_info = get_file_info_from_message(msg)
                    msg_copy = {
                        'media_id': media_id,
                        'msgtype': msg_type,
                        'msgid': msg.get('msgid'),
                        'open_kfid': msg.get('open_kfid'),
                        'file_info': file_info
                    }
                    # 启动异步线程下载媒体
                    thread = threading.Thread(
                        target=async_download_media,
                        args=(msg_copy,),
                        daemon=True
                    )
                    thread.start()
                    logger.debug(f"Started async media download for {msg_type} message {msg.get('msgid')}")
                else:
                    logger.warning(f"No media_id found for {msg_type} message {msg.get('msgid')}")

        return {
            'processed_count': processed_count,
            'results': results,
            'next_cursor': messages_data.get('next_cursor'),
            'has_more': messages_data.get('has_more', 0)
        }

    except Exception as e:
        db.rollback()
        logger.error("Process messages failed: %s", str(e), exc_info=True)
        raise Exception(f"Process messages failed: {str(e)}")


def async_download_media(msg_data):
    """异步下载媒体文件 - 独立的数据库会话"""
    db = None
    try:
        media_id = msg_data['media_id']
        msgtype = msg_data['msgtype']
        msgid = msg_data['msgid']
        file_info = msg_data.get('file_info', {})

        logger.debug(f"Async downloading media for message {msgid}, media_id: {media_id}, type: {msgtype}")

        # 获取独立的数据库会话
        db = next(get_db_for_async())

        # 下载媒体文件
        media_content, filename_from_header = download_media_file(media_id, msgtype)

        if media_content:
            # 构造文件名
            filename = file_info.get('filename', '')
            
            # --- 关键修复：如果从 file_info 拿到的名字看起来像是自动生成的，尝试用 header 里的真实名字覆盖 ---
            # 自动生成的特征：空，或者 startswith 'file_'/'image_'
            is_generic_name = not filename or filename.startswith(('file_', 'image_', 'voice_', 'video_'))
            if is_generic_name and filename_from_header:
                 logger.info(f"🔄 Replacing generic filename '{filename}' with header filename '{filename_from_header}'")
                 filename = filename_from_header
            
            extension = file_info.get('extension')
            # 如果没有扩展名，尝试从 filename 提取
            if not extension and filename and '.' in filename:
                extension = filename.rsplit('.', 1)[-1]
            if not extension and filename_from_header and '.' in filename_from_header:
                 extension = filename_from_header.rsplit('.', 1)[-1]
            
            # 确保唯一性和目录结构
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            import uuid
            random_str = str(uuid.uuid4())[:8]
            
            # 4. 改进的文件命名策略 (优先保留原文件名，但防止冲突)
            # 如果有原始文件名 (且不是默认生成的 text_... / image_...)
            is_default_name = filename.startswith(f"{msgtype}_") and 10 < len(filename) < 40
            
            # 安全文件名处理
            final_filename = ""
            if filename and not is_default_name:
                # 尝试保留原始文件名: timestamp_originalName
                # 允许中文 (\u4e00-\u9fff)
                safe_name = "".join([c for c in filename if c.isalpha() or c.isdigit() or c in (' ', '.', '-', '_') or '\u4e00' <= c <= '\u9fff']).strip()
                if len(safe_name) > 50:
                    safe_name = safe_name[:50]
                if not safe_name: safe_name = "file"
                
                # 去除可能的重复后缀 (如果 safe_name 已经有后缀)
                base_name = safe_name
                if extension and safe_name.lower().endswith(f'.{extension}'):
                     base_name = safe_name.rsplit('.', 1)[0]
                
                final_filename = f"{timestamp}_{base_name}"
            else:
                # 使用默认命名
                final_filename = f"{timestamp}_{random_str}"

            # 统一添加后缀
            if extension and not final_filename.endswith(f'.{extension}'):
                final_filename = f"{final_filename}.{extension}"
            
            filename = final_filename # 赋值回 filename 变量以供后续使用
            
            # 🔥 安全特性：强制重命名危险文件
            DANGEROUS_EXTENSIONS = {'exe', 'bat', 'sh', 'cmd', 'ps1', 'vbs', 'scr', 'com', 'js', 'dll', 'jar', 'iso', 'asp', 'aspx', 'php', 'jsp'}
            
            # 检查生成的本地文件名
            cur_ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ""
            if cur_ext in DANGEROUS_EXTENSIONS:
                logger.warning(f"⚠️ Detected dangerous file extension form generated name: {filename}. Appending .dangerous")
                filename = f"{filename}.dangerous"
                
            # 检查原始文件名 (如果存在，也需要重命名，防止下载时恢复为危险后缀)
            if filename_from_header:
                 h_ext = filename_from_header.rsplit('.', 1)[-1].lower() if '.' in filename_from_header else ""
                 if h_ext in DANGEROUS_EXTENSIONS:
                      logger.warning(f"⚠️ Detected dangerous file extension from header: {filename_from_header}. Appending .dangerous")
                      filename_from_header = f"{filename_from_header}.dangerous"
            
            # 构建存储Key (e.g. image/2023...jpg)
            # 使用 msgtype 作为子目录
            storage_key = f"{msgtype}/{filename}"
                
            # 保存媒体文件 (到S3或本地)
            # 保存媒体文件 (到S3或本地)
            saved_path = storage.save_file(media_content, storage_key)

            if saved_path:
                # 更新数据库记录
                message = db.query(Message).filter(Message.msgid == msgid).first()
                if message:
                    if message.download_count is None:
                        message.download_count = 0
                    message.download_count += 1
                    
                    message.last_download_time = datetime.datetime.utcnow()
                    
                    # 更新文件哈希
                    import hashlib
                    message.file_hash = hashlib.md5(media_content).hexdigest()[:16]
                    
                    # 🔥 关键修复：更新文件大小和文件名
                    message.file_size = len(media_content)
                    # 如果原始文件名为空，或者使用了从Header获取的更好文件名，则更新
                    if not message.original_filename or (filename_from_header and message.original_filename != filename_from_header):
                        # 优先使用 Header 中的文件名 (去除可能的时间戳前缀? 不，这里 header 也就是原始名)
                        # 如果没有 header filename，就用 final_filename (虽带时间戳但总比 None 好)
                        message.original_filename = filename_from_header if filename_from_header else filename

                    # 更新 download_status
                    message.download_status = 'success'
                    
                    # 更新文件路径信息
                    message.media_path = saved_path
                    # 构造访问URL (假设存储在 MEDIA_STORAGE_PATH 下，通过 /media 访问)
                    # storage_key 类似于 "video/20260210_123456.mp4"
                    message.media_url = f"/media/{storage_key}"

                    db.commit()
                    logger.info(f"✅ Media downloaded and saved for msg {msgid}: {saved_path}")
                else:
                    logger.warning(f"⚠️ Message {msgid} found but DB record missing during update.")
            else:
                 logger.error(f"❌ Storage failed to save file for msg {msgid}")

        else:
            # download_media_file 返回 None
            logger.error(f"❌ Failed to download media content for msg {msgid}, media_id: {media_id}. content is None.")
            # 可选: 更新数据库状态为 failed
            message = db.query(Message).filter(Message.msgid == msgid).first()
            if message:
                message.download_status = 'failed'
                db.commit()

    except Exception as e:
        logger.error(f"❌ Async media download thread failed for msg {msg_data.get('msgid')}: {e}", exc_info=True)
        # 尝试记录失败状态
        try:
             if db:
                 message = db.query(Message).filter(Message.msgid == msg_data.get('msgid')).first()
                 if message:
                     message.download_status = 'failed'
                     message.download_error = str(e)
                     db.commit()
        except:
             pass
    finally:
        if db:
            db.close()


def get_media_id_from_message(msg):
    """从消息中提取media_id"""
    msgtype = msg.get('msgtype', '')
    logger.debug(f"Extracting media_id for msgtype: {msgtype}")
    media_id = None
    if msgtype == 'image':
        media_id = msg.get('image', {}).get('media_id')
        logger.debug(f"Image message media_id: {media_id}")
    elif msgtype == 'voice':
        media_id = msg.get('voice', {}).get('media_id')
        logger.debug(f"Voice message media_id: {media_id}")
    elif msgtype == 'video':
        media_id = msg.get('video', {}).get('media_id')
        logger.debug(f"Video message media_id: {media_id}")
    elif msgtype == 'file':
        # 文件消息，media_id 在 file 字段中
        media_id = msg.get('file', {}).get('media_id')
        logger.debug(f"File message media_id: {media_id}")
    return media_id


def get_file_info_from_message(msg):
    """从消息中提取文件信息"""
    msgtype = msg.get('msgtype', '')
    logger.debug(f"Extracting file info for msgtype: {msgtype}")

    # 基础文件信息
    file_info = {
        'filename': f"download_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
        'file_type': msgtype,
        'extension': '',
        'size': 0,
        'mime_type': ''
    }

    if msgtype == 'file':
        file_data = msg.get('file', {})
        logger.debug(f"File data received: %s", json.dumps(file_data, ensure_ascii=False, indent=2))

        # 1. 从文件数据中提取文件名
        filename = file_data.get('filename', '')
        if not filename:
            filename = file_data.get('file_name', '')
        if not filename:
            filename = file_data.get('title', '')

        file_info['filename'] = filename if filename else f"file_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # 2. 从文件名提取扩展名
        if '.' in file_info['filename']:
            file_info['extension'] = file_info['filename'].rsplit('.', 1)[-1].lower()

        # 3. 文件大小
        file_size = file_data.get('file_size')
        if file_size:
            try:
                file_info['size'] = int(file_size)
            except (TypeError, ValueError):
                pass

        # 4. 文件类型/MIME类型
        file_type = file_data.get('file_type', '').lower()
        file_info['file_type'] = file_type

        if file_type:
            # 常见文件类型映射
            mime_map = {
                'txt': 'text/plain',
                'pdf': 'application/pdf',
                'doc': 'application/msword',
                'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'xls': 'application/vnd.ms-excel',
                'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'ppt': 'application/vnd.ms-powerpoint',
                'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                'jpg': 'image/jpeg',
                'jpeg': 'image/jpeg',
                'png': 'image/png',
                'gif': 'image/gif',
                'bmp': 'image/bmp',
                'mp3': 'audio/mpeg',
                'amr': 'audio/amr',
                'wav': 'audio/wav',
                'mp4': 'video/mp4',
                'avi': 'video/x-msvideo',
                'mov': 'video/quicktime',
                'zip': 'application/zip',
                'rar': 'application/vnd.rar',
                '7z': 'application/x-7z-compressed'
            }

            if file_type in mime_map:
                file_info['mime_type'] = mime_map[file_type]
            else:
                # 从扩展名推断
                ext = file_info['extension']
                if ext and '.' + ext in mimetypes.types_map:
                    file_info['mime_type'] = mimetypes.types_map['.' + ext]
                else:
                    file_info['mime_type'] = f'application/{file_type}'

    elif msgtype == 'image':
        filename = msg.get('image', {}).get('filename', '')
        file_info['filename'] = filename if filename else f"image_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        file_info['file_type'] = 'image'
        file_info['extension'] = 'jpg' if not filename or '.' not in filename else filename.rsplit('.', 1)[-1].lower()
        file_info['mime_type'] = 'image/jpeg' if file_info['extension'] == 'jpg' else f'image/{file_info["extension"]}'

    elif msgtype == 'voice':
        filename = msg.get('voice', {}).get('filename', '')
        file_info['filename'] = filename if filename else f"voice_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        file_info['file_type'] = 'voice'
        file_info['extension'] = 'amr' if not filename or '.' not in filename else filename.rsplit('.', 1)[-1].lower()
        file_info['mime_type'] = 'audio/amr' if file_info['extension'] == 'amr' else f'audio/{file_info["extension"]}'

    elif msgtype == 'video':
        filename = msg.get('video', {}).get('filename', '')
        file_info['filename'] = filename if filename else f"video_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        file_info['file_type'] = 'video'
        file_info['extension'] = 'mp4' if not filename or '.' not in filename else filename.rsplit('.', 1)[-1].lower()
        file_info['mime_type'] = 'video/mp4' if file_info['extension'] == 'mp4' else f'video/{file_info["extension"]}'

    # 5. 确保有扩展名
    if not file_info['extension']:
        # 从MIME类型推断
        mime_type = file_info['mime_type']
        if mime_type:
            ext = mimetypes.guess_extension(mime_type)
            if ext:
                file_info['extension'] = ext.lstrip('.')

    # 6. 确保有文件名
    if '.' not in file_info['filename']:
        file_info['filename'] = f"{file_info['filename']}.{file_info['extension']}"

    logger.debug(f"Final file info: %s", json.dumps(file_info, ensure_ascii=False, indent=2))
    return file_info