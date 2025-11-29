"""
Telegram Bot Integration for FIMonacci
Handles sending file integrity alerts to Telegram
"""
import os
import logging
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Check if telegram library is available
TELEGRAM_AVAILABLE = False
try:
    from telegram import Bot
    from telegram.ext import ContextTypes
    TELEGRAM_AVAILABLE = True
except ImportError:
    logger.warning("python-telegram-bot not installed. Telegram alerts disabled.")

# Global bot instance
_bot_instance: Optional[Bot] = None
_bot_token: Optional[str] = None
_authorized_chats: dict = {}  # {chat_id: {username, timestamp}}


def init_telegram_bot(token: Optional[str] = None):
    """
    Initialize Telegram bot
    
    Args:
        token: Telegram bot token (if None, reads from TELEGRAM_BOT_TOKEN env var)
    """
    global _bot_instance, _bot_token
    
    if not TELEGRAM_AVAILABLE:
        logger.warning("python-telegram-bot not installed. Telegram alerts disabled.")
        return False
    
    _bot_token = token or os.environ.get("TELEGRAM_BOT_TOKEN")
    
    if not _bot_token:
        logger.warning("TELEGRAM_BOT_TOKEN not set. Telegram alerts disabled.")
        return False
    
    try:
        _bot_instance = Bot(token=_bot_token)
        logger.info("Telegram bot initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize Telegram bot: {e}")
        return False


def is_authorized(chat_id: int) -> bool:
    """Check if chat_id is authorized"""
    return chat_id in _authorized_chats


def authorize_chat(chat_id: int, username: str = None, admin_username: str = None, admin_password: str = None):
    """
    Authorize a chat to receive alerts
    
    Args:
        chat_id: Telegram chat ID
        username: Telegram username (optional)
        admin_username: Admin username for verification
        admin_password: Admin password for verification
    """
    global _authorized_chats
    
    try:
        # Verify admin credentials if provided
        if admin_username and admin_password:
            from .database import User
            from werkzeug.security import check_password_hash
            from app import create_app
            
            app = create_app()
            with app.app_context():
                user = User.query.filter_by(username=admin_username).first()
                if not user or not user.is_admin or not check_password_hash(user.password_hash, admin_password):
                    return False, "Invalid admin credentials"
        
        # Authorize chat
        _authorized_chats[chat_id] = {
            "username": username,
            "timestamp": datetime.utcnow()
        }
        
        logger.info(f"Chat {chat_id} authorized as admin {admin_username}")
        return True, "Authorization successful"
    except Exception as e:
        logger.error(f"Error authorizing chat {chat_id}: {e}")
        return False, f"Error: {str(e)}"


def deauthorize_chat(chat_id: int):
    """Deauthorize a chat"""
    global _authorized_chats
    if chat_id in _authorized_chats:
        del _authorized_chats[chat_id]
        logger.info(f"Chat {chat_id} deauthorized")


def get_authorized_chats_count() -> int:
    """Get number of authorized chats"""
    return len(_authorized_chats)


def send_alert(filepath: str, alert_type: str, client_id: Optional[int] = None, 
               initial_hash: Optional[str] = None, current_hash: Optional[str] = None,
               client_hostname: Optional[str] = None):
    """
    Send file integrity alert to all authorized Telegram chats
    
    Args:
        filepath: Path to the file
        alert_type: Type of alert (created, modified, deleted, hash_mismatch)
        client_id: Client ID (optional)
        initial_hash: Previous hash (optional)
        current_hash: Current hash (optional)
        client_hostname: Client hostname (optional)
    """
    global _bot_instance
    
    if not _bot_instance:
        logger.debug("Bot instance not initialized, skipping Telegram alert")
        return
    
    if not _authorized_chats:
        logger.debug("No authorized chats, skipping Telegram alert")
        return
    
    logger.info(f"📤 Sending Telegram alert: {alert_type} for {filepath} to {len(_authorized_chats)} chat(s)")
    
    # Format alert message with beautiful design
    filename = filepath.split('/')[-1] if '/' in filepath else filepath.split('\\')[-1]
    directory = '/'.join(filepath.split('/')[:-1]) if '/' in filepath else '\\'.join(filepath.split('\\')[:-1])
    
    # Emoji and color based on alert type
    emoji_map = {
        "created": "🆕",
        "modified": "✏️",
        "deleted": "🗑️",
        "hash_mismatch": "⚠️",
        "missing": "❌"
    }
    emoji = emoji_map.get(alert_type, "📢")
    
    # Beautiful header with separator
    message = f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    message += f"{emoji} *{alert_type.upper()} ALERT*\n"
    message += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    
    # File information
    message += f"📁 *File Name:*\n`{filename}`\n\n"
    message += f"📂 *Full Path:*\n`{filepath}`\n\n"
    
    if directory:
        message += f"📂 *Directory:*\n`{directory}`\n\n"
    
    # Client information
    if client_hostname:
        message += f"💻 *Client Hostname:*\n`{client_hostname}`\n\n"
    
    if client_id:
        message += f"🆔 *Client ID:* `{client_id}`\n\n"
    
    # Hash information - FULL HASHES
    message += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    message += f"🔐 *HASH INFORMATION*\n"
    message += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    
    if alert_type == "deleted":
        if initial_hash and initial_hash != "unknown":
            message += f"🗑️ *Deleted File Hash (MD5):*\n`{initial_hash}`\n\n"
        else:
            message += f"🗑️ *Hash:* `unknown`\n\n"
    elif alert_type == "created":
        if current_hash:
            message += f"🆕 *New File Hash (MD5):*\n`{current_hash}`\n\n"
    elif alert_type == "modified" or alert_type == "hash_mismatch":
        if initial_hash and initial_hash != "unknown":
            message += f"📥 *Previous Hash (MD5):*\n`{initial_hash}`\n\n"
        if current_hash:
            message += f"📤 *Current Hash (MD5):*\n`{current_hash}`\n\n"
        if initial_hash and current_hash and initial_hash != "unknown":
            message += f"🔄 *Hash Changed:* ✅ Yes\n\n"
    
    # File size if available
    try:
        from pathlib import Path
        if Path(filepath).exists():
            file_size = Path(filepath).stat().st_size
            size_kb = file_size / 1024
            size_mb = size_kb / 1024
            if size_mb >= 1:
                message += f"📊 *File Size:* {size_mb:.2f} MB\n\n"
            else:
                message += f"📊 *File Size:* {size_kb:.2f} KB\n\n"
    except:
        pass
    
    # Footer
    message += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    message += f"⚡ *FIMonacci File Integrity Monitor*"
    
    # Send to all authorized chats
    # Note: This function is called from Flask (sync) context
    # But bot instance requires async, so we use asyncio
    import asyncio
    
    async def _send_to_all():
        """Async function to send message to all chats"""
        sent_count = 0
        for chat_id in _authorized_chats.keys():
            try:
                await _bot_instance.send_message(
                    chat_id=chat_id,
                    text=message,
                    parse_mode="Markdown"
                )
                sent_count += 1
                logger.info(f"✅ Telegram alert sent to chat {chat_id}")
            except Exception as e:
                logger.error(f"❌ Failed to send Telegram alert to chat {chat_id}: {e}")
        
        if sent_count > 0:
            logger.info(f"📤 Sent alert to {sent_count}/{len(_authorized_chats)} chat(s)")
    
    # Try to send message - handle different async contexts
    try:
        # Try to get existing event loop
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Loop is running (probably in bot polling script)
                # Create task in running loop
                asyncio.create_task(_send_to_all())
                logger.debug(f"📤 Telegram alert queued for {len(_authorized_chats)} chat(s)")
            else:
                # Loop exists but not running
                loop.run_until_complete(_send_to_all())
        except RuntimeError:
            # No event loop exists, create new one
            asyncio.run(_send_to_all())
    except Exception as e:
        logger.error(f"❌ Error sending Telegram alerts: {e}")
        import traceback
        logger.debug(traceback.format_exc())


# Command handlers for bot
async def start_command(update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    chat_id = update.effective_chat.id
    username = update.effective_user.username
    
    if is_authorized(chat_id):
        await update.message.reply_text(
            f"✅ *Welcome back, {username or 'Admin'}!*\n\n"
            "You are already authorized. You will receive file integrity alerts.\n\n"
            "Commands:\n"
            "/status - Check bot status\n"
            "/stop - Stop receiving alerts",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text(
            f"👋 *Welcome to FIMonacci Bot!*\n\n"
            "This bot sends file integrity monitoring alerts.\n\n"
            "To receive alerts, you need to authorize:\n"
            "/auth <admin_username> <admin_password>\n\n"
            "Example: /auth admin mypassword",
            parse_mode="Markdown"
        )


async def auth_command(update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /auth command"""
    chat_id = update.effective_chat.id
    username = update.effective_user.username
    
    if is_authorized(chat_id):
        await update.message.reply_text("✅ You are already authorized!")
        return
    
    if not context.args or len(context.args) < 2:
        await update.message.reply_text(
            "❌ Usage: /auth <admin_username> <admin_password>\n\n"
            "Example: /auth admin mypassword"
        )
        return
    
    admin_username = context.args[0]
    admin_password = context.args[1]
    
    success, message = authorize_chat(
        chat_id=chat_id,
        username=username,
        admin_username=admin_username,
        admin_password=admin_password
    )
    
    if success:
        await update.message.reply_text(
            f"✅ *Authorization successful!*\n\n"
            f"You will now receive file integrity alerts.\n\n"
            f"Chat ID: `{chat_id}`",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text(f"❌ {message}")


async def status_command(update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /status command"""
    chat_id = update.effective_chat.id
    username = update.effective_user.username
    
    is_auth = is_authorized(chat_id)
    total_chats = get_authorized_chats_count()
    
    status_text = f"📊 *Bot Status*\n\n"
    status_text += f"👤 *Your Status:* {'✅ Authorized' if is_auth else '❌ Not Authorized'}\n"
    status_text += f"🆔 *Chat ID:* `{chat_id}`\n"
    status_text += f"👥 *Total Authorized Chats:* {total_chats}\n"
    status_text += f"🤖 *Bot Status:* {'✅ Running' if _bot_instance else '❌ Not Initialized'}\n"
    
    if not is_auth:
        status_text += f"\n💡 To authorize: /auth <username> <password>"
    
    await update.message.reply_text(status_text, parse_mode="Markdown")


async def stop_command(update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /stop command"""
    chat_id = update.effective_chat.id
    
    if is_authorized(chat_id):
        deauthorize_chat(chat_id)
        await update.message.reply_text(
            "🛑 *Alerts stopped*\n\n"
            "You will no longer receive file integrity alerts.\n"
            "To re-enable: /auth <username> <password>",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text("ℹ️ You are not authorized.")

