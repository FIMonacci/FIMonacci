#!/usr/bin/env python3
"""
Telegram Bot for FIMonacci
Standalone bot that connects to FIMonacci Flask app
"""
import os
import sys
import asyncio
import logging
from pathlib import Path

# Add parent directory (main project) to path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

try:
    from telegram import Update
    from telegram.ext import Application, CommandHandler, ContextTypes
    from app import create_app
    from app.telegram_bot import (
        start_command, auth_command, status_command, stop_command,
        init_telegram_bot, TELEGRAM_AVAILABLE
    )
except ImportError as e:
    logger.error(f"Import error: {e}")
    logger.error("Make sure:")
    logger.error("1. python-telegram-bot is installed: pip install python-telegram-bot[job-queue]")
    logger.error("2. You're running from the project root or telegram_bot directory")
    sys.exit(1)


def setup_handlers(application: Application):
    """Setup bot command handlers"""
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("auth", auth_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("stop", stop_command))


async def post_init(application: Application):
    """Initialize Flask app context after bot is created"""
    # Create Flask app for database access
    app = create_app()
    application.bot_data['flask_app'] = app
    
    # Start background task to monitor database for new alerts
    # Check if job_queue is available
    if application.job_queue:
        application.job_queue.run_repeating(
            check_and_send_alerts,
            interval=5.0,  # Check every 5 seconds
            first=5.0,     # Start after 5 seconds
            name="alert_monitor"
        )
        logger.info("Flask app initialized for Telegram bot")
        logger.info("Background alert monitor started (checking every 5 seconds)")
    else:
        # Fallback: use asyncio.create_task if job_queue not available
        logger.warning("JobQueue not available, using asyncio task instead")
        logger.info("Flask app initialized for Telegram bot")
        
        async def _start_alert_monitor():
            """Start alert monitoring as background task"""
            await asyncio.sleep(5.0)  # Wait 5 seconds before first check
            while True:
                try:
                    # Pass application instance to check_and_send_alerts
                    await check_and_send_alerts(application)
                except Exception as e:
                    logger.error(f"Error in alert monitor: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                await asyncio.sleep(5.0)  # Check every 5 seconds
        
        # Get the event loop and create task
        loop = asyncio.get_event_loop()
        loop.create_task(_start_alert_monitor())
        logger.info("Background alert monitor started (using asyncio task)")


async def check_and_send_alerts(context_or_app=None):
    """
    Background task to check database for new alerts and send to Telegram
    Runs every 5 seconds
    
    Args:
        context_or_app: Either ContextTypes (from job_queue) or Application instance
    """
    try:
        # Handle both ContextTypes (from job_queue) and Application (from asyncio task)
        if context_or_app is None:
            return
        
        # Check if it's a ContextTypes or Application
        if hasattr(context_or_app, 'bot_data'):
            # It's an Application instance
            app = context_or_app.bot_data.get('flask_app')
            bot_data = context_or_app.bot_data
        elif hasattr(context_or_app, 'application'):
            # It's a ContextTypes from job_queue
            app = context_or_app.application.bot_data.get('flask_app')
            bot_data = context_or_app.application.bot_data
        else:
            # Try direct access (ContextTypes)
            app = context_or_app.bot_data.get('flask_app')
            bot_data = context_or_app.bot_data
        
        if not app:
            return
        
        with app.app_context():
            from app.database import FileIntegrity, Client
            from app.telegram_bot import get_authorized_chats_count, _authorized_chats, _bot_instance
            
            # Check if bot is authorized
            if get_authorized_chats_count() == 0:
                return  # No authorized chats, skip
            
            # Get last checked timestamp from bot_data
            last_check = bot_data.get('last_alert_check')
            if last_check:
                # Get alerts newer than last check
                alerts = FileIntegrity.query.filter(
                    FileIntegrity.timestamp > last_check,
                    FileIntegrity.alert_type != "baseline"  # Skip baseline alerts
                ).order_by(FileIntegrity.timestamp.asc()).all()
            else:
                # First run - get alerts from last 1 minute
                from datetime import datetime, timedelta
                one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
                alerts = FileIntegrity.query.filter(
                    FileIntegrity.timestamp > one_minute_ago,
                    FileIntegrity.alert_type != "baseline"
                ).order_by(FileIntegrity.timestamp.asc()).all()
            
            # Send each alert to Telegram
            from app.telegram_bot import _bot_instance, _authorized_chats
            
            for alert in alerts:
                # Get client hostname if available
                client_hostname = None
                if alert.client_id:
                    client = Client.query.get(alert.client_id)
                    if client:
                        client_hostname = client.hostname
                
                # Format alert message with beautiful design
                filename = alert.path.split('/')[-1] if '/' in alert.path else alert.path.split('\\')[-1]
                directory = '/'.join(alert.path.split('/')[:-1]) if '/' in alert.path else '\\'.join(alert.path.split('\\')[:-1])
                
                # Emoji and color based on alert type
                emoji_map = {
                    "created": "🆕",
                    "modified": "✏️",
                    "deleted": "🗑️",
                    "hash_mismatch": "⚠️",
                    "missing": "❌"
                }
                emoji = emoji_map.get(alert.alert_type, "📢")
                
                # Beautiful header with separator
                message = f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                message += f"{emoji} *{alert.alert_type.upper()} ALERT*\n"
                message += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                
                # File information
                message += f"📁 *File Name:*\n`{filename}`\n\n"
                message += f"📂 *Full Path:*\n`{alert.path}`\n\n"
                
                if directory:
                    message += f"📂 *Directory:*\n`{directory}`\n\n"
                
                # Client information
                if client_hostname:
                    message += f"💻 *Client Hostname:*\n`{client_hostname}`\n\n"
                
                if alert.client_id:
                    message += f"🆔 *Client ID:* `{alert.client_id}`\n\n"
                
                # Hash information - FULL HASHES
                message += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                message += f"🔐 *HASH INFORMATION*\n"
                message += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                
                if alert.alert_type == "deleted":
                    if alert.initial_hash and alert.initial_hash != "unknown":
                        message += f"🗑️ *Deleted File Hash (MD5):*\n`{alert.initial_hash}`\n\n"
                    else:
                        message += f"🗑️ *Hash:* `unknown`\n\n"
                elif alert.alert_type == "created":
                    if alert.current_hash:
                        message += f"🆕 *New File Hash (MD5):*\n`{alert.current_hash}`\n\n"
                elif alert.alert_type == "modified" or alert.alert_type == "hash_mismatch":
                    if alert.initial_hash and alert.initial_hash != "unknown":
                        message += f"📥 *Previous Hash (MD5):*\n`{alert.initial_hash}`\n\n"
                    if alert.current_hash:
                        message += f"📤 *Current Hash (MD5):*\n`{alert.current_hash}`\n\n"
                    if alert.initial_hash and alert.current_hash and alert.initial_hash != "unknown":
                        message += f"🔄 *Hash Changed:* ✅ Yes\n\n"
                
                # File size if available
                try:
                    from pathlib import Path
                    if Path(alert.path).exists():
                        file_size = Path(alert.path).stat().st_size
                        size_kb = file_size / 1024
                        size_mb = size_kb / 1024
                        if size_mb >= 1:
                            message += f"📊 *File Size:* {size_mb:.2f} MB\n\n"
                        else:
                            message += f"📊 *File Size:* {size_kb:.2f} KB\n\n"
                except:
                    pass
                
                # Alert ID and timestamp from database
                message += f"🆔 *Alert ID:* `{alert.id}`\n\n"
                
                # Footer
                message += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                message += f"⚡ *FIMonacci File Integrity Monitor*"
                
                # Send to all authorized chats (async context)
                for chat_id in _authorized_chats.keys():
                    try:
                        await _bot_instance.send_message(
                            chat_id=chat_id,
                            text=message,
                            parse_mode="Markdown"
                        )
                        logger.info(f"✅ Telegram alert sent to chat {chat_id}: {alert.alert_type} - {filename}")
                    except Exception as e:
                        logger.error(f"❌ Failed to send Telegram alert to chat {chat_id}: {e}")
                
                # Update last check timestamp
                bot_data['last_alert_check'] = alert.timestamp
            
            # Update last check time even if no alerts
            if alerts:
                bot_data['last_alert_check'] = alerts[-1].timestamp
            else:
                from datetime import datetime
                bot_data['last_alert_check'] = datetime.utcnow()
                
    except Exception as e:
        logger.error(f"Error checking alerts: {e}")
        import traceback
        logger.error(traceback.format_exc())


async def post_shutdown(application: Application):
    """Cleanup on shutdown"""
    logger.info("Telegram bot shutting down...")


def main():
    """Main entry point"""
    # Check if Telegram bot token is set
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not bot_token:
        logger.error("TELEGRAM_BOT_TOKEN environment variable not set!")
        logger.error("Get your bot token from @BotFather on Telegram")
        logger.error("Then set: export TELEGRAM_BOT_TOKEN='your_token_here'")
        logger.error("Or create a .env file in this directory with TELEGRAM_BOT_TOKEN=...")
        sys.exit(1)
    
    if not TELEGRAM_AVAILABLE:
        logger.error("python-telegram-bot library not available")
        logger.error("Install it with: pip install python-telegram-bot[job-queue]")
        sys.exit(1)
    
    # Initialize bot
    if not init_telegram_bot(bot_token):
        logger.error("Failed to initialize Telegram bot")
        sys.exit(1)
    
    # Create application
    application = Application.builder().token(bot_token).post_init(post_init).post_shutdown(post_shutdown).build()
    
    # Setup handlers
    setup_handlers(application)
    
    logger.info("=" * 50)
    logger.info("🚀 FIMonacci Telegram Bot Starting...")
    logger.info("=" * 50)
    logger.info("📱 Bot is ready! Use /start in Telegram to begin.")
    logger.info("💡 Bot: @fimonacci_bot")
    logger.info("=" * 50)
    
    # Start polling
    try:
        application.run_polling(allowed_updates=Update.ALL_TYPES)
    except KeyboardInterrupt:
        logger.info("\n⚠️  Bot stopped by user")
    except Exception as e:
        logger.error(f"❌ Bot error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

