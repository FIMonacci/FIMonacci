#!/bin/bash
# Start FIMonacci Telegram Bot

# Load environment variables from .env if exists
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Set token if not already set (use your actual token)
if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
    export TELEGRAM_BOT_TOKEN='7512481255:AAGjvQdKNWYmAAQRQ92laN_oirYI7VCDkn4'
fi

# Check if token is set
if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
    echo "❌ Error: TELEGRAM_BOT_TOKEN not set!"
    echo "Set it in .env file or export it:"
    echo "export TELEGRAM_BOT_TOKEN='your_token_here'"
    exit 1
fi

echo "🚀 Starting FIMonacci Telegram Bot..."
echo "📱 Bot Token: ${TELEGRAM_BOT_TOKEN:0:20}..."
echo ""
echo "💡 Instructions:"
echo "1. Open Telegram and find @fimonacci_bot"
echo "2. Send /start"
echo "3. Send /auth <admin_username> <admin_password>"
echo "4. You will receive file integrity alerts!"
echo ""
echo "Press Ctrl+C to stop"
echo ""

python3 bot.py

