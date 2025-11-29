import os
import threading
from pathlib import Path

from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO

db = SQLAlchemy()
socketio = SocketIO(async_mode="threading")
login_manager = LoginManager()
_background_threads = {}


def _determine_monitor_paths():
    env_paths = os.environ.get("FIMONACCI_PATHS")
    if env_paths:
        return [Path(p).expanduser().resolve() for p in env_paths.split(":") if p.strip()]

    # On Vercel, don't create monitored directory (read-only filesystem)
    is_vercel = os.environ.get("VERCEL") == "1" or os.environ.get("VERCEL_ENV")
    if is_vercel:
        return []  # Return empty list on Vercel
    
    default_path = Path(__file__).resolve().parent.parent / "monitored"
    try:
        default_path.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError):
        # If we can't create directory (e.g., on Vercel), return empty list
        return []
    return [default_path]


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    # PostgreSQL connection string (Railway.app)
    default_db_url = "postgresql://postgres:fuDyEVQghwYxXYEJpZcXcCQdXeSMPnZK@shuttle.proxy.rlwy.net:51274/railway"
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", default_db_url)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MONITOR_PATHS"] = _determine_monitor_paths()

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    
    # SocketIO initialization - skip on Vercel (WebSocket not fully supported)
    is_vercel = os.environ.get("VERCEL") == "1" or os.environ.get("VERCEL_ENV")
    if not is_vercel:
        try:
            socketio.init_app(app, cors_allowed_origins="*")
            
            # SocketIO connection handler
            @socketio.on('connect')
            def handle_connect(auth=None):
                from flask_login import current_user
                from flask import request
                try:
                    if current_user.is_authenticated:
                        # Join user to their personal room using the correct SID
                        socketio.server.enter_room(request.sid, f"user_{current_user.id}")
                except Exception as e:
                    app.logger.error(f"SocketIO connect error: {e}")
                    return False
        except Exception as e:
            app.logger.warning(f"SocketIO initialization failed (may be expected on Vercel): {e}")

    from .routes import main_bp
    from .auth import auth_bp
    from .admin import admin_bp
    from .database import User, FileIntegrity, MonitoredFolder  # noqa: F401
    from .monitor import create_baseline, start_monitoring, start_hash_verification_loop, start_active_scan_loop

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    # Initialize database - wrap in try/except for Vercel compatibility
    try:
        with app.app_context():
            try:
                db.create_all()
            except Exception as e:
                app.logger.error(f"Database initialization error: {e}")
                # Continue even if database fails (for Vercel compatibility)
            
            # Only start monitoring if not disabled and not on Vercel
            if not is_vercel and os.environ.get("DISABLE_MONITORING") != "1":
                try:
                    create_baseline(app)
                    _start_background_thread("watchdog", app, start_monitoring)
                    _start_background_thread("hash_verifier", app, start_hash_verification_loop)
                except Exception as e:
                    app.logger.warning(f"Monitoring initialization failed: {e}")
            
            # Always start active scan loop (runs every 1 minute) - skip on Vercel
            if not is_vercel:
                try:
                    _start_background_thread("active_scan", app, lambda app: start_active_scan_loop(app, interval_seconds=60))
                except Exception as e:
                    app.logger.warning(f"Active scan initialization failed: {e}")
    except Exception as e:
        # If app context fails, log but continue
        app.logger.error(f"App context initialization error: {e}")
        import traceback
        app.logger.error(traceback.format_exc())

    return app


def _start_background_thread(name, app, target_func):
    thread = _background_threads.get(name)
    if thread and thread.is_alive():
        return

    def _runner():
        target_func(app)

    new_thread = threading.Thread(target=_runner, daemon=True, name=f"fimonacci-{name}")
    _background_threads[name] = new_thread
    new_thread.start()

