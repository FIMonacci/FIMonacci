import hashlib
import time
from pathlib import Path
from datetime import datetime

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from . import db, socketio
from .database import FileHash, FileIntegrity, MonitoredFolder


def calculate_md5(filepath):
    """
    Calculate MD5 hash of a file.
    Returns None if file cannot be read.
    """
    hash_md5 = hashlib.md5()
    try:
        # Ensure we have a valid file path
        path_obj = Path(filepath)
        if not path_obj.exists():
            return None
        if not path_obj.is_file():
            return None
        
        # Read file in chunks to handle large files efficiently
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)  # Read 8KB chunks
                if not chunk:
                    break
                hash_md5.update(chunk)
        
        return hash_md5.hexdigest()
    except (FileNotFoundError, PermissionError, IOError, OSError) as e:
        # File doesn't exist, no permission, or I/O error
        return None
    except Exception:
        # Any other unexpected error
        return None


def create_baseline(app):
    monitor_paths = app.config["MONITOR_PATHS"]
    for path in monitor_paths:
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        for file_path in path.rglob("*"):
            if file_path.is_file():
                _upsert_baseline(str(file_path))


def _upsert_baseline(filepath):
    existing = FileIntegrity.query.filter_by(path=filepath, alert_type="baseline").first()
    file_hash = calculate_md5(filepath)
    if not file_hash:
        return
    if existing:
        existing.initial_hash = file_hash
    else:
        record = FileIntegrity(
            path=filepath,
            initial_hash=file_hash,
            current_hash=file_hash,
            alert_type="baseline",
        )
        db.session.add(record)
    db.session.commit()


def _record_alert(filepath, baseline_hash, current_hash, event_type, client_id=None):
    """
    Record an alert and emit it via SocketIO.
    If client_id is provided, associate alert with that client.
    """
    # Normalize path for comparison
    normalized_path = filepath.replace('\\', '/')
    
    last_alert = (
        FileIntegrity.query.filter_by(alert_type=event_type, client_id=client_id)
        .filter(
            (FileIntegrity.path == filepath) |
            (FileIntegrity.path == normalized_path) |
            (FileIntegrity.path == filepath.replace('/', '\\'))
        )
        .order_by(FileIntegrity.timestamp.desc())
        .first()
    )
    if last_alert and last_alert.current_hash == current_hash:
        return

    # Use current UTC time for accurate timestamp
    alert = FileIntegrity(
        client_id=client_id,
        path=normalized_path,
        initial_hash=baseline_hash or "unknown",
        current_hash=current_hash,
        alert_type=event_type,
        timestamp=datetime.utcnow()  # Explicit timestamp
    )
    db.session.add(alert)
    db.session.commit()
    
    # Emit alert to all admins (skip on Vercel - WebSocket not fully supported)
    try:
        import os
        is_vercel = os.environ.get("VERCEL") == "1" or os.environ.get("VERCEL_ENV")
        if not is_vercel:
            alert_data = {
                "path": normalized_path,
                "alert_type": event_type,
                "initial_hash": baseline_hash,
                "current_hash": current_hash,
                "timestamp": alert.timestamp.isoformat(),
                "client_id": client_id,
            }
            socketio.emit("new_alert", alert_data)
    except Exception as e:
        # SocketIO may not be available (e.g., on Vercel)
        pass


class FIMHandler(FileSystemEventHandler):
    def __init__(self, app):
        super().__init__()
        self.app = app

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle_event(event.src_path, "created")

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle_event(event.src_path, "modified")

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._handle_deleted(event.src_path)

    def _handle_event(self, filepath, event_type):
        with self.app.app_context():
            baseline = FileIntegrity.query.filter_by(path=filepath, alert_type="baseline").first()
            current_hash = calculate_md5(filepath)
            if not current_hash:
                return

            if not baseline:
                _upsert_baseline(filepath)
                baseline_hash = current_hash
            else:
                baseline_hash = baseline.initial_hash

            if baseline_hash != current_hash or event_type == "created":
                self._log_alert(filepath, baseline_hash, current_hash, event_type)

    def _handle_deleted(self, filepath):
        with self.app.app_context():
            baseline = FileIntegrity.query.filter_by(path=filepath, alert_type="baseline").first()
            baseline_hash = baseline.initial_hash if baseline else "unknown"
            self._log_alert(filepath, baseline_hash, None, "deleted")

    def _log_alert(self, filepath, baseline_hash, current_hash, event_type):
        _record_alert(filepath, baseline_hash, current_hash, event_type)


def start_monitoring(app):
    monitor_paths = app.config["MONITOR_PATHS"]
    event_handler = FIMHandler(app)
    observer = Observer()
    for path in monitor_paths:
        folder = Path(path)
        folder.mkdir(parents=True, exist_ok=True)
        observer.schedule(event_handler, str(folder), recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def start_hash_verification_loop(app, interval_seconds=300):
    """Periodically verify uploaded file hashes against current disk state."""
    while True:
        with app.app_context():
            try:
                _run_hash_verification_cycle()
            except Exception as exc:  # pragma: no cover - safety net
                app.logger.exception("Hash verification loop error: %s", exc)
        time.sleep(interval_seconds)


def start_active_scan_loop(app, interval_seconds=60):
    """Scan actively monitored folders every minute and verify hashes."""
    while True:
        with app.app_context():
            try:
                _run_active_scan_cycle()
            except Exception as exc:
                app.logger.exception("Active scan loop error: %s", exc)
        time.sleep(interval_seconds)


def _run_active_scan_cycle():
    """Scan all active monitored folders and verify file hashes."""
    # Get all active monitored folders
    active_folders = MonitoredFolder.query.filter_by(is_active=True).all()
    
    for monitored_folder in active_folders:
        folder_path = Path(monitored_folder.folder_path)
        
        # Only scan folders that exist on THIS server
        # Client-uploaded files are on the client, not server, so skip if folder doesn't exist
        if not folder_path.exists() or not folder_path.is_dir():
            continue
        
        # Normalize folder path for comparison
        folder_path_normalized = str(folder_path.resolve()).replace('\\', '/')
        
        # Get all files in this folder (recursively)
        for file_path in folder_path.rglob("*"):
            if not file_path.is_file():
                continue
            
            abs_path = str(file_path.resolve())
            abs_path_normalized = abs_path.replace('\\', '/')
            
            # Find corresponding FileHash record - try multiple path formats
            file_hash_record = FileHash.query.filter_by(
                client_id=monitored_folder.client_id
            ).filter(
                (FileHash.path == abs_path) |
                (FileHash.path == abs_path_normalized) |
                (FileHash.path == abs_path.replace('/', '\\')) |
                (FileHash.path == abs_path.replace('\\', '/'))
            ).first()
            
            if not file_hash_record:
                # File exists on server but not in database - this is a NEW file (created event)
                current_hash = calculate_md5(abs_path)
                if current_hash:
                    _record_alert(abs_path_normalized, None, current_hash, "created", client_id=monitored_folder.client_id)
                continue
            
            # Calculate current hash
            current_hash = calculate_md5(abs_path)
            baseline_hash = file_hash_record.hash_md5
            
            if current_hash is None:
                # File missing or unreadable - only if it was previously in DB
                _record_alert(abs_path_normalized, baseline_hash, None, "missing", client_id=monitored_folder.client_id)
                continue
            
            if current_hash != baseline_hash:
                # Hash mismatch - file changed!
                _record_alert(abs_path_normalized, baseline_hash, current_hash, "hash_mismatch", client_id=monitored_folder.client_id)
        
        # Update last_scan timestamp
        monitored_folder.last_scan = datetime.utcnow()
        db.session.commit()


def _run_hash_verification_cycle():
    """
    Verify all file hashes in database against current disk state.
    NOTE: This only verifies files that exist on the SERVER.
    Client-uploaded files are on the client machine and cannot be verified here.
    """
    records = FileHash.query.all()
    for record in records:
        # Try multiple path formats (normalize separators)
        path_variants = [
            record.path,
            record.path.replace('/', '\\'),  # Windows format
            record.path.replace('\\', '/'),  # Unix format
        ]
        
        # Check if file exists on server before trying to hash
        file_exists = False
        for path_variant in path_variants:
            if Path(path_variant).exists():
                file_exists = True
                break
        
        # If file doesn't exist on server, it's likely a client file - skip verification
        if not file_exists:
            continue
        
        current_hash = None
        actual_path = None
        for path_variant in path_variants:
            if Path(path_variant).exists():
                current_hash = calculate_md5(path_variant)
                if current_hash is not None:
                    actual_path = path_variant
                    break
        
        baseline_hash = record.hash_md5
        if current_hash is None:
            # File was on server but now missing/unreadable
            _record_alert(record.path, baseline_hash, None, "missing", client_id=record.client_id)
            continue

        if current_hash != baseline_hash:
            _record_alert(actual_path or record.path, baseline_hash, current_hash, "hash_mismatch", client_id=record.client_id)

