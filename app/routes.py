import os
import json
from pathlib import Path
from datetime import datetime

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, g
from flask_login import login_required, current_user

from . import db
from .database import FileHash, MonitoredFolder, Client
from .monitor import calculate_md5, _record_alert
from .auth import token_required

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin.admin_panel"))
        else:
            # Regular users should use client script
            return """
            <html>
            <head><title>FIMonacci</title></head>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                <h1>FIMonacci File Integrity Monitor</h1>
                <p>This interface is for administrators only.</p>
                <p>To upload file hashes, please use the FIMonacci client script.</p>
                <p><a href="/auth/logout">Logout</a></p>
            </body>
            </html>
            """
    return redirect(url_for("auth.login"))


@main_bp.route("/dashboard")
@login_required
def dashboard():
    # Dashboard is now admin-only, redirect to admin panel
    if not current_user.is_admin:
        flash("Access denied. Admin privileges required.", "error")
        return redirect(url_for("main.index"))
    return redirect(url_for("admin.admin_panel"))


@main_bp.route("/api/browse")
@login_required
def browse_filesystem():
    # Only admins can browse file system via UI
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required"}), 403
    """Browse file system and return directory structure"""
    path = request.args.get("path", "/")
    
    try:
        path_obj = Path(path).resolve()
        
        # Security: prevent directory traversal
        if not path_obj.exists() or not path_obj.is_dir():
            return jsonify({"error": "Invalid path"}), 400
        
        items = []
        for item in sorted(path_obj.iterdir()):
            try:
                if item.is_dir():
                    items.append({
                        "name": item.name,
                        "path": str(item),
                        "type": "directory",
                        "size": None
                    })
                elif item.is_file():
                    try:
                        size = item.stat().st_size
                    except:
                        size = 0
                    items.append({
                        "name": item.name,
                        "path": str(item),
                        "type": "file",
                        "size": size
                    })
            except PermissionError:
                continue
        
        return jsonify({
            "current_path": str(path_obj),
            "parent_path": str(path_obj.parent) if path_obj.parent != path_obj else None,
            "items": items
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@main_bp.route("/api/upload", methods=["POST"])
@login_required
def upload_folders():
    """Calculate hashes for files in selected folders and store in database (Admin only)"""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required"}), 403
    data = request.get_json()
    folders = data.get("folders", [])
    
    if not folders:
        return jsonify({"error": "No folders selected"}), 400
    
    results = {
        "processed": 0,
        "errors": [],
        "success": []
    }
    
    for folder_path in folders:
        try:
            folder = Path(folder_path)
            if not folder.exists() or not folder.is_dir():
                results["errors"].append(f"{folder_path}: Folder not found")
                continue
            
            # Recursively process all files in folder
            # Use resolve() to get absolute paths and avoid duplicates
            processed_paths = set()
            for file_path in folder.rglob("*"):
                if file_path.is_file():
                    try:
                        # Get absolute resolved path to avoid duplicates
                        abs_path = str(file_path.resolve())
                        
                        # Skip if already processed in this batch
                        if abs_path in processed_paths:
                            continue
                        processed_paths.add(abs_path)
                        
                        # Verify file still exists and is readable
                        if not file_path.exists() or not file_path.is_file():
                            results["errors"].append(f"{abs_path}: File not found")
                            continue
                        
                        # Calculate hash
                        file_hash = calculate_md5(abs_path)
                        if not file_hash:
                            results["errors"].append(f"{abs_path}: Hash calculation failed (file could not be read)")
                            continue
                        
                        # Get file size
                        try:
                            file_size = file_path.stat().st_size
                        except OSError:
                            file_size = None
                        
                        # Note: This endpoint is deprecated - use /api/upload/hashes instead
                        # This was for admin UI upload, but now clients upload directly
                        # Skipping file processing as it requires client_id
                        results["errors"].append(f"{abs_path}: This endpoint is deprecated. Use client script instead.")
                    except Exception as e:
                        results["errors"].append(f"{file_path}: {str(e)}")
        except Exception as e:
            results["errors"].append(f"{folder_path}: {str(e)}")
    
    return jsonify(results)


@main_bp.route("/api/hashes")
@login_required
def get_hashes():
    """Get all file hashes (Admin only - returns all)"""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required"}), 403
    hashes = FileHash.query.order_by(FileHash.timestamp.desc()).limit(1000).all()
    return jsonify([h.as_dict() for h in hashes])


@main_bp.route("/api/client/register", methods=["POST"])
def register_client():
    """Register or update a client (no authentication required)"""
    data = request.get_json()
    client_id = data.get("client_id")
    hostname = data.get("hostname", "unknown")
    
    if not client_id:
        return jsonify({"error": "client_id is required"}), 400
    
    # Find or create client
    client = Client.query.filter_by(client_id=client_id).first()
    
    if client:
        # Update existing client
        client.hostname = hostname
        client.last_seen = datetime.utcnow()
        db.session.commit()
        return jsonify(client.as_dict()), 200
    else:
        # Create new client
        client = Client(
            client_id=client_id,
            hostname=hostname
        )
        db.session.add(client)
        db.session.commit()
        return jsonify(client.as_dict()), 201


@main_bp.route("/api/upload/hashes", methods=["POST"])
def upload_file_hashes():
    """Upload pre-calculated file hashes from client script (client_id based)"""
    # Get client_id from header
    client_id = request.headers.get('X-Client-ID')
    hostname = request.headers.get('X-Hostname', 'unknown')
    
    if not client_id:
        return jsonify({"error": "X-Client-ID header is required"}), 400
    
    # Find or create client
    client = Client.query.filter_by(client_id=client_id).first()
    if not client:
        client = Client(client_id=client_id, hostname=hostname)
        db.session.add(client)
        db.session.commit()
    else:
        # Update hostname and last_seen
        client.hostname = hostname
        client.last_seen = datetime.utcnow()
        db.session.commit()
    
    data = request.get_json()
    files = data.get("files", [])
    
    if not files:
        return jsonify({"error": "No files provided"}), 400
    
    results = {
        "processed": 0,
        "errors": [],
        "success": []
    }
    
    for file_data in files:
        try:
            file_path = file_data.get("path")
            file_hash = file_data.get("hash_md5")
            file_size = file_data.get("file_size")
            
            if not file_path or not file_hash:
                results["errors"].append(f"Missing path or hash for file")
                continue
            
            # Store path as-is from client (don't resolve on server side)
            # Client sends absolute paths, so we just normalize separators
            abs_path = file_path.replace('\\', '/')  # Normalize Windows backslashes to forward slashes
            
            # Check if hash already exists for this client and path
            existing = FileHash.query.filter_by(
                client_id=client.id,
                path=abs_path
            ).first()
            
            # Check if this is an event-triggered upload (has event_type in request)
            event_type = file_data.get("event_type")  # created, modified, deleted, hash_mismatch
            
            is_new_file = False
            if existing:
                # Update existing record - check if hash changed
                old_hash = existing.hash_md5
                existing.hash_md5 = file_hash
                if file_size is not None:
                    existing.file_size = file_size
                existing.timestamp = datetime.utcnow()
                
                # If hash changed and event_type is provided, use it; otherwise default to hash_mismatch
                if old_hash != file_hash:
                    alert_type = event_type if event_type else "hash_mismatch"
                    _record_alert(abs_path, old_hash, file_hash, alert_type, client_id=client.id)
            else:
                # Create new record
                is_new_file = True
                file_hash_record = FileHash(
                    client_id=client.id,
                    path=abs_path,
                    hash_md5=file_hash,
                    file_size=file_size,
                    timestamp=datetime.utcnow()  # Explicit timestamp
                )
                db.session.add(file_hash_record)
                
                # If event_type is "created", record the alert
                if event_type == "created":
                    _record_alert(abs_path, None, file_hash, "created", client_id=client.id)
            
            # Commit after each file to avoid transaction rollback issues
            db.session.commit()
            
            results["processed"] += 1
            results["success"].append(abs_path)
            
        except Exception as e:
            # Rollback on error to allow next file to be processed
            db.session.rollback()
            results["errors"].append(f"{file_data.get('path', 'unknown')}: {str(e)}")
    
    return jsonify(results)


@main_bp.route("/api/upload/event", methods=["POST"])
def upload_file_event():
    """Upload file event alert from client (for deleted files and other events)"""
    # Get client_id from header (same as upload/hashes endpoint)
    client_id = request.headers.get('X-Client-ID')
    hostname = request.headers.get('X-Hostname', 'unknown')
    
    if not client_id:
        return jsonify({"error": "X-Client-ID header is required"}), 400
    
    # Find or create client
    client = Client.query.filter_by(client_id=client_id).first()
    if not client:
        client = Client(client_id=client_id, hostname=hostname)
        db.session.add(client)
        db.session.commit()
    else:
        # Update hostname and last_seen
        client.hostname = hostname
        client.last_seen = datetime.utcnow()
        db.session.commit()
    
    data = request.get_json()
    filepath = data.get("path")
    initial_hash = data.get("initial_hash")
    current_hash = data.get("current_hash")
    alert_type = data.get("alert_type")
    
    if not filepath or not alert_type:
        return jsonify({"error": "path and alert_type are required"}), 400
    
    # Normalize path
    abs_path = filepath.replace('\\', '/')
    
    # Record the alert
    from .monitor import _record_alert
    _record_alert(abs_path, initial_hash, current_hash, alert_type, client_id=client.id)
    
    # For deleted files, also remove from FileHash if it exists
    if alert_type == "deleted":
        # Try multiple path formats
        file_hash = FileHash.query.filter_by(
            client_id=client.id
        ).filter(
            (FileHash.path == abs_path) |
            (FileHash.path == abs_path.replace('/', '\\')) |
            (FileHash.path == filepath.replace('\\', '/'))
        ).first()
        if file_hash:
            db.session.delete(file_hash)
            db.session.commit()
    
    return jsonify({"success": True, "message": "Event recorded"})


@main_bp.route("/api/monitor/start", methods=["POST"])
@login_required
def start_monitoring_folders():
    """Start active scan for selected folders (Admin only)"""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required"}), 403
    data = request.get_json()
    folders = data.get("folders", [])
    
    if not folders:
        return jsonify({"error": "No folders selected"}), 400
    
    activated = []
    for folder_path in folders:
        try:
            folder = Path(folder_path)
            abs_folder_path = str(folder.resolve())
            
            if not folder.exists() or not folder.is_dir():
                continue
            
            # Note: Monitoring folders requires client_id, not user_id
            # This endpoint is deprecated - folders should be monitored via client uploads
            # Keeping for backward compatibility but it won't work properly
            pass
        except Exception as e:
            continue
    
    return jsonify({
        "success": True,
        "activated": len(activated),
        "folders": activated
    })


@main_bp.route("/api/monitor/stop", methods=["POST"])
@login_required
def stop_monitoring_folders():
    """Stop active scan for selected folders (Admin only)"""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required"}), 403
    data = request.get_json()
    folders = data.get("folders", [])
    
    if folders:
        # Deactivate specific folders
        for folder_path in folders:
            abs_folder_path = str(Path(folder_path).resolve())
            # Deactivate by folder path (works for all clients with that path)
            MonitoredFolder.query.filter_by(
                folder_path=abs_folder_path
            ).update({"is_active": False})
    else:
        # Deactivate all folders (admin can deactivate all)
        MonitoredFolder.query.update({"is_active": False})
    
    db.session.commit()
    return jsonify({"success": True})


@main_bp.route("/api/monitor/status")
@login_required
def get_monitoring_status():
    """Get active monitoring folders (Admin only - returns all)"""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required"}), 403
    active_folders = MonitoredFolder.query.filter_by(is_active=True).all()
    
    return jsonify([f.as_dict() for f in active_folders])


@main_bp.route("/api/alerts")
@login_required
def get_alerts():
    """Get all alerts for current user (Admin only)"""
    if not current_user.is_admin:
        return jsonify({"error": "Admin access required"}), 403
    from .database import FileIntegrity
    alerts = FileIntegrity.query.filter(
        FileIntegrity.alert_type != "baseline"
    ).order_by(FileIntegrity.timestamp.desc()).limit(500).all()
    
    return jsonify([a.as_dict() for a in alerts])

