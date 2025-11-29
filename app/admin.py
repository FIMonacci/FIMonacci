from functools import wraps
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user

from . import db
from .database import User, FileHash, MonitoredFolder, FileIntegrity, Client

admin_bp = Blueprint("admin", __name__)


def admin_required(f):
    """Decorator to require admin access"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        # Double check: ensure user is authenticated and is admin
        if not current_user.is_authenticated:
            flash("Please log in to access this page.", "error")
            return redirect(url_for("auth.login"))
        
        # Reload user from database to ensure we have latest admin status
        from .database import User
        user = User.query.get(current_user.id)
        if not user or not user.is_admin:
            flash("Access denied. Admin privileges required.", "error")
            return redirect(url_for("main.dashboard"))
        
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route("/admin")
@admin_required
def admin_panel():
    """Admin panel main page"""
    return render_template("admin.html")


@admin_bp.route("/admin/api/clients")
@admin_required
def get_all_clients():
    """Get all clients with statistics"""
    clients = Client.query.order_by(Client.last_seen.desc()).all()
    result = []
    
    for client in clients:
        hash_count = FileHash.query.filter_by(client_id=client.id).count()
        monitored_count = MonitoredFolder.query.filter_by(client_id=client.id, is_active=True).count()
        alerts_count = FileIntegrity.query.filter_by(client_id=client.id).filter(
            FileIntegrity.alert_type != "baseline"
        ).count()
        
        result.append({
            **client.as_dict(),
            "hash_count": hash_count,
            "monitored_folders_count": monitored_count,
            "alerts_count": alerts_count,
        })
    
    return jsonify(result)


@admin_bp.route("/admin/api/client/<int:client_id>/hashes")
@admin_required
def get_client_hashes(client_id):
    """Get all file hashes for a specific client"""
    client = Client.query.get_or_404(client_id)
    hashes = FileHash.query.filter_by(client_id=client_id).order_by(FileHash.timestamp.desc()).all()
    return jsonify({
        "client": client.as_dict(),
        "hashes": [h.as_dict() for h in hashes],
        "count": len(hashes)
    })


@admin_bp.route("/admin/api/client/<int:client_id>/folders")
@admin_required
def get_client_folders(client_id):
    """Get all monitored folders for a specific client"""
    client = Client.query.get_or_404(client_id)
    folders = MonitoredFolder.query.filter_by(client_id=client_id).order_by(MonitoredFolder.created_at.desc()).all()
    return jsonify({
        "client": client.as_dict(),
        "folders": [f.as_dict() for f in folders],
        "count": len(folders)
    })


@admin_bp.route("/admin/api/client/<int:client_id>/alerts")
@admin_required
def get_client_alerts(client_id):
    """Get all alerts for a specific client"""
    client = Client.query.get_or_404(client_id)
    alerts = FileIntegrity.query.filter_by(client_id=client_id).filter(
        FileIntegrity.alert_type != "baseline"
    ).order_by(FileIntegrity.timestamp.desc()).limit(500).all()
    
    return jsonify({
        "client": client.as_dict(),
        "alerts": [a.as_dict() for a in alerts],
        "count": len(alerts)
    })


@admin_bp.route("/admin/api/client/<int:client_id>/stats")
@admin_required
def get_client_stats(client_id):
    """Get comprehensive statistics for a specific client"""
    client = Client.query.get_or_404(client_id)
    
    hash_count = FileHash.query.filter_by(client_id=client_id).count()
    active_folders = MonitoredFolder.query.filter_by(client_id=client_id, is_active=True).count()
    total_folders = MonitoredFolder.query.filter_by(client_id=client_id).count()
    alerts_count = FileIntegrity.query.filter_by(client_id=client_id).filter(
        FileIntegrity.alert_type != "baseline"
    ).count()
    hash_mismatch_count = FileIntegrity.query.filter_by(client_id=client_id).filter_by(
        alert_type="hash_mismatch"
    ).count()
    missing_count = FileIntegrity.query.filter_by(client_id=client_id).filter_by(
        alert_type="missing"
    ).count()
    
    return jsonify({
        "client": client.as_dict(),
        "stats": {
            "total_hashes": hash_count,
            "active_monitored_folders": active_folders,
            "total_monitored_folders": total_folders,
            "total_alerts": alerts_count,
            "hash_mismatch_alerts": hash_mismatch_count,
            "missing_file_alerts": missing_count,
        }
    })


@admin_bp.route("/admin/api/make-admin/<int:user_id>", methods=["POST"])
@admin_required
def make_admin(user_id):
    """Make a user admin"""
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    return jsonify({"success": True, "message": f"User {user.username} is now an admin"})


@admin_bp.route("/admin/api/remove-admin/<int:user_id>", methods=["POST"])
@admin_required
def remove_admin(user_id):
    """Remove admin privileges from a user"""
    if user_id == current_user.id:
        return jsonify({"success": False, "message": "Cannot remove admin privileges from yourself"}), 400
    
    user = User.query.get_or_404(user_id)
    user.is_admin = False
    db.session.commit()
    return jsonify({"success": True, "message": f"Admin privileges removed from {user.username}"})


@admin_bp.route("/admin/api/charts/activity")
@admin_required
def get_activity_chart_data():
    """Get system activity data for 24h chart"""
    from datetime import datetime, timedelta
    from .database import FileIntegrity
    
    # Get data for last 24 hours
    now = datetime.utcnow()
    start_time = now - timedelta(hours=24)
    
    # Get all alerts in last 24 hours
    alerts = FileIntegrity.query.filter(
        FileIntegrity.timestamp >= start_time,
        FileIntegrity.alert_type != "baseline"
    ).order_by(FileIntegrity.timestamp.asc()).all()
    
    # Create 24 hour buckets (1 hour each)
    buckets = {}
    for i in range(24):
        bucket_time = start_time + timedelta(hours=i)
        buckets[bucket_time] = 0
    
    # Count events per hour
    for alert in alerts:
        # Round to nearest hour
        alert_hour = alert.timestamp.replace(minute=0, second=0, microsecond=0)
        if alert_hour in buckets:
            buckets[alert_hour] += 1
    
    # Generate labels and data
    labels = []
    events_data = []
    
    for hour in sorted(buckets.keys()):
        # Format label
        if hour.hour == 0:
            labels.append("00:00")
        elif hour.hour == now.hour and hour.date() == now.date():
            labels.append("Now")
        else:
            labels.append(f"{hour.hour:02d}:00")
        events_data.append(buckets[hour])
    
    # Generate mock CPU data (in real app, this would come from system monitoring)
    # For now, we'll simulate CPU based on events
    cpu_data = [min(80, 40 + (count * 0.5)) for count in events_data]
    
    return jsonify({
        "labels": labels,
        "events": events_data,
        "cpu": cpu_data
    })


@admin_bp.route("/admin/api/charts/distribution")
@admin_required
def get_distribution_chart_data():
    """Get event distribution data for pie chart"""
    from datetime import datetime, timedelta
    from .database import FileIntegrity
    
    # Get data for last 24 hours
    now = datetime.utcnow()
    start_time = now - timedelta(hours=24)
    
    # Count events by type
    alerts = FileIntegrity.query.filter(
        FileIntegrity.timestamp >= start_time,
        FileIntegrity.alert_type != "baseline"
    ).all()
    
    # Count by type
    event_counts = {
        "Modified": 0,
        "Created": 0,
        "Deleted": 0,
        "Accessed": 0
    }
    
    for alert in alerts:
        alert_type = alert.alert_type
        if alert_type in ["hash_mismatch", "modified"]:
            event_counts["Modified"] += 1
        elif alert_type == "created":
            event_counts["Created"] += 1
        elif alert_type in ["deleted", "missing"]:
            event_counts["Deleted"] += 1
        else:
            # Count as accessed for other types
            event_counts["Accessed"] += 1
    
    # Prepare data for chart
    labels = []
    values = []
    colors = []
    
    # Order: Modified, Accessed, Created, Deleted
    chart_order = [
        ("Modified", "#3b82f6"),  # Blue
        ("Accessed", "#f59e0b"),  # Orange
        ("Created", "#10b981"),   # Green
        ("Deleted", "#ef4444")    # Red
    ]
    
    for label, color in chart_order:
        count = event_counts[label]
        if count > 0:  # Only include if there are events
            labels.append(label)
            values.append(count)
            colors.append(color)
    
    return jsonify({
        "labels": labels,
        "values": values,
        "colors": colors
    })


@admin_bp.route("/admin/api/logs")
@admin_required
def get_logs():
    """Get system logs from FileIntegrity events and client activity"""
    from datetime import datetime, timedelta
    from .database import FileIntegrity, Client
    
    logs = []
    
    # Get file integrity events from last 24 hours
    now = datetime.utcnow()
    start_time = now - timedelta(hours=24)
    
    alerts = FileIntegrity.query.filter(
        FileIntegrity.timestamp >= start_time
    ).order_by(FileIntegrity.timestamp.desc()).limit(500).all()
    
    for alert in alerts:
        alert_type = alert.alert_type
        
        # Determine log level and message
        if alert_type in ["deleted", "missing"]:
            level = "error"
            message = f"File deleted: {alert.path}"
        elif alert_type == "created":
            level = "success"
            message = f"File created: {alert.path}"
        elif alert_type in ["hash_mismatch", "modified"]:
            level = "warning"
            message = f"File modified: {alert.path} (Hash changed)"
        else:
            level = "info"
            message = f"File event: {alert.path} ({alert_type})"
        
        # Get client hostname if available
        client_info = ""
        if alert.client_id and alert.client:
            client_info = f" [Client: {alert.client.hostname or alert.client.client_id[:8]}]"
        
        logs.append({
            "timestamp": alert.timestamp.isoformat(),
            "level": level,
            "type": "file_event",
            "message": message + client_info
        })
    
    # Get client connection events
    clients = Client.query.filter(
        Client.last_seen >= start_time
    ).order_by(Client.last_seen.desc()).limit(100).all()
    
    for client in clients:
        # Check if this is a recent connection (within last hour)
        if (now - client.last_seen).total_seconds() < 3600:
            logs.append({
                "timestamp": client.last_seen.isoformat(),
                "level": "info",
                "type": "client",
                "message": f"Client connected: {client.hostname or 'Unknown'} (ID: {client.client_id[:8]}...)"
            })
    
    # Add system events
    logs.append({
        "timestamp": now.isoformat(),
        "level": "info",
        "type": "system",
        "message": "FIMonacci monitoring system active"
    })
    
    # Sort by timestamp (newest first)
    logs.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return jsonify(logs[:200])  # Return latest 200 logs


@admin_bp.route("/admin/api/logs/clear", methods=["POST"])
@admin_required
def clear_logs():
    """Clear old logs (older than 7 days)"""
    from datetime import datetime, timedelta
    from .database import FileIntegrity
    
    # Delete logs older than 7 days (except baseline)
    cutoff = datetime.utcnow() - timedelta(days=7)
    
    deleted_count = FileIntegrity.query.filter(
        FileIntegrity.timestamp < cutoff,
        FileIntegrity.alert_type != "baseline"
    ).delete()
    
    db.session.commit()
    
    return jsonify({
        "success": True,
        "message": f"Cleared {deleted_count} old log entries"
    })

