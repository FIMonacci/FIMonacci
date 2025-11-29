import secrets
from functools import wraps
from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, g
from flask_login import login_user, logout_user, login_required, current_user

from . import db
from .database import User, ApiToken

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin.admin_panel"))
        else:
            return redirect(url_for("main.index"))
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for("admin.admin_panel"))
            else:
                return redirect(url_for("main.index"))
        else:
            flash("Invalid username or password.", "error")
    
    return render_template("login.html")


# Signup removed - users are created by admins via admin panel or API


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Successfully logged out.", "success")
    return redirect(url_for("auth.login"))


def token_required(f):
    """Decorator for API endpoints that require token authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # Format: "Bearer <token>"
                token = auth_header.split(' ')[1] if ' ' in auth_header else auth_header
            except:
                pass
        
        # Also check in query parameter (for convenience)
        if not token:
            token = request.args.get('token')
        
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        
        # Find token in database
        api_token = ApiToken.query.filter_by(token=token, is_active=True).first()
        
        if not api_token:
            return jsonify({"error": "Invalid or inactive token"}), 401
        
        # Update last used timestamp
        api_token.last_used = datetime.utcnow()
        db.session.commit()
        
        # Store user in g for access in route
        g.current_user = api_token.user
        
        return f(*args, **kwargs)
    
    return decorated_function


@auth_bp.route("/api/tokens", methods=["GET"])
@login_required
def list_tokens():
    """List all API tokens for current user"""
    tokens = ApiToken.query.filter_by(user_id=current_user.id).order_by(ApiToken.created_at.desc()).all()
    return jsonify([t.as_dict() for t in tokens])


@auth_bp.route("/api/tokens", methods=["POST"])
@login_required
def create_token():
    """Create a new API token for current user"""
    data = request.get_json() or {}
    name = data.get("name", "Default Token")
    
    # Generate secure token
    token = secrets.token_urlsafe(48)  # 64 characters
    
    api_token = ApiToken(
        user_id=current_user.id,
        token=token,
        name=name
    )
    db.session.add(api_token)
    db.session.commit()
    
    return jsonify({
        "id": api_token.id,
        "token": token,  # Only return full token on creation
        "name": api_token.name,
        "created_at": api_token.created_at.isoformat(),
        "message": "Token created successfully. Save this token - it won't be shown again!"
    }), 201


@auth_bp.route("/api/tokens/<int:token_id>", methods=["DELETE"])
@login_required
def delete_token(token_id):
    """Delete (deactivate) an API token"""
    api_token = ApiToken.query.filter_by(id=token_id, user_id=current_user.id).first()
    
    if not api_token:
        return jsonify({"error": "Token not found"}), 404
    
    api_token.is_active = False
    db.session.commit()
    
    return jsonify({"message": "Token deactivated successfully"})


@auth_bp.route("/api/tokens/<int:token_id>", methods=["PUT"])
@login_required
def update_token(token_id):
    """Update token name"""
    api_token = ApiToken.query.filter_by(id=token_id, user_id=current_user.id).first()
    
    if not api_token:
        return jsonify({"error": "Token not found"}), 404
    
    data = request.get_json() or {}
    if "name" in data:
        api_token.name = data["name"]
        db.session.commit()
    
    return jsonify(api_token.as_dict())

