import secrets
import time
from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from . import db


class User(UserMixin, db.Model):
    """Admin users only - for accessing admin panel"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    api_tokens = db.relationship('ApiToken', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def as_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_admin": self.is_admin,
            "created_at": self.created_at.isoformat(),
        }


class Client(db.Model):
    """Anonymous clients - identified by unique ID and hostname"""
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), unique=True, nullable=False, index=True)  # Unique random ID
    hostname = db.Column(db.String(255), nullable=True, index=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, onupdate=datetime.utcnow)
    
    # Relationships
    file_hashes = db.relationship('FileHash', backref='client', lazy=True, cascade='all, delete-orphan')
    monitored_folders = db.relationship('MonitoredFolder', backref='client', lazy=True, cascade='all, delete-orphan')
    alerts = db.relationship('FileIntegrity', backref='client', lazy=True, cascade='all, delete-orphan')
    
    @staticmethod
    def generate_client_id():
        """Generate a unique client ID"""
        return secrets.token_urlsafe(32)  # 43 characters, URL-safe
    
    def as_dict(self):
        return {
            "id": self.id,
            "client_id": self.client_id,
            "hostname": self.hostname,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class FileHash(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=True, index=True)  # Nullable for migration
    path = db.Column(db.String, nullable=False, index=True)
    hash_md5 = db.Column(db.String(32), nullable=False)
    file_size = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def as_dict(self):
        return {
            "id": self.id,
            "client_id": self.client_id,
            "path": self.path,
            "hash_md5": self.hash_md5,
            "file_size": self.file_size,
            "timestamp": self.timestamp.isoformat(),
        }


class MonitoredFolder(db.Model):
    """Tracks folders that are actively being monitored"""
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=True, index=True)  # Nullable for migration
    folder_path = db.Column(db.String, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_scan = db.Column(db.DateTime)
    
    def as_dict(self):
        return {
            "id": self.id,
            "client_id": self.client_id,
            "folder_path": self.folder_path,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "last_scan": self.last_scan.isoformat() if self.last_scan else None,
        }


class FileIntegrity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=True, index=True)  # Nullable for migration
    path = db.Column(db.String, nullable=False, index=True)
    initial_hash = db.Column(db.String(32), nullable=False)
    current_hash = db.Column(db.String(32))
    alert_type = db.Column(db.String, nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def as_dict(self):
        # Include client info if available
        client_info = {}
        if self.client_id and self.client:
            client_info = {
                "client_hostname": self.client.hostname,
                "client_id_str": self.client.client_id,
            }
        
        return {
            "id": self.id,
            "client_id": self.client_id,
            "path": self.path,
            "initial_hash": self.initial_hash,
            "current_hash": self.current_hash,
            "alert_type": self.alert_type,
            "timestamp": self.timestamp.isoformat(),
            **client_info,
        }


class ApiToken(db.Model):
    """API tokens for admin authentication (legacy - not used by clients)"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=True)  # Token name/description
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_used = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    # Relationship is defined in User model with backref
    
    def as_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "token": self.token[:8] + "..." if self.token else None,  # Only show first 8 chars
            "created_at": self.created_at.isoformat(),
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "is_active": self.is_active,
        }

