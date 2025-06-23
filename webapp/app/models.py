"""
models.py - SQLAlchemy models for the webapp.
"""

from app import db
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


class Host(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(64), unique=True, nullable=False)  # Clave única
    ip = db.Column(db.String(64), nullable=True)  # Puede cambiar con el tiempo
    vendor = db.Column(db.String(128))
    hostname = db.Column(db.String(128))
    os = db.Column(db.String(128))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    custom_name = db.Column(db.String(100), nullable=True)
    comments = db.Column(db.Text, nullable=True)
    ports = db.relationship("Port", backref="host", cascade="all, delete-orphan")
    status = db.Column(db.String(10), default="offline")  # "online" or "offline"


class Port(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("host.id"), nullable=False)
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    state = db.Column(db.String(20))
    service = db.Column(db.String(128))
    product = db.Column(db.String(128))
    version = db.Column(db.String(128))


class ChangeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    mac = db.Column(db.String(64), nullable=False)
    old_ip = db.Column(db.String(64), nullable=True)
    new_ip = db.Column(db.String(64), nullable=True)
    change_type = db.Column(db.String(32), nullable=False)  # "new", "ip_change", etc.


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
