from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Host(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(64), unique=True, nullable=False)
    ip = db.Column(db.String(64), nullable=True)
    vendor = db.Column(db.String(128))
    hostname = db.Column(db.String(128))
    os = db.Column(db.String(128))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    custom_name = db.Column(db.String(100), nullable=True)
    comments = db.Column(db.Text, nullable=True)
    ports = db.relationship('Port', backref='host', cascade="all, delete-orphan")
    status = db.Column(db.String(10), default="offline")  # "online" or "offline"

class Port(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'), nullable=False)
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    state = db.Column(db.String(20))
    service = db.Column(db.String(128))
    product = db.Column(db.String(128))
    version = db.Column(db.String(128))

class HostHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip = db.Column(db.String(64))
    hostname = db.Column(db.String(128))

class ChangeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    mac = db.Column(db.String(64), nullable=False)
    old_ip = db.Column(db.String(64), nullable=True)
    new_ip = db.Column(db.String(64), nullable=True)
    change_type = db.Column(db.String(32), nullable=False)  # "new", "ip_change", etc.


def init_app(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()


def get_all_known_macs():
    return [host.mac for host in Host.query.filter(Host.mac != None).all()]


def save_host_history(host_id, ip=None, hostname=None):
    entry = HostHistory(
        host_id=host_id,
        ip=ip,
        hostname=hostname
    )
    db.session.add(entry)
    db.session.commit()


def insert_ports(host_id, ports):
    Port.query.filter_by(host_id=host_id).delete()
    for port in ports:
        p = Port(
            host_id=host_id,
            port=port["port"],
            protocol=port["protocol"],
            state=port["state"],
            service=port.get("service"),
            product=port.get("product"),
            version=port.get("version"),
        )
        db.session.add(p)
    db.session.commit()


def log_change(mac, change_type, old_ip=None, new_ip=None):
    log = ChangeLog(
        mac=mac,
        old_ip=old_ip,
        new_ip=new_ip,
        change_type=change_type
    )
    db.session.add(log)
    db.session.commit()


def insert_or_update_host(mac, ip=None, vendor=None, hostname=None, os_name=None):
    host = Host.query.filter_by(mac=mac).first()
    is_new = False
    ip_changed = False

    if not host:
        host = Host(mac=mac)
        is_new = True
        log_change(mac=mac, change_type="new", new_ip=ip)
    else:
        if ip and ip != host.ip:
            ip_changed = True
            log_change(mac=mac, change_type="ip_change", old_ip=host.ip, new_ip=ip)

    host.ip = ip
    host.vendor = vendor
    host.hostname = hostname
    host.os = os_name
    host.last_seen = datetime.utcnow()

    if is_new:
        db.session.add(host)

    db.session.commit()
    return is_new, ip_changed, host.id


def update_host_status(mac, online):
    """ Updates the 'status' field of a host."""
    host = Host.query.filter_by(mac=mac).first()
    if host:
        new_status = "online" if online else "offline"
        if host.status != new_status:
            host.status = new_status
            db.session.commit()
