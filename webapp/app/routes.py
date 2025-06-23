"""
routes.py - Web routes for displaying network hosts and details.
"""

from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, logout_user
import logging
import sys
import ipaddress
from app import app, db
from app.models import Host, Port, ChangeLog, User
from datetime import datetime, timedelta


@app.route("/host/<int:host_id>")
@login_required
def host_detail(host_id):
    host = Host.query.get_or_404(host_id)
    history = (
        ChangeLog.query.filter_by(mac=host.mac)
        .order_by(ChangeLog.timestamp.desc())
        .all()
    )
    return render_template("host_detail.html", host=host, history=history)


@app.route("/hosts")
@login_required
def hosts():
    """Display all hosts sorted by last_seen."""
    #    hosts = Host.query.all()
    hosts = Host.query.all()
    hosts = sorted(
        hosts,
        key=lambda h: ipaddress.IPv4Address(h.ip)
        if h.ip
        else ipaddress.IPv4Address("0.0.0.0"),
    )
    return render_template("hosts.html", hosts=hosts)


@app.route("/")
@login_required
def index():
    total_hosts = Host.query.count()
    total_macs = db.session.query(Host.mac).distinct().count()
    total_ports = Port.query.count()
    latest_seen = db.session.query(db.func.max(Host.last_seen)).scalar()
    last_24h = Host.query.filter(
        Host.last_seen >= datetime.utcnow() - timedelta(days=1)
    ).count()
    return render_template(
        "index.html",
        total_hosts=total_hosts,
        total_macs=total_macs,
        total_ports=total_ports,
        latest_seen=latest_seen,
        last_24h=last_24h,
    )


@app.route("/host/<int:host_id>/edit", methods=["GET", "POST"])
@login_required
def edit_host(host_id):
    host = Host.query.get_or_404(host_id)
    history = (
        ChangeLog.query.filter_by(mac=host.mac)
        .order_by(ChangeLog.timestamp.desc())
        .all()
    )
    if request.method == "POST":
        host.comments = request.form.get("comments")
        host.custom_name = request.form.get("custom_name")
        db.session.commit()
        flash("Host updated")
        return redirect(url_for("edit_host", host_id=host.id))
    return render_template("host_detail.html", host=host, history=history)


@app.route("/changelog")
@login_required
def changelog():
    entries = ChangeLog.query.order_by(ChangeLog.timestamp.desc()).limit(100).all()
    return render_template("changelog.html", entries=entries)


@app.route("/host/delete/<int:host_id>", methods=["POST"])
@login_required
def delete_host(host_id):
    host = Host.query.get_or_404(host_id)
    db.session.delete(host)
    db.session.commit()
    flash(f"Host {host.mac} deleted successfully.")
    return redirect(url_for("hosts"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("index"))
        flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
