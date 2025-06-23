
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import logging
import sys
from dotenv import load_dotenv
import os

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Load environment variables from .env file
load_dotenv()

DB_PATH = os.getenv("DB_PATH", "/db/network.db")
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "CHANGE_ME")

if not SECRET_KEY or SECRET_KEY == "CHANGE_ME":
    raise ValueError("Please set a valid SECRET_KEY in your environment variables.")

if not ADMIN_PASSWORD or ADMIN_PASSWORD == "CHANGE_ME":
    raise ValueError("Please set a valid ADMIN_PASSWORD in your environment variables.")

# Initialize Flask app and database
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = SECRET_KEY
db = SQLAlchemy(app)

from app.models import User
from app import routes

# Create tables on startup
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        u = User(username="admin")
        u.set_password(ADMIN_PASSWORD)
        db.session.add(u)
        db.session.commit()

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Load user function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
