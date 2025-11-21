# models.py
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from ext import db  # shared instance
from sqlalchemy import inspect

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    phone_number = db.Column(db.String(20), unique=True, nullable=True)
    phone_verified = db.Column(db.Boolean, default=False)

    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    last_password_changed = db.Column(db.DateTime, default=datetime.utcnow)
    password_expiry_date = db.Column(db.DateTime, nullable=True)

    last_login = db.Column(db.DateTime, nullable=True)  # added last_login

    two_factor_enabled = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(32), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        self.last_password_changed = datetime.utcnow()
        self.password_expiry_date = datetime.utcnow() + timedelta(days=90)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_account_locked(self):
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        elif self.locked_until and datetime.utcnow() >= self.locked_until:
            self.locked_until = None
            self.failed_attempts = 0
            db.session.commit()
        return False

    def increment_failed_attempts(self):
        self.failed_attempts += 1
        if self.failed_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)
        db.session.commit()

    def reset_failed_attempts(self):
        self.failed_attempts = 0
        self.locked_until = None
        db.session.commit()

    def is_password_expired(self):
        return self.password_expiry_date and datetime.utcnow() > self.password_expiry_date

# OTP table for SMS verification or password resets
class PasswordResetOTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# --- Auto-create last_login if missing (SQLite / dev friendly) ---
def add_missing_columns():
    inspector = inspect(db.engine)
    columns = [c['name'] for c in inspector.get_columns('user')]
    if 'last_login' not in columns:
        with db.engine.connect() as conn:
            conn.execute('ALTER TABLE user ADD COLUMN last_login DATETIME;')
            conn.commit()
