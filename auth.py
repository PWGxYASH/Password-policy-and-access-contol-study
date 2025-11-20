# auth.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ext import db
from models import User, PasswordResetOTP, AuditLog
from datetime import datetime, timedelta
from utils import password_policy  # make sure this exists

auth_bp = Blueprint('auth', __name__, template_folder='templates')

# ------------------------------
# Helper: Generate OTP
# ------------------------------
def generate_otp():
    import random
    return str(random.randint(100000, 999999))

# ------------------------------
# Decorators
# ------------------------------
def login_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('auth.login'))
        return func(*args, **kwargs)
    return wrapper

def admin_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('auth.login'))
        user = User.query.get(session['user_id'])
        if user.role != 'admin':
            flash('Access denied.', 'danger')
            return redirect(url_for('auth.dashboard'))
        return func(*args, **kwargs)
    return wrapper

# ------------------------------
# Standard Registration
# ------------------------------
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.register'))

        valid, message = password_policy(password)
        if not valid:
            flash(message, 'danger')
            return redirect(url_for('auth.register'))

        new_user = User(username=username, role='user')
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')

# ------------------------------
# SMS Registration
# ------------------------------
@auth_bp.route('/register_sms', methods=['GET', 'POST'])
def register_sms():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        phone_number = request.form['phone_number']

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.register_sms'))

        valid, message = password_policy(password)
        if not valid:
            flash(message, 'danger')
            return redirect(url_for('auth.register_sms'))

        new_user = User(username=username, phone_number=phone_number, role='user')
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        otp = generate_otp()
        otp_entry = PasswordResetOTP(
            email=username,
            otp=otp,
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        db.session.add(otp_entry)
        db.session.commit()

        print(f"\n📱 SMS OTP for {username} ({phone_number}): {otp}\nExpires in 5 minutes\n")

        flash(f"User registered! OTP sent to console for {username}.", 'success')
        return redirect(url_for('auth.login'))

    return render_template('register_sms.html')
