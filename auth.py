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

# ------------------------------
# Registration (standard + SMS)
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

# ------------------------------
# Login Route
# ------------------------------
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('auth.login'))

        session['user_id'] = user.id
        user.last_login = datetime.utcnow()  # Update last login
        db.session.commit()

        audit = AuditLog(user_id=user.id, action="login", timestamp=datetime.utcnow())
        db.session.add(audit)
        db.session.commit()

        flash("Logged in successfully", "success")
        return redirect(url_for('auth.dashboard'))

    return render_template('login.html')

# ------------------------------
# Dashboard Route
# ------------------------------
@auth_bp.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    password_expiry_warning = None
    if user.is_password_expired():
        password_expiry_warning = "Your password has expired! Please change it immediately."
    return render_template('dashboard.html', user=user, password_expiry_warning=password_expiry_warning)

# ------------------------------
# Add / Update Phone Number
# ------------------------------
@auth_bp.route('/add_phone', methods=['GET', 'POST'])
@login_required
def add_phone():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        phone_number = request.form['phone_number']
        if User.query.filter_by(phone_number=phone_number).first():
            flash('Phone number already in use.', 'danger')
            return redirect(url_for('auth.add_phone'))
        user.phone_number = phone_number
        user.phone_verified = False
        db.session.commit()

        otp = generate_otp()
        otp_entry = PasswordResetOTP(
            email=user.username,
            otp=otp,
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        db.session.add(otp_entry)
        db.session.commit()
        print(f"\n📱 OTP for {user.username} ({phone_number}): {otp}\nExpires in 5 minutes\n")
        flash('Phone number added! OTP sent to console.', 'success')
        return redirect(url_for('auth.verify_sms_otp', user_id=user.id))

    return render_template('add_phone.html', user=user)

# ------------------------------
# Verify SMS OTP
# ------------------------------
@auth_bp.route('/verify_sms/<int:user_id>', methods=['GET', 'POST'])
@login_required
def verify_sms_otp(user_id):
    user = User.query.get(user_id)
    if request.method == 'POST':
        otp_input = request.form['otp']
        otp_entry = PasswordResetOTP.query.filter_by(email=user.username).order_by(PasswordResetOTP.created_at.desc()).first()
        if not otp_entry or otp_entry.expires_at < datetime.utcnow():
            flash('OTP expired or not found', 'danger')
            return redirect(url_for('auth.verify_sms_otp', user_id=user.id))
        if otp_entry.otp == otp_input:
            user.phone_verified = True
            db.session.commit()
            flash('Phone number verified successfully!', 'success')
            return redirect(url_for('auth.dashboard'))
        else:
            flash('Invalid OTP', 'danger')
            return redirect(url_for('auth.verify_sms_otp', user_id=user.id))

    return render_template('verify_sms.html', user=user)
