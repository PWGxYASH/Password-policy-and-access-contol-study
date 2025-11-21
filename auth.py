# auth.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from ext import db
from models import User, PasswordResetOTP, AuditLog
from datetime import datetime, timedelta
from utils import password_policy
from decorators import login_required, role_required

auth_bp = Blueprint('auth', __name__, template_folder='templates')


# ------------------------------
# Helper: Generate OTP
# ------------------------------
def generate_otp():
    import random
    return str(random.randint(100000, 999999))


# ------------------------------
# Registration Routes
# ------------------------------
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        phone = request.form['phone']

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.register'))

        user = User(username=username, phone_number=phone, role='user')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # Generate OTP
        otp_code = generate_otp()
        otp_entry = PasswordResetOTP(
            email=username,
            otp=otp_code,
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        db.session.add(otp_entry)
        db.session.commit()

        print(f"[OTP] {username}: {otp_code}")
        flash('User registered! OTP sent (check console).', 'success')
        return redirect(url_for("auth.verify_otp", email=username))

    return render_template("register.html")


@auth_bp.route('/register_sms', methods=['GET', 'POST'])
def register_sms():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        phone_number = request.form['phone_number']

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.register_sms'))

        if User.query.filter_by(phone_number=phone_number).first():
            flash('Phone number already registered!', 'danger')
            return redirect(url_for('auth.register_sms'))

        valid, message = password_policy(password)
        if not valid:
            flash(message, 'danger')
            return redirect(url_for('auth.register_sms'))

        user = User(username=username, phone_number=phone_number, role='user')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        otp_code = generate_otp()
        otp_entry = PasswordResetOTP(
            email=username,
            otp=otp_code,
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        db.session.add(otp_entry)
        db.session.commit()

        print(f"[SMS OTP] {username} ({phone_number}): {otp_code}")
        flash("User registered! OTP sent to console.", "success")
        return redirect(url_for("auth.verify_sms_otp", user_id=user.id))

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
        user.last_login = datetime.utcnow()
        db.session.commit()

        audit = AuditLog(user_id=user.id, action="login", timestamp=datetime.utcnow())
        db.session.add(audit)
        db.session.commit()

        flash("Logged in successfully", "success")
        return redirect(url_for('auth.dashboard'))

    return render_template('login.html')


# ------------------------------
# Dashboard
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
# SMS OTP Verification
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


# ------------------------------
# Logout
# ------------------------------
@auth_bp.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('auth.login'))


# ------------------------------
# Forgot Password / Reset
# ------------------------------
@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['email']  # phone/email
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('auth.forgot_password'))

        # Generate OTP
        otp_code = generate_otp()
        otp_entry = PasswordResetOTP(
            email=user.username,
            otp=otp_code,
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        db.session.add(otp_entry)
        db.session.commit()

        print(f"\n📱 OTP for password reset ({user.username}): {otp_code}\nExpires in 5 minutes\n")
        flash('OTP sent! Check console.', 'info')
        return redirect(url_for('auth.verify_otp', email=user.username))

    return render_template('reset_password.html')


@auth_bp.route('/verify_otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    user = User.query.filter_by(username=email).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        otp_input = request.form['otp']
        otp_entry = PasswordResetOTP.query.filter_by(email=email).order_by(PasswordResetOTP.created_at.desc()).first()

        if not otp_entry or otp_entry.expires_at < datetime.utcnow():
            flash('OTP expired or not found.', 'danger')
            return redirect(url_for('auth.forgot_password'))

        if otp_entry.otp == otp_input:
            flash('OTP verified! You can now reset your password.', 'success')
            return redirect(url_for('auth.reset_password_form', email=email))
        else:
            flash('Invalid OTP', 'danger')
            return redirect(url_for('auth.verify_otp', email=email))

    return render_template('verify_otp.html', user=user)




@auth_bp.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    user = User.query.filter_by(username=email).first()

    # Only allow if OTP verified
    if 'otp_verified_user' not in session or session['otp_verified_user'] != user.id:
        flash('Please verify OTP first!', 'warning')
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        valid, message = password_policy(password)
        if not valid:
            flash(message, 'danger')
            return redirect(url_for('auth.reset_password', email=email))

        user.set_password(password)
        db.session.commit()

        flash('Password reset successfully!', 'success')
        session.pop('otp_verified_user', None)  # ✅ Clear session flag
        return redirect(url_for('auth.login'))

    return render_template('reset_password_form.html', user=user)

@auth_bp.route('/reset_password_form/<email>', methods=['GET', 'POST'])
def reset_password_form(email):
    user = User.query.filter_by(username=email).first()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        new_password = request.form['password']
        valid, message = password_policy(new_password)
        if not valid:
            flash(message, 'danger')
            return redirect(url_for('auth.reset_password_form', email=email))

        user.set_password(new_password)
        db.session.commit()
        flash('Password has been reset successfully! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password_form.html', user=user)


# ------------------------------
# Admin Routes
# ------------------------------
@auth_bp.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@auth_bp.route('/admin/logs')
@login_required
@role_required('admin')
def admin_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin/audit_logs.html', logs=logs)


@auth_bp.route('/request_new_email_otp/<email>')
def request_new_email_otp(email):
    user = User.query.filter_by(username=email).first()
    if not user:
        flash("User not found", "danger")
        return redirect(url_for("auth.login"))

    otp_code = generate_otp()
    otp_entry = PasswordResetOTP(
        email=user.username,
        otp=otp_code,
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )
    db.session.add(otp_entry)
    db.session.commit()

    print(f"[NEW EMAIL OTP] {user.username}: {otp_code}")
    flash("A new OTP has been sent!", "success")
    return redirect(url_for('auth.verify_otp', email=user.username))

@auth_bp.route('/user_details/<int:user_id>')
def user_details(user_id):
    return f"User {user_id} details"




