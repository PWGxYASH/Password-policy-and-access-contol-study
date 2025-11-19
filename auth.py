from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from models import db, User, PasswordResetOTP, PasswordHistory, AuditLog, UserSession
from utils import password_policy
from sms_utils import send_verification_sms_console, verify_otp, send_verification_sms
from datetime import datetime, timedelta
from functools import wraps
import secrets
from flask import Flask
import os
auth_bp = Blueprint('auth', __name__)
# ===== Helper Functions =====

def get_client_ip():
    """Get client IP address from request"""
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ.get('HTTP_X_FORWARDED_FOR').split(',')[0]
    return request.environ.get('REMOTE_ADDR')

def log_audit(user_id, action, status="success", details=None):
    """Log audit event"""
    audit = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=get_client_ip(),
        device_info=request.user_agent.string,
        status=status,
        details=details
    )
    db.session.add(audit)
    db.session.commit()

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('auth.login'))
        user = User.query.get(session['user_id'])
        if user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('auth.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ===== Authentication Routes =====

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        # Validate inputs
        if not all([username, email, password]):
            flash('All fields are required.', 'danger')
            return render_template('register.html')
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return render_template('register.html')
        
        # Validate password policy
        valid, message = password_policy(password)
        if not valid:
            flash(message, 'danger')
            return render_template('register.html')
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        user.generate_verification_token()
        
        # Store initial password in history
        db.session.add(user)
        db.session.flush()  # Get user ID
        
        password_history = PasswordHistory(
            user_id=user.id,
            password_hash=user.password_hash
        )
        db.session.add(password_history)
        db.session.commit()
        
        # Email verification skipped - using SMS verification instead
        log_audit(user.id, "signup", "success")
        
        flash('Registration successful! Please use SMS verification to proceed.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')


@auth_bp.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    print("DEBUG: VERIFY ROUTE HIT")
    print("DEBUG: Token received:", token, flush=True)

    user = User.query.filter_by(verification_token=token).first()
    print("DEBUG: Found user:", user.email if user else None, flush=True)

    if not user:
        print("DEBUG: INVALID TOKEN", flush=True)
        flash('Invalid or expired verification link.', 'danger')
        return redirect(url_for('auth.login'))

    user.email_verified = True
    user.verification_token = None
    db.session.commit()

    print("DEBUG: Email VERIFIED ✔", flush=True)

    flash('Email verified successfully! You can now log in.', 'success')
    return redirect(url_for('auth.login'))





@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('login.html')
        
        user = User.query.filter_by(email=email).first()
        
        # Check if account is locked
        if user and user.is_account_locked():
            flash('Account is locked due to multiple failed login attempts. Try again in 30 minutes.', 'danger')
            log_audit(user.id, "failed_login", "failed", "Account locked")
            return render_template('login.html')
        
        # Check email verification
        if user and not user.email_verified:
            flash('Please verify your email before logging in. Check your inbox for the verification link.', 'warning')
            return render_template('login.html')
        
        # Check password expiration
        if user and user.is_password_expired():
            flash('Your password has expired. Please reset it.', 'warning')
            return redirect(url_for('auth.forgot_password'))
        
        # Validate credentials
        if user and user.check_password(password):
            # Create session
            user.reset_failed_attempts()
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            log_audit(user.id, "login", "success")
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('auth.dashboard'))
        else:
            if user:
                user.increment_failed_attempts()
                log_audit(user.id, "failed_login", "failed", "Invalid password")
                remaining = 5 - user.failed_attempts
                if remaining > 0:
                    flash(f'Invalid credentials. {remaining} attempts remaining.', 'danger')
                else:
                    flash('Account locked due to multiple failed attempts.', 'danger')
            else:
                log_audit(None, "failed_login", "failed", f"User not found: {email}")
                flash('Invalid email or password.', 'danger')
    
    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id')
    session.clear()
    if user_id:
        log_audit(user_id, "logout", "success")
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    password_expiry_warning = None
    
    if user.is_password_expired():
        password_expiry_warning = "Your password has expired. Please reset it."
    elif user.password_expiry_date:
        days_left = (user.password_expiry_date - datetime.utcnow()).days
        if days_left <= 7:
            password_expiry_warning = f"Your password will expire in {days_left} days."
    
    return render_template('dashboard.html', user=user, password_expiry_warning=password_expiry_warning)


# ===== Password Management Routes =====

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('If that email is registered, you will receive an OTP.', 'info')
            return render_template('forgot_password.html')

        send_otp_email(mail, email)
        log_audit(user.id, "password_reset_requested", "success")
        flash('An OTP has been sent to your email.', 'info')
        return redirect(url_for('auth.verify_otp', email=email))
    
    return render_template('forgot_password.html')


@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email', '').strip()
    
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        record = PasswordResetOTP.query.filter_by(email=email).order_by(PasswordResetOTP.id.desc()).first()

        if record and record.is_valid(otp):
            flash('OTP verified successfully. You can reset your password.', 'success')
            return redirect(url_for('auth.reset_password', email=email, verified='true'))
        else:
            flash('Invalid or expired OTP.', 'danger')
    
    return render_template('verify_otp.html', email=email)


@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    email = request.args.get('email', '').strip()
    verified = request.args.get('verified', '').lower() == 'true'
    
    if not email or not verified:
        flash('Invalid password reset link.', 'danger')
        return redirect(url_for('auth.forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', email=email)
        
        # Validate password policy
        valid, message = password_policy(new_password)
        if not valid:
            flash(message, 'danger')
            return render_template('reset_password.html', email=email)
        
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('auth.forgot_password'))
        
        # Check if new password is in history (last 5 passwords)
        recent_passwords = PasswordHistory.query.filter_by(user_id=user.id).order_by(
            PasswordHistory.changed_at.desc()
        ).limit(5).all()
        
        for history in recent_passwords:
            if user.check_password(new_password):
                flash('You cannot reuse one of your last 5 passwords.', 'danger')
                return render_template('reset_password.html', email=email)
        
        # Update password
        user.set_password(new_password)
        
        # Add to password history
        password_history = PasswordHistory(
            user_id=user.id,
            password_hash=user.password_hash
        )
        db.session.add(password_history)
        db.session.commit()
        
        log_audit(user.id, "password_reset", "success")
        flash('Password reset successful! Please log in with your new password.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('reset_password.html', email=email)


# ===== Admin Routes =====

@auth_bp.route('/admin/users')
@admin_required
def admin_users():
    """View all users"""
    users = User.query.all()
    return render_template('admin/users.html', users=users)


@auth_bp.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    """View user details and activity"""
    user = User.query.get_or_404(user_id)
    audit_logs = AuditLog.query.filter_by(user_id=user_id).order_by(AuditLog.created_at.desc()).limit(50).all()
    return render_template('admin/user_detail.html', user=user, audit_logs=audit_logs)


@auth_bp.route('/admin/audit-logs')
@admin_required
def admin_audit_logs():
    """View all audit logs"""
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
    return render_template('admin/audit_logs.html', logs=logs)


@auth_bp.route('/admin/user/<int:user_id>/lock', methods=['POST'])
@admin_required
def admin_lock_user(user_id):
    """Lock a user account"""
    user = User.query.get_or_404(user_id)
    user.locked_until = datetime.utcnow() + timedelta(days=1)
    db.session.commit()
    log_audit(session['user_id'], f"admin_lock_user_{user_id}", "success")
    flash(f'User {user.username} has been locked.', 'success')
    return redirect(url_for('auth.admin_user_detail', user_id=user_id))


# ===== SMS/Twilio Authy Routes =====

@auth_bp.route('/register-sms', methods=['GET', 'POST'])
def register_sms():
    """Register with SMS verification instead of email"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        password = request.form.get('password', '').strip()
        
        # Validate inputs
        if not all([username, phone_number, password]):
            flash('All fields are required.', 'danger')
            return render_template('register_sms.html')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return render_template('register_sms.html')
        
        if User.query.filter_by(phone_number=phone_number).first():
            flash('Phone number already registered.', 'danger')
            return render_template('register_sms.html')
        
        # Validate password policy
        valid, message = password_policy(password)
        if not valid:
            flash(message, 'danger')
            return render_template('register_sms.html')
        
        # Create new user with phone verification
        user = User(username=username, phone_number=phone_number)
        user.set_password(password)
        user.email_verified = True  # SMS verified, don't need email
        user.phone_verified = False  # Need to verify phone
        
        db.session.add(user)
        db.session.flush()
        
        # Store password in history
        password_history = PasswordHistory(
            user_id=user.id,
            password_hash=user.password_hash
        )
        db.session.add(password_history)
        db.session.commit()
        
        # Send SMS verification
        # Use console version for development
        from sms_utils import generate_otp
        otp = generate_otp()
        user.sms_otp = otp
        user.sms_otp_expires_at = datetime.utcnow() + timedelta(minutes=5)
        db.session.commit()
        
        # Print to console (development mode)
        send_verification_sms_console(phone_number, username, otp)
        
        log_audit(user.id, "sms_signup", "success")
        
        flash('Account created! Enter the OTP sent to your phone.', 'success')
        return redirect(url_for('auth.verify_sms_otp', user_id=user.id))
    
    return render_template('register_sms.html')


@auth_bp.route('/verify-sms/<int:user_id>', methods=['GET', 'POST'])
def verify_sms_otp(user_id):
    """Verify SMS OTP code"""
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        otp_code = request.form.get('otp', '').strip()
        
        if not otp_code:
            flash('Please enter the OTP code.', 'danger')
            return render_template('verify_sms.html', user=user)
        
        # Check if OTP is expired
        if not user.sms_otp_expires_at or datetime.utcnow() > user.sms_otp_expires_at:
            flash('OTP has expired. Request a new one.', 'danger')
            return redirect(url_for('auth.request_new_otp', user_id=user.id))
        
        # Check if OTP is correct
        if user.sms_otp != otp_code:
            flash('Invalid OTP code. Try again.', 'danger')
            return render_template('verify_sms.html', user=user)
        
        # OTP verified!
        user.phone_verified = True
        user.sms_otp = None
        user.sms_otp_expires_at = None
        db.session.commit()
        
        log_audit(user.id, "sms_verified", "success")
        flash('Phone number verified! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('verify_sms.html', user=user)


@auth_bp.route('/request-otp/<int:user_id>', methods=['GET'])
def request_new_otp(user_id):
    """Request a new OTP code"""
    user = User.query.get_or_404(user_id)
    
    # Generate new OTP
    from sms_utils import generate_otp
    otp = generate_otp()
    user.sms_otp = otp
    user.sms_otp_expires_at = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()
    
    # Print to console
    send_verification_sms_console(user.phone_number, user.username, otp)
    
    log_audit(user.id, "otp_requested", "success")
    flash('New OTP sent to your phone!', 'success')
    return redirect(url_for('auth.verify_sms_otp', user_id=user.id))





@auth_bp.route('/admin/user/<int:user_id>/unlock', methods=['POST'])
@admin_required
def admin_unlock_user(user_id):
    """Unlock a user account"""
    user = User.query.get_or_404(user_id)
    user.locked_until = None
    user.failed_attempts = 0
    db.session.commit()
    log_audit(session['user_id'], f"admin_unlock_user_{user_id}", "success")
    flash(f'User {user.username} has been unlocked.', 'success')
    return redirect(url_for('auth.admin_user_detail', user_id=user_id))


@auth_bp.route('/admin/user/<int:user_id>/force-password-reset', methods=['POST'])
@admin_required
def admin_force_password_reset(user_id):
    """Force user to reset password"""
    user = User.query.get_or_404(user_id)
    user.password_expiry_date = datetime.utcnow()
    db.session.commit()
    log_audit(session['user_id'], f"admin_force_password_reset_{user_id}", "success")
    flash(f'User {user.username} must reset password on next login.', 'success')
    return redirect(url_for('auth.admin_user_detail', user_id=user_id))


# ===== Helper Email Functions =====
# Email sending functions moved to mail_utils.py