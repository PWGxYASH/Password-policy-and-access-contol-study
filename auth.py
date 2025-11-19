from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models import db, User, PasswordResetOTP
from utils import password_policy
from mail_utils import send_otp_email
from flask_mail import Mail
from datetime import datetime

auth_bp = Blueprint('auth', __name__)
mail = Mail()

# ===== Basic Auth Routes =====

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')
        
        # Validate password policy
        valid, message = password_policy(password)
        if not valid:
            flash(message, 'danger')
            return render_template('register.html')
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('login.html')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Welcome, {user.username}!', 'success')
            return redirect(url_for('auth.dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('login.html')


@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)


# ===== Password Reset Routes =====

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email not registered.', 'danger')
            return render_template('forgot_password.html')

        send_otp_email(mail, email)
        flash('An OTP has been sent to your email.', 'info')
        return redirect(url_for('auth.verify_otp', email=email))
    return render_template('forgot_password.html')


@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email')
    if request.method == 'POST':
        otp = request.form['otp']
        record = PasswordResetOTP.query.filter_by(email=email).order_by(PasswordResetOTP.id.desc()).first()

        if record and record.is_valid(otp):
            flash('OTP verified successfully. You can reset your password.', 'success')
            return redirect(url_for('auth.reset_password', email=email))
        else:
            flash('Invalid or expired OTP.', 'danger')
            return render_template('verify_otp.html', email=email)
    return render_template('verify_otp.html', email=email)


@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    email = request.args.get('email')
    if request.method == 'POST':
        new_password = request.form['password']
        valid, message = password_policy(new_password)
        if not valid:
            flash(message, 'danger')
            return render_template('reset_password.html', email=email)

        user = User.query.filter_by(email=email).first()
        user.set_password(new_password)
        db.session.commit()
        flash('Password reset successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html', email=email)
