from flask_mail import Message
from datetime import datetime, timedelta
import random
from models import db, PasswordResetOTP

def generate_otp():
    return str(random.randint(100000, 999999))

def send_verification_email(mail, recipient_email, verification_token):
    """Send email verification link"""
    try:
        verification_url = f"http://localhost:5000/verify-email/{verification_token}"
        
        msg = Message(
            "Verify Your Email - SecureAccess",
            sender="noreply@secureaccess.com",
            recipients=[recipient_email]
        )
        msg.body = f"""
Welcome to SecureAccess!

Please verify your email by clicking the link below:

{verification_url}

This link expires in 24 hours.

If you didn't sign up for this account, please ignore this email.

Best regards,
SecureAccess Team
"""
        msg.html = f"""
<html>
    <body style="font-family: Arial, sans-serif;">
        <h2>Welcome to SecureAccess!</h2>
        <p>Please verify your email by clicking the button below:</p>
        <a href="{verification_url}" style="background-color: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email</a>
        <p>Or copy this link: <code>{verification_url}</code></p>
        <p style="color: #999; font-size: 12px;">This link expires in 24 hours.</p>
    </body>
</html>
"""
        try:
            mail.send(msg)
            print(f"✓ Verification email sent to {recipient_email}")
        except Exception as e:
            print(f"⚠ Email send failed (connection issue): {str(e)}")
            print(f"📧 EMAIL CONTENT:\n{msg.body}\n")
        return True
    except Exception as e:
        print(f"✗ Failed to create verification email: {str(e)}")
        return False


def send_otp_email(mail, recipient_email):
    """Send OTP for password reset"""
    try:
        otp = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=5)

        # Store OTP in DB
        otp_entry = PasswordResetOTP(email=recipient_email, otp=otp, expires_at=expires_at)
        db.session.add(otp_entry)
        db.session.commit()

        # Send email
        msg = Message(
            "Your Password Reset Code - SecureAccess",
            sender="noreply@secureaccess.com",
            recipients=[recipient_email]
        )
        msg.body = f"""
SecureAccess Password Reset

Your OTP for password reset is:

{otp}

This code expires in 5 minutes. If you didn't request a password reset, please ignore this email.

Best regards,
SecureAccess Team
"""
        msg.html = f"""
<html>
    <body style="font-family: Arial, sans-serif;">
        <h2>Password Reset Request</h2>
        <p>Your OTP for password reset is:</p>
        <h1 style="letter-spacing: 5px; color: #667eea;">{otp}</h1>
        <p style="color: #999;">This code expires in 5 minutes.</p>
        <p style="font-size: 12px;">If you didn't request this, please ignore this email.</p>
    </body>
</html>
"""
        try:
            mail.send(msg)
            print(f"✓ OTP email sent to {recipient_email}")
        except Exception as e:
            print(f"⚠ Email send failed (connection issue): {str(e)}")
            print(f"📧 OTP CODE: {otp}\n")
        return otp
    except Exception as e:
        print(f"✗ Failed to send OTP email: {str(e)}")
        return None


def send_password_reset_notification(mail, recipient_email, username):
    """Send notification that password was changed"""
    try:
        msg = Message(
            "Your Password Has Been Changed - SecureAccess",
            sender="noreply@secureaccess.com",
            recipients=[recipient_email]
        )
        msg.body = f"""
Hi {username},

Your password has been successfully changed.

If you didn't make this change, please reset your password immediately at:
http://localhost:5000/forgot-password

Best regards,
SecureAccess Team
"""
        msg.html = f"""
<html>
    <body style="font-family: Arial, sans-serif;">
        <h2>Password Changed</h2>
        <p>Hi {username},</p>
        <p>Your password has been successfully changed.</p>
        <p style="color: #999; font-size: 12px;">If you didn't make this change, please reset your password immediately.</p>
    </body>
</html>
"""
        try:
            mail.send(msg)
            print(f"✓ Password reset notification sent to {recipient_email}")
        except Exception as e:
            print(f"⚠ Email send failed: {str(e)}")
        return True
    except Exception as e:
        print(f"✗ Failed to send password notification: {str(e)}")
        return False


def send_account_locked_notification(mail, recipient_email, username):
    """Send notification that account was locked"""
    try:
        msg = Message(
            "Your Account Has Been Locked - SecureAccess",
            sender="noreply@secureaccess.com",
            recipients=[recipient_email]
        )
        msg.body = f"""
Hi {username},

Your account has been locked due to multiple failed login attempts.

Your account will automatically unlock in 30 minutes.

If this wasn't you, please contact support immediately.

Best regards,
SecureAccess Team
"""
        msg.html = f"""
<html>
    <body style="font-family: Arial, sans-serif;">
        <h2>Account Locked</h2>
        <p>Hi {username},</p>
        <p>Your account has been locked due to multiple failed login attempts.</p>
        <p style="color: #999; font-size: 12px;">Your account will automatically unlock in 30 minutes.</p>
    </body>
</html>
"""
        try:
            mail.send(msg)
            print(f"✓ Account locked notification sent to {recipient_email}")
        except Exception as e:
            print(f"⚠ Email send failed: {str(e)}")
        return True
    except Exception as e:
        print(f"✗ Failed to send account locked notification: {str(e)}")
        return False
