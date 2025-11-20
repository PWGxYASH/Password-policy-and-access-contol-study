from models import db, User
from datetime import datetime, timedelta
import random

# ===== OTP Functions =====

def generate_otp():
    """Generate a random 6-digit OTP"""
    return str(random.randint(100000, 999999))


def send_verification_otp_console(user):
    """
    Store OTP in user record and print to console for development/testing.
    """
    otp = generate_otp()
    user.sms_otp = otp
    user.sms_otp_expires_at = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()

    print("\n" + "="*50)
    print("📱 OTP (Console Mode) for Testing")
    print(f"Username: {user.username}")
    print(f"Phone: {user.phone_number}")
    print(f"OTP: {otp}")
    print("Expires in 5 minutes")
    print("="*50 + "\n")
    return otp


def verify_otp_console(user, otp_input):
    """Verify OTP entered by user"""
    if not user.sms_otp_expires_at or datetime.utcnow() > user.sms_otp_expires_at:
        return False, "OTP has expired. Request a new one."
    if user.sms_otp != otp_input:
        return False, "Invalid OTP code."
    
    # OTP valid
    user.sms_otp = None
    user.sms_otp_expires_at = None
    user.phone_verified = True
    db.session.commit()
    return True, "Phone number verified successfully!"
