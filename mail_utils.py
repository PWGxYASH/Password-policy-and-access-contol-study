from datetime import datetime, timedelta
import random
from models import db, PasswordResetOTP

def generate_otp():
    return str(random.randint(100000, 999999))

def send_verification_email(mail, recipient_email, verification_token):
    """Send email verification link - prints to console for development"""
    verification_url = f"http://localhost:5000/verify-email/{verification_token}"
    
    print("\n" + "="*70, flush=True)
    print("📧 EMAIL: VERIFICATION EMAIL", flush=True)
    print("="*70, flush=True)
    print(f"To: {recipient_email}", flush=True)
    print(f"Subject: Verify Your Email - SecureAccess", flush=True)
    print("-"*70, flush=True)
    print("Welcome to SecureAccess!", flush=True)
    print("\nPlease verify your email by clicking the link below:", flush=True)
    print(f"\n🔗 {verification_url}", flush=True)
    print("\nThis link expires in 24 hours.", flush=True)
    print("-"*70, flush=True)
    print("✓ Verification email ready for {}\n".format(recipient_email), flush=True)
    
    return True


def send_otp_email(mail, recipient_email):
    """Send OTP for password reset - prints to console for development"""
    otp = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=5)

    # Store OTP in DB
    otp_entry = PasswordResetOTP(email=recipient_email, otp=otp, expires_at=expires_at)
    db.session.add(otp_entry)
    db.session.commit()

    print("\n" + "="*70, flush=True)
    print("📧 EMAIL: PASSWORD RESET OTP", flush=True)
    print("="*70, flush=True)
    print(f"To: {recipient_email}", flush=True)
    print(f"Subject: Your Password Reset Code - SecureAccess", flush=True)
    print("-"*70, flush=True)
    print("Your OTP for password reset is:", flush=True)
    print(f"\n🔐 {otp}", flush=True)
    print("\nThis code expires in 5 minutes.", flush=True)
    print("-"*70, flush=True)
    print("✓ OTP email ready for {}\n".format(recipient_email), flush=True)
    
    return otp


def send_password_reset_notification(mail, recipient_email, username):
    """Send notification that password was changed - prints to console"""
    print("\n" + "="*70)
    print("📧 EMAIL: PASSWORD CHANGED NOTIFICATION")
    print("="*70)
    print(f"To: {recipient_email}")
    print(f"Subject: Your Password Has Been Changed - SecureAccess")
    print("-"*70)
    print(f"Hi {username},")
    print("\nYour password has been successfully changed.")
    print("-"*70)
    print("✓ Password notification email ready for {}\n".format(recipient_email))
    
    return True


def send_account_locked_notification(mail, recipient_email, username):
    """Send notification that account was locked - prints to console"""
    print("\n" + "="*70)
    print("📧 EMAIL: ACCOUNT LOCKED NOTIFICATION")
    print("="*70)
    print(f"To: {recipient_email}")
    print(f"Subject: Your Account Has Been Locked - SecureAccess")
    print("-"*70)
    print(f"Hi {username},")
    print("\nYour account has been locked due to multiple failed login attempts.")
    print("Your account will automatically unlock in 30 minutes.")
    print("-"*70)
    print("✓ Account locked notification email ready for {}\n".format(recipient_email))
    
    return True


def send_email_verified_confirmation(mail, recipient_email, username):
    """Send confirmation that email was verified - prints to console"""
    print("\n" + "="*70, flush=True)
    print("📧 EMAIL: EMAIL VERIFICATION CONFIRMATION", flush=True)
    print("="*70, flush=True)
    print(f"To: {recipient_email}", flush=True)
    print(f"Subject: Your Email Has Been Verified - SecureAccess", flush=True)
    print("-"*70, flush=True)
    print(f"Hi {username},", flush=True)
    print("\nYour email has been successfully verified!", flush=True)
    print("You can now log in to your account with your credentials.", flush=True)
    print("-"*70, flush=True)
    print("✓ Email verification confirmation ready for {}\n".format(recipient_email), flush=True)
    
    return True
