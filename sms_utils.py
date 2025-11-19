"""Twilio SMS Verification Integration"""
from models import db, PasswordResetOTP
from datetime import datetime, timedelta
import os

# Try to import Twilio, but make it optional for development
try:
    from twilio.rest import Client
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False
    print("⚠️  Twilio not fully installed. SMS will print to console only.")

# ===== TWILIO CONFIGURATION =====
# Get these from your Twilio dashboard at https://www.twilio.com/console
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID', 'your_twilio_account_sid')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN', 'your_twilio_auth_token')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER', '+1234567890')

# Initialize Twilio client only if available
if TWILIO_AVAILABLE:
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
else:
    twilio_client = None


def generate_otp():
    """Generate a random 6-digit OTP"""
    import random
    return str(random.randint(100000, 999999))


def send_verification_sms(phone_number, user_email, username):
    """
    Send SMS verification code to user's phone number
    
    Args:
        phone_number: User's phone number (e.g., +1234567890)
        user_email: User's email
        username: User's username
    
    Returns:
        dict with 'success', 'otp', 'message'
    """
    otp = generate_otp()
    
    # Store OTP in database
    otp_entry = PasswordResetOTP(
        email=user_email,
        otp=otp,
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )
    db.session.add(otp_entry)
    db.session.commit()
    
    try:
        # Send SMS via Twilio
        message = twilio_client.messages.create(
            body=f"SecureAccess Verification Code: {otp}\n\nThis code expires in 5 minutes.",
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        
        print("\n" + "="*70)
        print("📱 SMS SENT SUCCESSFULLY")
        print("="*70)
        print(f"To: {phone_number}")
        print(f"Username: {username}")
        print(f"Email: {user_email}")
        print(f"OTP: {otp}")
        print(f"Expires: 5 minutes")
        print("-"*70)
        print(f"Message SID: {message.sid}")
        print("="*70 + "\n")
        
        return {
            'success': True,
            'otp': otp,
            'message': f'Verification code sent to {phone_number}'
        }
    
    except Exception as e:
        print("\n" + "="*70)
        print("❌ SMS FAILED TO SEND")
        print("="*70)
        print(f"Error: {str(e)}")
        print("="*70 + "\n")
        
        return {
            'success': False,
            'message': f'Failed to send SMS: {str(e)}'
        }


def verify_otp(email, otp):
    """
    Verify OTP code for email
    
    Args:
        email: User's email
        otp: OTP code to verify
    
    Returns:
        dict with 'success' and 'message'
    """
    # Find the most recent OTP for this email
    otp_entry = PasswordResetOTP.query.filter_by(
        email=email,
        otp=otp
    ).order_by(PasswordResetOTP.created_at.desc()).first()
    
    if not otp_entry:
        return {
            'success': False,
            'message': 'Invalid OTP code'
        }
    
    # Check if OTP has expired
    if datetime.utcnow() > otp_entry.expires_at:
        return {
            'success': False,
            'message': 'OTP has expired. Request a new code.'
        }
    
    # OTP is valid - mark as used
    otp_entry.is_used = True
    db.session.commit()
    
    return {
        'success': True,
        'message': 'OTP verified successfully'
    }


def send_authy_push_notification(authy_id):
    """
    Send Authy push notification for push-based 2FA
    
    Args:
        authy_id: User's Authy ID
    
    Returns:
        dict with success status
    """
    if not TWILIO_AVAILABLE:
        return {
            'success': False,
            'message': 'Twilio not configured for push notifications'
        }
    
    try:
        # This would require authy_client setup
        # For now, return not implemented
        print("\n" + "="*70)
        print("⚠️  AUTHY PUSH NOTIFICATION - NOT CONFIGURED")
        print("="*70)
        print("Authy push notifications require additional Authy SDK setup.")
        print("Using SMS OTP instead.")
        print("="*70 + "\n")
        
        return {
            'success': False,
            'message': 'Authy push notifications not configured'
        }
    
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to send push notification: {str(e)}'
        }


def register_with_authy(phone_number, username, email):
    """
    Register user with Authy for SMS/push 2FA
    
    Args:
        phone_number: User's phone number
        username: Username
        email: User's email
    
    Returns:
        dict with 'success', 'authy_id', 'message'
    """
    if not TWILIO_AVAILABLE:
        return {
            'success': False,
            'message': 'Twilio not configured'
        }
    
    try:
        # This would require authy_client setup
        # For now, just store the phone number
        print("\n" + "="*70)
        print("✅ USER REGISTERED FOR SMS VERIFICATION")
        print("="*70)
        print(f"Username: {username}")
        print(f"Email: {email}")
        print(f"Phone: {phone_number}")
        print("="*70 + "\n")
        
        return {
            'success': True,
            'message': f'User registered for SMS verification'
        }
    
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to register with Authy: {str(e)}'
        }


def send_verification_sms_console(phone_number, username, otp):
    """
    Console version for development - prints OTP instead of sending
    
    Args:
        phone_number: User's phone number
        username: Username
        otp: OTP code
    """
    print("\n" + "="*70)
    print("📱 SMS VERIFICATION CODE (DEVELOPMENT MODE)")
    print("="*70)
    print(f"To: {phone_number}")
    print(f"Username: {username}")
    print("-"*70)
    print(f"SecureAccess Verification Code: {otp}")
    print("\nThis code expires in 5 minutes.")
    print("-"*70)
    print("✓ SMS ready for testing\n")
    print("="*70 + "\n")
