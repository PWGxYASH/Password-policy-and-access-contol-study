from flask_mail import Message
from datetime import datetime, timedelta
import random
from models import db, PasswordResetOTP

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(mail, recipient_email):
    otp = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=5)

    # Store OTP in DB
    otp_entry = PasswordResetOTP(email=recipient_email, otp=otp, expires_at=expires_at)
    db.session.add(otp_entry)
    db.session.commit()

    # Send email
    msg = Message("Your SecureAccess Password Reset Code",
                  sender="no-reply@secureaccess.com",
                  recipients=[recipient_email])
    msg.body = f"Your OTP for password reset is: {otp}\n\nThis code expires in 5 minutes."
    mail.send(msg)

    return otp
