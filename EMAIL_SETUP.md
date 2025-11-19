# Email Configuration Setup Guide

This guide walks you through configuring Gmail SMTP for email verification and password reset emails.

## Why Emails Aren't Sending

The Flask-Mail library is configured in `app.py`, but **Gmail requires an app-specific password** for authentication. Using your regular Gmail password will fail with authentication errors.

## Step-by-Step Gmail Setup

### 1. Enable 2-Factor Authentication (Required)

1. Go to [myaccount.google.com](https://myaccount.google.com)
2. Click **"Security"** in the left menu
3. Scroll to **"How you sign in to Google"**
4. Enable **"2-Step Verification"** if not already enabled
   - Follow the prompts (you'll need to verify with your phone)

### 2. Generate an App Password

1. Go back to [myaccount.google.com](https://myaccount.google.com)
2. Click **"Security"** (left menu)
3. Scroll to **"App passwords"** (only visible if 2FA is enabled)
4. Select:
   - **App:** "Mail"
   - **Device:** "Windows Computer" (or your device type)
5. Click **"Generate"**
6. Google shows a 16-character password like: `abcd efgh ijkl mnop`
   - **Copy this password** (without spaces for our use)

### 3. Update app.py Configuration

Edit `app.py` and find the Flask configuration section:

```python
# Current configuration (around line 15-20):
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'        # ← Update this
app.config['MAIL_PASSWORD'] = 'abcdefghijklmnop'           # ← Update this
```

**Replace with your actual values:**
- `MAIL_USERNAME` = Your Gmail email address (e.g., yourname@gmail.com)
- `MAIL_PASSWORD` = The 16-character app password from Step 2 (without spaces)

### 4. Test Email Sending

Run this Python script to test:

```python
# test_email.py
from app import app, mail
from flask_mail import Message

with app.app_context():
    msg = Message(
        subject='Test Email',
        sender='your-email@gmail.com',
        recipients=['your-email@gmail.com']
    )
    msg.body = 'This is a test email from SecureAccess!'
    
    try:
        mail.send(msg)
        print('✓ Email sent successfully!')
    except Exception as e:
        print(f'✗ Failed to send email: {str(e)}')
```

Run with:
```bash
python test_email.py
```

### 5. Test with Application

1. Start the Flask app:
   ```bash
   python app.py
   ```

2. Go to `http://localhost:5000`

3. Register with a test account using your email address

4. Check your email inbox for verification message

5. If not in inbox, check **Spam** folder

## Troubleshooting

### Error: "Username and Password not accepted"
- ✓ Verify 2FA is enabled on Gmail
- ✓ Check that you're using an App Password (not regular Gmail password)
- ✓ Make sure there are no spaces in the password
- ✓ Verify MAIL_USERNAME and MAIL_PASSWORD are correct in app.py

### Error: "SMTPAuthenticationError"
- This usually means the password is wrong
- Generate a new app password and update app.py

### Email goes to Spam folder
- This is normal for development
- Check your spam/junk folder
- You can mark as "Not Spam" to train your email provider

### Console shows "Verification email sent to..." but no email arrives
- Check spam folder first
- Verify Gmail credentials in app.py are correct
- Try running the test script above to verify connectivity

### App Password is not showing in Security settings
- Ensure 2-Factor Authentication is fully enabled (not just activated)
- Sometimes it takes a few minutes to appear
- Try logging out and back in

## For Production

For a production deployment, **do not use Gmail app passwords**. Instead:

1. **Use SendGrid:**
   ```python
   app.config['MAIL_SERVER'] = 'smtp.sendgrid.net'
   app.config['MAIL_PORT'] = 587
   app.config['MAIL_USERNAME'] = 'apikey'
   app.config['MAIL_PASSWORD'] = 'SG.your-sendgrid-api-key'
   ```

2. **Use AWS SES:**
   ```python
   app.config['MAIL_SERVER'] = 'email-smtp.your-region.amazonaws.com'
   app.config['MAIL_PORT'] = 587
   app.config['MAIL_USERNAME'] = 'your-ses-username'
   app.config['MAIL_PASSWORD'] = 'your-ses-password'
   ```

3. **Use environment variables:**
   ```python
   import os
   app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
   app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
   ```

## Email Features Implemented

Once configured, the application will automatically send:

1. **Email Verification** - Sent when user signs up
   - Contains verification link
   - User must click to verify email
   - Cannot login until verified

2. **Password Reset OTP** - Sent when user requests password reset
   - Contains 6-digit OTP code
   - Expires in 5 minutes
   - User enters code + new password to reset

3. **Account Locked Notification** - Sent after 5 failed login attempts
   - Informs user account is locked for 30 minutes
   - Recommends secure password reset

4. **Password Reset Confirmation** - Sent when password is successfully changed
   - Confirms password change
   - User can reset password again if they didn't make this change

## Email Templates

All emails are formatted with:
- HTML version (pretty formatting)
- Plain text version (fallback)
- Consistent branding
- Clear action links/buttons

You can customize email templates in `mail_utils.py`:
- Search for `msg.body =` and `msg.html =`
- Modify text/HTML content as needed
- Keep verification links functional
