# SecureAccess - Password Policy & Access Control System

A comprehensive Flask-based authentication system with enterprise-grade security features including account lockout, email verification, role-based access control, audit logging, password history, and expiration management.

## Features

### Security Features
✅ **Account Lockout** - Locks accounts after 5 failed login attempts for 30 minutes
✅ **Email Verification** - Users must verify email before first login
✅ **Session Management** - IP and device tracking for all user sessions
✅ **Role-Based Access Control** - Admin, User, Moderator, Viewer roles with permission decorators
✅ **Audit Logging** - Comprehensive logging of all security events
✅ **Password History** - Prevents reuse of last 5 passwords
✅ **Password Expiration** - Passwords expire after 90 days with 7-day warning
✅ **Password Policy** - Strong password requirements enforced

### Additional Security Measures
- Secure password hashing using Werkzeug
- JWT token-based authentication
- Flash messages for security feedback
- Admin dashboard for user management
- Account unlock capabilities
- Forced password reset for compromised accounts

## Quick Start

### Installation

1. **Clone the repository**
   ```bash
   cd /workspaces/Password-policy-and-access-contol-study
   ```

2. **Activate virtual environment**
   ```bash
   source env/bin/activate  # On Linux/Mac
   # or
   env\Scripts\activate  # On Windows
   ```

3. **Install dependencies** (already done in env/)
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Email (IMPORTANT for Email Verification)**
   
   The application uses Flask-Mail with Gmail SMTP. You must set up Gmail app password:
   
   a. **Enable 2-Factor Authentication on your Gmail account**
   
   b. **Generate an App Password:**
      - Go to myaccount.google.com
      - Click "Security" in left menu
      - Scroll to "App passwords" (only visible if 2FA is enabled)
      - Select "Mail" and "Windows Computer" (or your device type)
      - Google will generate a 16-character password
   
   c. **Set environment variables** in `.env` file:
      ```
      MAIL_USERNAME=your-email@gmail.com
      MAIL_PASSWORD=your-16-character-app-password
      MAIL_SERVER=smtp.gmail.com
      MAIL_PORT=587
      MAIL_USE_TLS=True
      ```
   
   d. **Update app.py** to read from `.env`:
      The app is currently configured with Flask-Mail, but you need to set:
      ```python
      MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
      MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
      ```

5. **Initialize Database**
   ```bash
   python init_db.py
   ```

6. **Run the application**
   ```bash
   python app.py
   ```
   
   The application will start on `http://localhost:5000`

## Database Schema

### User Model
- `id` - Primary key
- `username` - Unique username
- `email` - Unique email (must be verified)
- `password_hash` - Hashed password
- `email_verified` - Boolean flag for email verification status
- `verification_token` - Token for email verification
- `failed_attempts` - Counter for failed login attempts
- `locked_until` - Timestamp when account auto-unlocks
- `last_login` - Last successful login timestamp
- `last_login_ip` - IP of last login
- `last_password_changed` - When password was last changed
- `password_expiry_date` - When password expires (90 days from change)
- `role` - User role (admin, user, moderator, viewer)
- `created_at` - Account creation timestamp

### Related Models
- **PasswordResetOTP** - Stores OTP codes for password reset (expires in 5 minutes)
- **PasswordHistory** - Tracks last 5 passwords to prevent reuse
- **AuditLog** - Logs all security events (login, signup, password change, etc.)
- **UserSession** - Tracks active sessions with IP and device info

## API Routes

### Authentication Routes
- `GET /` - Redirect to registration page
- `GET/POST /register` - User registration
- `GET/POST /login` - User login
- `GET /logout` - User logout
- `GET /verify-email/<token>` - Email verification
- `GET /dashboard` - User dashboard (requires login)

### Password Management
- `POST /forgot-password` - Request password reset (sends OTP via email)
- `POST /verify-otp` - Verify OTP and confirm password reset
- `POST /reset-password` - Set new password

### Admin Routes (requires admin role)
- `GET /admin/users` - List all users
- `GET /admin/user/<id>` - View user details
- `POST /admin/user/<id>/lock` - Lock user account for 30 days
- `POST /admin/user/<id>/unlock` - Unlock user account
- `POST /admin/user/<id>/force-password-reset` - Force user password reset
- `GET /admin/audit-logs` - View audit logs

## Email Configuration Troubleshooting

### "No mail is coming"
1. **Verify Gmail App Password is correct:**
   ```bash
   python -c "from flask_mail import Mail; print('Flask-Mail imported successfully')"
   ```

2. **Check app.py configuration:**
   - Ensure MAIL_SERVER='smtp.gmail.com'
   - Ensure MAIL_PORT=587
   - Ensure MAIL_USE_TLS=True

3. **Check console output:**
   - Look for "Verification email sent to [email]" messages
   - If you see errors, they'll be printed with full traceback

4. **Gmail may be blocking:**
   - Check your Gmail account for "Less secure app access" warnings
   - 2-Factor Authentication MUST be enabled for app passwords to work
   - App password must be 16 characters (no spaces)

5. **Test with a simple script:**
   ```python
   from app import app, mail
   from flask_mail import Message
   
   with app.app_context():
       msg = Message('Test Email', recipients=['your-email@gmail.com'])
       msg.body = 'Test message'
       mail.send(msg)
       print('Email sent!')
   ```

## Testing

### Test Registration Flow
1. Go to `http://localhost:5000`
2. Click "Sign Up Here"
3. Enter username, email, password (must meet requirements)
4. Check console output for verification link
5. Click verification link in console
6. You can now login

### Test Account Lockout
1. Try logging in with wrong password 5 times
2. Account will lock for 30 minutes
3. Admin can unlock immediately via admin dashboard

### Test Password Expiration
1. Create new user (password expires in 90 days)
2. After 83 days, user sees warning on dashboard
3. After 90 days, user cannot login until password is reset

## Requirements

```
Flask==3.0.0
Flask-SQLAlchemy==3.1.1
Flask-JWT-Extended==4.7.1
Flask-Mail==0.10.0
Werkzeug==3.0.0
```

See `requirements.txt` for full list.

## Security Considerations

1. **Production Deployment:**
   - Never use app.run() directly
   - Use a production WSGI server (Gunicorn, uWSGI)
   - Enable HTTPS/TLS
   - Use environment variables for all secrets
   - Set SECRET_KEY to a random secure value

2. **Database:**
   - This uses SQLite (development only)
   - For production, migrate to PostgreSQL or MySQL
   - Enable database backups

3. **Email:**
   - Gmail app passwords work for testing
   - For production, use SendGrid, AWS SES, or similar service
   - Never commit credentials to git

4. **Additional Protections to Add:**
   - Rate limiting on login/register endpoints
   - CSRF protection using Flask-WTF
   - HTTPS enforcement
   - Two-factor authentication (TOTP)
   - Password reset via secure email token

## File Structure

```
.
├── app.py              # Flask application entry point
├── auth.py             # Authentication routes and logic
├── models.py           # Database models
├── utils.py            # Utility functions (password policy)
├── mail_utils.py       # Email sending functions
├── init_db.py          # Database initialization script
├── requirements.txt    # Python dependencies
├── README.md           # This file
├── SECURITY_FEATURES.md # Detailed security documentation
├── templates/          # HTML templates
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   ├── forgot_password.html
│   ├── verify_otp.html
│   └── reset_password.html
└── static/            # Static files (CSS, JS)
    └── js/
        └── forgot_password.js
```

## Future Enhancements

- [ ] Two-factor authentication (TOTP/SMS)
- [ ] OAuth2 integration (Google, GitHub)
- [ ] Rate limiting on sensitive endpoints
- [ ] Breach detection and alerts
- [ ] Geographic login restrictions
- [ ] API key management for developers
- [ ] WebAuthn/FIDO2 support
- [ ] Passwordless authentication

## License

This project is for educational purposes.

## Support

For detailed information about security features, see `SECURITY_FEATURES.md`