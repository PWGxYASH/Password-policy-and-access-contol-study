# 🔐 Twilio Authy SMS Verification Setup Guide

## Step 1️⃣: Create Twilio Account

1. Go to **https://www.twilio.com/console**
2. Sign up for a free Twilio account
3. Verify your phone number and email
4. You'll get free credits to test ($15 free trial)

## Step 2️⃣: Get Your Twilio Credentials

1. Go to **https://www.twilio.com/console**
2. Copy your:
   - **Account SID** (looks like: ACxxxxxxxxxxxxxxxxxx)
   - **Auth Token** (looks like: your_auth_token_here)
3. Save these - you'll need them!

## Step 3️⃣: Get a Twilio Phone Number

1. In Twilio Console, click **"Phone Numbers"** → **"Buy a Number"**
2. Choose a country and region
3. Click **"Buy"** (you get a number for free with trial credits)
4. You'll get a phone number like **+1 (555) 000-0000**
5. Copy this number - you need it!

## Step 4️⃣: Enable Authy

1. In Twilio Console, go to **"Add-ons"** → Search for **"Authy"**
2. Click **"Authy"** and select **"Subscribe"**
3. You'll get an **Authy API Key**
4. Copy this key

## Step 5️⃣: Set Environment Variables

Create a `.env` file in your project root with:

```bash
# .env file
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_auth_token_here
TWILIO_PHONE_NUMBER=+1234567890
AUTHY_API_KEY=your_authy_api_key_here
```

Then run:
```bash
source .env
# Or if using python-dotenv, install it:
# pip install python-dotenv
```

## Step 6️⃣: Update Your Flask App

In your `app.py`, load environment variables:

```python
import os
from dotenv import load_dotenv

load_dotenv()  # Load from .env file
```

## Step 7️⃣: Test SMS Verification

Run this Python script to test:

```python
from sms_utils import send_verification_sms

result = send_verification_sms(
    phone_number="+1234567890",  # Your phone number
    user_email="user@example.com",
    username="testuser"
)

if result['success']:
    print("✅ SMS sent successfully!")
else:
    print("❌ Failed:", result['message'])
```

## 📱 Testing Phone Numbers (Sandbox Mode)

If you want to test without a real phone number, Twilio provides sandbox numbers:

```
+1 (555) 0100  - Any number starting with (555) 01
```

These won't actually send SMS but are useful for testing the flow.

## 🔄 User Registration Flow with SMS

1. User provides phone number during registration
2. System sends OTP via SMS to that number
3. User enters OTP code
4. If valid → email_verified = True (user can login)
5. User can now access the application

## 💰 Twilio Pricing

- **Free Trial**: $15 credit (test mode)
- **SMS Cost**: $0.0075 per SMS (after trial ends)
- **Authy**: Free with Twilio account
- **Push Notifications**: Free (part of Authy)

## 🆘 Troubleshooting

**"SMS not received":**
- Check phone number format: +1 (country code) (number)
- Ensure your Twilio account is verified
- Check you're not in sandbox mode

**"Invalid Authy API Key":**
- Verify you subscribed to Authy add-on
- Copy the key correctly from the Authy dashboard

**"Authentication failed":**
- Double-check Account SID and Auth Token
- Make sure they're loaded from environment variables

## 📚 Resources

- **Twilio Console**: https://www.twilio.com/console
- **Twilio SMS API**: https://www.twilio.com/docs/sms
- **Authy API**: https://www.twilio.com/docs/authy/api
- **Python Twilio SDK**: https://www.twilio.com/docs/libraries/python

---

Once you have your credentials, the application is ready to use SMS verification! 🎉
