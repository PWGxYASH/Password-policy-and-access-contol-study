# api.py (extended)
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from ext import db
from models import User, PasswordResetOTP, AuditLog
from utils import password_policy
from sms_utils import generate_otp, send_verification_sms_console

api_bp = Blueprint("api_bp", __name__, url_prefix="/api")

# ------------------------------
# Register User
# ------------------------------
@api_bp.route("/register", methods=["POST"])
def api_register():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    phone_number = (data.get("phone_number") or "").strip()
    password = data.get("password") or ""

    if not username or not phone_number or not password:
        return jsonify({"error": "All fields required"}), 400

    if User.query.filter((User.username==username)|(User.phone_number==phone_number)).first():
        return jsonify({"error": "Username or phone already exists"}), 409

    valid, message = password_policy(password)
    if not valid:
        return jsonify({"error": message}), 400

    user = User(username=username, phone_number=phone_number)
    user.set_password(password)
    user.phone_verified = False
    db.session.add(user)
    db.session.flush()

    otp = generate_otp()
    user.sms_otp = otp
    user.sms_otp_expires_at = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()

    send_verification_sms_console(phone_number, username, otp)
    return jsonify({"message": "User created! OTP sent to console.", "user_id": user.id}), 201


# ------------------------------
# Verify SMS OTP
# ------------------------------
@api_bp.route("/verify_sms", methods=["POST"])
def api_verify_sms():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    otp = data.get("otp")

    if not user_id or not otp:
        return jsonify({"error": "user_id and otp required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.sms_otp or user.sms_otp_expires_at < datetime.utcnow():
        return jsonify({"error": "OTP expired or not generated"}), 400

    if user.sms_otp != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    user.phone_verified = True
    user.sms_otp = None
    user.sms_otp_expires_at = None
    db.session.commit()

    # Log action
    db.session.add(AuditLog(user_id=user.id, action="Phone verified"))
    db.session.commit()

    return jsonify({"message": "Phone verified successfully"}), 200


# ------------------------------
# Login
# ------------------------------
@api_bp.route("/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    phone_number = data.get("phone_number")
    password = data.get("password")

    if not phone_number or not password:
        return jsonify({"error": "Phone number and password required"}), 400

    user = User.query.filter_by(phone_number=phone_number).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    if not user.phone_verified:
        return jsonify({"error": "Phone not verified"}), 403
    if user.is_account_locked():
        return jsonify({"error": "Account locked due to failed attempts"}), 403
    if not user.check_password(password):
        user.increment_failed_attempts()
        return jsonify({"error": "Invalid password"}), 400

    user.reset_failed_attempts()
    db.session.add(AuditLog(user_id=user.id, action="Login"))
    db.session.commit()

    return jsonify({"message": f"Welcome {user.username}!"}), 200


# ------------------------------
# Request Password Reset OTP
# ------------------------------
@api_bp.route("/request_password_reset", methods=["POST"])
def api_request_password_reset():
    data = request.get_json() or {}
    phone_number = data.get("phone_number")

    if not phone_number:
        return jsonify({"error": "Phone number required"}), 400

    user = User.query.filter_by(phone_number=phone_number).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    otp = generate_otp()
    otp_entry = PasswordResetOTP(
        email=user.username,
        otp=otp,
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )
    db.session.add(otp_entry)
    db.session.commit()

    send_verification_sms_console(user.phone_number, user.username, otp)
    return jsonify({"message": "Password reset OTP sent to console"}), 200


# ------------------------------
# Reset Password via OTP
# ------------------------------
@api_bp.route("/reset_password", methods=["POST"])
def api_reset_password():
    data = request.get_json() or {}
    username = data.get("username")
    otp = data.get("otp")
    new_password = data.get("new_password")

    if not username or not otp or not new_password:
        return jsonify({"error": "Username, OTP, and new password required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    otp_entry = PasswordResetOTP.query.filter_by(email=username).order_by(PasswordResetOTP.created_at.desc()).first()
    if not otp_entry or otp_entry.expires_at < datetime.utcnow():
        return jsonify({"error": "OTP expired or not found"}), 400
    if otp_entry.otp != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    valid, message = password_policy(new_password)
    if not valid:
        return jsonify({"error": message}), 400

    user.set_password(new_password)
    db.session.commit()

    db.session.add(AuditLog(user_id=user.id, action="Password reset via API"))
    db.session.commit()

    return jsonify({"message": "Password reset successfully"}), 200
