from flask import Blueprint, request, jsonify
from models import db, User
from utils import password_policy
from sms_utils import generate_otp, send_verification_sms_console
from datetime import datetime, timedelta

api_bp = Blueprint("api_bp", __name__)

@api_bp.route("/register", methods=["POST"])
def api_register():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    phone_number = (data.get("phone_number") or "").strip()
    password = data.get("password") or ""

    if not username or not phone_number or not password:
        return jsonify({"error": "All fields required"}), 400

    if User.query.filter((User.username==username)|(User.phone_number==phone_number)).first():
        return jsonify({"error": "Username or phone exists"}), 409

    valid, message = password_policy(password)
    if not valid:
        return jsonify({"error": message}), 400

    user = User(username=username, phone_number=phone_number)
    user.set_password(password)
    user.phone_verified = False
    db.session.add(user)
    db.session.flush()

    # Generate OTP
    otp = generate_otp()
    user.sms_otp = otp
    user.sms_otp_expires_at = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()

    send_verification_sms_console(phone_number, username, otp)
    return jsonify({"message": "User created! OTP sent to phone.", "user_id": user.id}), 201

@api_bp.route("/verify_sms", methods=["POST"])
def api_verify_sms():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    otp = data.get("otp")

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if user.sms_otp_expires_at and datetime.utcnow() > user.sms_otp_expires_at:
        return jsonify({"error": "OTP expired"}), 400

    if user.sms_otp != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    user.phone_verified = True
    user.sms_otp = None
    user.sms_otp_expires_at = None
    db.session.commit()

    return jsonify({"message": "Phone verified successfully"}), 200

@api_bp.route("/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    phone_number = data.get("phone_number")
    password = data.get("password")

    user = User.query.filter_by(phone_number=phone_number).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    if not user.phone_verified:
        return jsonify({"error": "Phone not verified"}), 403
    if user.is_account_locked():
        return jsonify({"error": "Account locked"}), 403
    if not user.check_password(password):
        user.increment_failed_attempts()
        return jsonify({"error": "Invalid password"}), 400

    user.reset_failed_attempts()
    return jsonify({"message": f"Welcome {user.username}!"}), 200
