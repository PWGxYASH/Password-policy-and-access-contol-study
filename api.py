from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from models import db, User
from utils import password_policy
from datetime import timedelta

api_bp = Blueprint("api", __name__)

# --------------------------
# User Registration (API)
# --------------------------
@api_bp.route("/register", methods=["POST"])
def api_register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")

    if not username or not password or not email:
        return jsonify({"error": "Username, email, and password required"}), 400

    valid, message = password_policy(password)
    if not valid:
        return jsonify({"error": message}), 400

    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({"error": "Username or email already exists"}), 409

    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


# --------------------------
# User Login (API)
# --------------------------
@api_bp.route("/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity={"username": username, "role": user.role}, expires_delta=timedelta(hours=1))
    refresh_token = create_refresh_token(identity={"username": username, "role": user.role})

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {"username": username, "role": user.role}
    }), 200


# --------------------------
# Protected Endpoint (JWT)
# --------------------------
@api_bp.route("/profile", methods=["GET"])
@jwt_required()
def api_profile():
    current_user = get_jwt_identity()
    return jsonify({
        "message": "Access granted",
        "user": current_user
    })


# --------------------------
# Role-Based Access Example
# --------------------------
@api_bp.route("/admin/dashboard", methods=["GET"])
@jwt_required()
def admin_dashboard():
    current_user = get_jwt_identity()
    if current_user["role"] != "admin":
        return jsonify({"error": "Access denied: admin role required"}), 403
    return jsonify({"message": "Welcome to the admin dashboard!"})


# --------------------------
# Token Refresh Endpoint
# --------------------------
from flask_jwt_extended import jwt_required as jwt_refresh_required
@api_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity, expires_delta=timedelta(hours=1))
    return jsonify({"access_token": access_token})
