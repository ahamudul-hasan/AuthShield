from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request, current_app
from app.extensions import db, limiter
from app.models.user import User
from app.auth.password import (
    hash_password,
    verify_password,
    needs_rehash,
    identify_algorithm,
    benchmark_argon2,
)
from app.auth.validator import validate_password
from app.auth.mfa import (
    encrypt_totp_secret,
    decrypt_totp_secret,
    generate_totp_secret,
    generate_provisioning_uri,
    generate_qr_code_data_uri,
    verify_totp_code,
    generate_pending_mfa_token,
    verify_pending_mfa_token,
    generate_mfa_setup_token,
    verify_mfa_setup_token,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/status", methods=["GET"])
def auth_status():
    """Report auth module status and algorithm capabilities."""
    return jsonify({
        "status": "ready",
        "module": "auth",
        "default_algorithm": "argon2id",
        "supported_algorithms": ["argon2id", "bcrypt"],
        "mfa_supported": True,
    }), 200


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new user with Argon2id password hashing."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not username:
        return jsonify({"error": "Bad Request", "message": "Username is required."}), 400
    if not email or "@" not in email:
        return jsonify({"error": "Bad Request", "message": "Valid email is required."}), 400
    if not password:
        return jsonify({"error": "Bad Request", "message": "Password is required."}), 400

    # Check for existing username or email
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Conflict", "message": f"Username '{username}' is already registered."}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Conflict", "message": f"Email '{email}' is already registered."}), 409

    # Validate password quality and strength against NIST SP 800-63B standards
    validation = validate_password(password, username=username, email=email)
    if not validation["is_valid"]:
        return jsonify({
            "error": "Bad Request",
            "message": "Password does not meet security requirements.",
            "details": validation,
        }), 400

    # Hash with Argon2id
    encoded_hash = hash_password(password)

    new_user = User(
        username=username,
        email=email,
        password_hash=encoded_hash,
        password_algorithm="argon2id",
        role="user",
        is_active=True,
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "message": "User registered successfully.",
        "user": new_user.to_dict(),
        "password_algorithm": new_user.password_algorithm,
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """Verify user password and rehash outdated parameters if needed."""
    data = request.get_json(silent=True) or {}
    login_id = data.get("username", "").strip()
    password = data.get("password", "")

    if not login_id or not password:
        return jsonify({"error": "Bad Request", "message": "Username/email and password are required."}), 400

    # Look up by username or email
    user = User.query.filter(
        (User.username == login_id) | (User.email == login_id.lower())
    ).first()

    if not user or not user.is_active:
        return jsonify({"error": "Unauthorized", "message": "Invalid username or password."}), 401

    # Check if account is temporarily locked
    if user.is_locked:
        expiry_iso = user.lockout_until.isoformat() if user.lockout_until else ""
        return jsonify({
            "error": "Forbidden",
            "message": f"Account is temporarily locked due to excessive failed attempts. Please try again after {expiry_iso}.",
            "lockout_until": expiry_iso,
        }), 403

    # Verify password against stored hash (Argon2id or bcrypt)
    is_valid = verify_password(password, user.password_hash)

    if not is_valid:
        # Increment failed attempts
        max_attempts = current_app.config.get("MAX_FAILED_ATTEMPTS", 5)
        lockout_minutes = current_app.config.get("LOCKOUT_DURATION_MINUTES", 15)

        user.failed_attempts += 1
        if user.failed_attempts >= max_attempts:
            user.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
        db.session.commit()

        remaining = max(0, max_attempts - user.failed_attempts)
        return jsonify({
            "error": "Unauthorized",
            "message": "Invalid username or password.",
            "attempts_remaining": remaining if remaining > 0 else 0,
            "locked": user.is_locked,
        }), 401

    # Check if hash needs upgrade (e.g. from bcrypt or weaker Argon2 params)
    hash_upgraded = False
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        user.password_algorithm = "argon2id"
        hash_upgraded = True

    # If MFA is enabled on this account, transition to pending-MFA state
    # Requirement 9: Keep only a short-lived pending MFA state, never a full session,
    # and do not reveal MFA status before password verification.
    if user.mfa_enabled:
        db.session.commit()
        mfa_token = generate_pending_mfa_token(user.id)
        return jsonify({
            "message": "Password verified. Multi-factor authentication code required.",
            "mfa_required": True,
            "mfa_token": mfa_token,
            "hash_upgraded": hash_upgraded,
        }), 200

    # Successful authentication without MFA
    user.failed_attempts = 0
    user.lockout_until = None
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({
        "message": "Login successful.",
        "mfa_required": False,
        "user": user.to_dict(),
        "password_algorithm": user.password_algorithm,
        "hash_upgraded": hash_upgraded,
    }), 200


@auth_bp.route("/benchmark", methods=["GET"])
def benchmark():
    """Benchmark Argon2id execution on the current machine."""
    iterations = request.args.get("iterations", 3, type=int)
    # Bound iterations to avoid excessive load
    iterations = max(1, min(iterations, 20))
    results = benchmark_argon2(iterations=iterations)
    return jsonify(results), 200


@auth_bp.route("/validate-password", methods=["POST"])
def validate_pwd():
    """Evaluate password strength and return real-time analysis and feedback."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    username = data.get("username", "")
    email = data.get("email", "")

    result = validate_password(password, username=username, email=email)
    return jsonify(result), 200


@auth_bp.route("/change-password", methods=["POST"])
def change_password():
    """Change user password after validating old password and testing new password strength."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    current_pwd = data.get("current_password", "")
    new_pwd = data.get("new_password", "")

    if not username or not current_pwd or not new_pwd:
        return jsonify({
            "error": "Bad Request",
            "message": "Username, current password, and new password are required."
        }), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.is_active:
        return jsonify({"error": "Unauthorized", "message": "Invalid username or password."}), 401

    if user.is_locked:
        expiry_iso = user.lockout_until.isoformat() if user.lockout_until else ""
        return jsonify({
            "error": "Forbidden",
            "message": f"Account is temporarily locked. Please try again after {expiry_iso}.",
        }), 403

    if not verify_password(current_pwd, user.password_hash):
        user.failed_attempts += 1
        db.session.commit()
        return jsonify({"error": "Unauthorized", "message": "Current password is incorrect."}), 401

    if current_pwd == new_pwd:
        return jsonify({
            "error": "Bad Request",
            "message": "New password cannot be the same as the current password."
        }), 400

    # Validate new password strength
    validation = validate_password(new_pwd, username=user.username, email=user.email)
    if not validation["is_valid"]:
        return jsonify({
            "error": "Bad Request",
            "message": "New password does not meet security requirements.",
            "details": validation,
        }), 400

    user.password_hash = hash_password(new_pwd)
    user.password_algorithm = "argon2id"
    user.password_changed_at = datetime.now(timezone.utc)
    user.failed_attempts = 0
    db.session.commit()

    return jsonify({
        "message": "Password changed successfully.",
        "password_algorithm": user.password_algorithm,
    }), 200


@auth_bp.route("/verify-mfa", methods=["POST"])
@limiter.limit("10 per minute")
def verify_mfa():
    """
    Verify TOTP MFA code for a user with pending MFA authentication.
    Enforces replay protection and clock-drift tolerance.
    """
    data = request.get_json(silent=True) or {}
    mfa_token = data.get("mfa_token", "").strip()
    code = str(data.get("code", "")).strip()

    if not mfa_token or not code:
        return jsonify({
            "error": "Bad Request",
            "message": "MFA token and 6-digit confirmation code are required."
        }), 400

    user_id = verify_pending_mfa_token(mfa_token)
    if not user_id:
        return jsonify({
            "error": "Unauthorized",
            "message": "Invalid or expired MFA session. Please log in again."
        }), 401

    user = db.session.get(User, user_id)
    if not user or not user.is_active:
        return jsonify({"error": "Unauthorized", "message": "User not found or disabled."}), 401

    if user.is_locked:
        expiry_iso = user.lockout_until.isoformat() if user.lockout_until else ""
        return jsonify({
            "error": "Forbidden",
            "message": f"Account is temporarily locked. Please try again after {expiry_iso}.",
        }), 403

    valid_window = current_app.config.get("MFA_VALID_WINDOW", 1)
    is_valid, matched_step, reason = verify_totp_code(
        secret=user.totp_secret,
        code=code,
        last_step=user.last_totp_step,
        valid_window=valid_window,
    )

    if not is_valid:
        # Increment failed attempts
        max_attempts = current_app.config.get("MAX_FAILED_ATTEMPTS", 5)
        lockout_minutes = current_app.config.get("LOCKOUT_DURATION_MINUTES", 15)
        user.failed_attempts += 1
        if user.failed_attempts >= max_attempts:
            user.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
        db.session.commit()

        return jsonify({
            "error": "Unauthorized",
            "message": reason or "Invalid or expired MFA code.",
            "attempts_remaining": max(0, max_attempts - user.failed_attempts),
            "locked": user.is_locked,
        }), 401

    # Successful MFA verification
    user.last_totp_step = matched_step
    user.failed_attempts = 0
    user.lockout_until = None
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({
        "message": "MFA verification successful. Login complete.",
        "user": user.to_dict(),
        "authenticated": True,
    }), 200


@auth_bp.route("/mfa/setup", methods=["POST"])
@limiter.limit("5 per minute")
def mfa_setup():
    """
    Initiate TOTP MFA enrollment: generates a secret and a QR code Data URI.
    Requires password reauthentication.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "error": "Bad Request",
            "message": "Username and password are required for reauthentication."
        }), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.is_active or not verify_password(password, user.password_hash):
        return jsonify({"error": "Unauthorized", "message": "Invalid username or password."}), 401

    if user.is_locked:
        return jsonify({"error": "Forbidden", "message": "Account is temporarily locked."}), 403

    raw_secret = generate_totp_secret()
    provisioning_uri = generate_provisioning_uri(raw_secret, user.email)
    qr_data_uri = generate_qr_code_data_uri(provisioning_uri)
    setup_token = generate_mfa_setup_token(user.id, raw_secret)

    return jsonify({
        "message": "Scan the QR code or enter the secret in your authenticator app, then submit a 6-digit code to enable MFA.",
        "setup_token": setup_token,
        "secret": raw_secret,
        "provisioning_uri": provisioning_uri,
        "qr_code": qr_data_uri,
    }), 200


@auth_bp.route("/mfa/enable", methods=["POST"])
@limiter.limit("5 per minute")
def mfa_enable():
    """
    Confirm 6-digit TOTP code and enable MFA on the user account.
    Encrypts the secret at rest using Fernet.
    """
    data = request.get_json(silent=True) or {}
    setup_token = data.get("setup_token", "").strip()
    code = str(data.get("code", "")).strip()

    if not setup_token or not code:
        return jsonify({
            "error": "Bad Request",
            "message": "Setup token and 6-digit confirmation code are required."
        }), 400

    token_data = verify_mfa_setup_token(setup_token)
    if not token_data:
        return jsonify({
            "error": "Unauthorized",
            "message": "Invalid or expired MFA setup session. Please initiate setup again."
        }), 401

    user = db.session.get(User, token_data["user_id"])
    if not user or not user.is_active:
        return jsonify({"error": "Unauthorized", "message": "User not found or disabled."}), 401

    raw_secret = token_data["secret"]
    valid_window = current_app.config.get("MFA_VALID_WINDOW", 1)
    is_valid, matched_step, reason = verify_totp_code(
        secret=raw_secret,
        code=code,
        last_step=None,
        valid_window=valid_window,
    )

    if not is_valid:
        return jsonify({
            "error": "Bad Request",
            "message": reason or "Invalid confirmation code."
        }), 400

    # Encrypt secret at rest and enable MFA
    encrypted_secret = encrypt_totp_secret(raw_secret)
    user.totp_secret = encrypted_secret
    user.mfa_enabled = True
    user.last_totp_step = matched_step
    db.session.commit()

    return jsonify({
        "message": "Multi-factor authentication enabled successfully.",
        "mfa_enabled": True,
    }), 200


@auth_bp.route("/mfa/disable", methods=["POST"])
@limiter.limit("5 per minute")
def mfa_disable():
    """
    Disable MFA after reauthentication with password and current TOTP code.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    code = str(data.get("code", "")).strip()

    if not username or not password or not code:
        return jsonify({
            "error": "Bad Request",
            "message": "Username, password, and current MFA code are required."
        }), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.is_active:
        return jsonify({"error": "Unauthorized", "message": "Invalid credentials."}), 401

    if user.is_locked:
        return jsonify({"error": "Forbidden", "message": "Account is temporarily locked."}), 403

    if not verify_password(password, user.password_hash):
        user.failed_attempts += 1
        db.session.commit()
        return jsonify({"error": "Unauthorized", "message": "Invalid username or password."}), 401

    if not user.mfa_enabled or not user.totp_secret:
        return jsonify({"error": "Bad Request", "message": "MFA is not enabled on this account."}), 400

    valid_window = current_app.config.get("MFA_VALID_WINDOW", 1)
    is_valid, matched_step, reason = verify_totp_code(
        secret=user.totp_secret,
        code=code,
        last_step=user.last_totp_step,
        valid_window=valid_window,
    )

    if not is_valid:
        user.failed_attempts += 1
        db.session.commit()
        return jsonify({"error": "Unauthorized", "message": reason or "Invalid MFA code."}), 401

    user.mfa_enabled = False
    user.totp_secret = None
    user.last_totp_step = None
    user.failed_attempts = 0
    db.session.commit()

    return jsonify({
        "message": "Multi-factor authentication disabled successfully.",
        "mfa_enabled": False,
    }), 200
