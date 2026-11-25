from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request, current_app, g
from app.extensions import db, limiter
from app.models.user import User
from app.models.recovery_code import RecoveryCode
from app.models.session import UserSession
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
from app.auth.recovery import (
    generate_user_recovery_codes,
    verify_and_consume_recovery_code,
    get_remaining_recovery_codes_count,
)
from app.auth.session_manager import (
    create_session,
    get_session_by_token,
    revoke_session,
    revoke_other_sessions,
    revoke_all_sessions,
    set_session_cookie,
    clear_session_cookie,
    get_token_from_request,
    generate_csrf_token,
    login_required,
    hash_session_token,
)
from app.auth.reset import (
    create_password_reset_token,
    send_reset_email_dev_console,
    verify_reset_token,
    consume_reset_token,
)
from app.detection.events import (
    record_security_event,
    EVENT_PASSWORD_RESET_REQUESTED,
    EVENT_PASSWORD_RESET_COMPLETED,
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

    # Step 2.7: Establish server-side session and set secure HttpOnly cookie
    user_agent_str = request.headers.get("User-Agent", "")
    ip_addr = request.remote_addr
    session_obj, raw_token = create_session(user.id, ip_address=ip_addr, user_agent=user_agent_str)

    resp = jsonify({
        "message": "Login successful.",
        "mfa_required": False,
        "user": user.to_dict(),
        "password_algorithm": user.password_algorithm,
        "hash_upgraded": hash_upgraded,
        "session_token": raw_token,
        "session": session_obj.to_dict(is_current=True),
    })
    return set_session_cookie(resp, raw_token), 200


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

    # Step 2.7 Task 8: Revoke other sessions after a password change
    token = get_token_from_request()
    current_sess = get_session_by_token(token) if token else None
    current_sess_id = current_sess.id if current_sess else None
    revoke_other_sessions(user.id, current_session_id=current_sess_id)

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

    # Step 2.7: Establish server-side session and set secure HttpOnly cookie
    user_agent_str = request.headers.get("User-Agent", "")
    ip_addr = request.remote_addr
    session_obj, raw_token = create_session(user.id, ip_address=ip_addr, user_agent=user_agent_str)

    resp = jsonify({
        "message": "MFA verification successful. Login complete.",
        "user": user.to_dict(),
        "authenticated": True,
        "session_token": raw_token,
        "session": session_obj.to_dict(is_current=True),
    })
    return set_session_cookie(resp, raw_token), 200


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

    # Generate one-time recovery codes (Step 2.6)
    recovery_codes = generate_user_recovery_codes(user.id)
    db.session.commit()

    return jsonify({
        "message": "Multi-factor authentication enabled successfully. Save your backup recovery codes now.",
        "mfa_enabled": True,
        "recovery_codes": recovery_codes,
        "warning": "Store these recovery codes in a secure location. They will only be displayed once.",
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
    # Invalidate recovery codes since MFA is disabled
    RecoveryCode.query.filter_by(user_id=user.id).delete()
    db.session.commit()

    # Step 2.7 Task 8: Revoke other sessions when MFA is disabled
    token = get_token_from_request()
    current_sess = get_session_by_token(token) if token else None
    current_sess_id = current_sess.id if current_sess else None
    revoke_other_sessions(user.id, current_session_id=current_sess_id)

    return jsonify({
        "message": "Multi-factor authentication disabled successfully.",
        "mfa_enabled": False,
    }), 200


@auth_bp.route("/recovery", methods=["POST"])
@limiter.limit("5 per minute")
def recovery_login():
    """
    Log in using a one-time recovery code when authenticator device is lost.
    Marks recovery code as used, authenticates user, and deactivates lost MFA
    device so user is prompted to re-enroll.
    """
    data = request.get_json(silent=True) or {}
    mfa_token = data.get("mfa_token", "").strip()
    recovery_code = data.get("recovery_code", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not recovery_code:
        return jsonify({
            "error": "Bad Request",
            "message": "Recovery code is required."
        }), 400

    user = None
    # Mode 1: From pending MFA login state
    if mfa_token:
        user_id = verify_pending_mfa_token(mfa_token)
        if user_id:
            user = db.session.get(User, user_id)

    # Mode 2: Direct username + password re-authentication fallback
    if not user and username and password:
        candidate = User.query.filter(
            (User.username == username) | (User.email == username.lower())
        ).first()
        if candidate and candidate.is_active and verify_password(password, candidate.password_hash):
            user = candidate

    if not user or not user.is_active:
        return jsonify({
            "error": "Unauthorized",
            "message": "Invalid or expired recovery session. Please provide valid login credentials."
        }), 401

    if user.is_locked:
        expiry_iso = user.lockout_until.isoformat() if user.lockout_until else ""
        return jsonify({
            "error": "Forbidden",
            "message": f"Account is temporarily locked. Please try again after {expiry_iso}.",
        }), 403

    # Verify and consume the one-time recovery code
    is_valid, message = verify_and_consume_recovery_code(user.id, recovery_code)

    if not is_valid:
        max_attempts = current_app.config.get("MAX_FAILED_ATTEMPTS", 5)
        lockout_minutes = current_app.config.get("LOCKOUT_DURATION_MINUTES", 15)
        user.failed_attempts += 1
        if user.failed_attempts >= max_attempts:
            user.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
        db.session.commit()

        return jsonify({
            "error": "Unauthorized",
            "message": message,
            "attempts_remaining": max(0, max_attempts - user.failed_attempts),
            "locked": user.is_locked,
        }), 401

    # Requirement 5: Require user to re-enroll MFA if authenticator is lost.
    # Deactivate the lost MFA authenticator on successful recovery
    user.mfa_enabled = False
    user.totp_secret = None
    user.last_totp_step = None
    user.failed_attempts = 0
    user.lockout_until = None
    user.last_login_at = datetime.now(timezone.utc)

    # Invalidate remaining codes since MFA is deactivated and will be re-enrolled
    RecoveryCode.query.filter_by(user_id=user.id).delete()
    db.session.commit()

    # Step 2.7: Establish server-side session and set secure HttpOnly cookie
    user_agent_str = request.headers.get("User-Agent", "")
    ip_addr = request.remote_addr
    session_obj, raw_token = create_session(user.id, ip_address=ip_addr, user_agent=user_agent_str)

    resp = jsonify({
        "message": "Recovery code accepted. Login successful. Your lost MFA device has been deactivated. Please re-enroll MFA immediately.",
        "authenticated": True,
        "mfa_reset": True,
        "require_mfa_re_enroll": True,
        "user": user.to_dict(),
        "session_token": raw_token,
        "session": session_obj.to_dict(is_current=True),
    })
    return set_session_cookie(resp, raw_token), 200


@auth_bp.route("/mfa/recovery-codes/regenerate", methods=["POST"])
@limiter.limit("5 per minute")
def regenerate_recovery_codes():
    """Regenerate a fresh set of one-time recovery codes for an MFA-enabled user."""
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

    if not user.mfa_enabled:
        return jsonify({
            "error": "Bad Request",
            "message": "Cannot generate recovery codes: MFA is not enabled on this account."
        }), 400

    new_codes = generate_user_recovery_codes(user.id, invalidate_existing=True)

    return jsonify({
        "message": "New recovery codes generated successfully. Previous codes have been invalidated.",
        "recovery_codes": new_codes,
        "warning": "Store these codes in a secure location. They will only be displayed once.",
    }), 200


@auth_bp.route("/mfa/recovery-codes/status", methods=["GET"])
def recovery_codes_status():
    """Return count of remaining unused recovery codes."""
    username = request.args.get("username", "").strip()
    if not username:
        return jsonify({"error": "Bad Request", "message": "Username is required."}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.is_active:
        return jsonify({"error": "NotFound", "message": "User not found."}), 404

    count = get_remaining_recovery_codes_count(user.id)
    return jsonify({
        "mfa_enabled": user.mfa_enabled,
        "remaining_recovery_codes": count,
    }), 200


@auth_bp.route("/csrf", methods=["GET"])
def get_csrf():
    """Return a CSRF token for state-changing requests."""
    token = get_token_from_request()
    sess = get_session_by_token(token) if token else None
    sess_id = sess.id if sess else 0
    csrf_token = generate_csrf_token(sess_id)
    return jsonify({"csrf_token": csrf_token}), 200


@auth_bp.route("/me", methods=["GET"])
@login_required
def get_me():
    """Return the currently authenticated user and active session."""
    return jsonify({
        "user": g.current_user.to_dict(),
        "session": g.current_session.to_dict(is_current=True),
    }), 200


@auth_bp.route("/sessions", methods=["GET"])
@login_required
def list_sessions():
    """List all active sessions for the current authenticated user."""
    sessions = UserSession.query.filter(
        UserSession.user_id == g.current_user.id,
        UserSession.is_revoked == False  # noqa: E712
    ).order_by(UserSession.created_at.desc()).all()

    active_sessions = []
    for s in sessions:
        if s.is_valid:
            active_sessions.append(s.to_dict(is_current=(s.id == g.current_session.id)))

    return jsonify({
        "sessions": active_sessions,
        "total": len(active_sessions),
    }), 200


@auth_bp.route("/sessions/<int:session_id>", methods=["DELETE"])
@login_required
def revoke_single_session(session_id: int):
    """Revoke an individual session belonging to the user."""
    success = revoke_session(session_id, g.current_user.id)
    if not success:
        return jsonify({"error": "NotFound", "message": "Session not found or already revoked."}), 404

    resp = jsonify({"message": f"Session {session_id} has been revoked."})
    if session_id == g.current_session.id:
        clear_session_cookie(resp)

    return resp, 200


@auth_bp.route("/sessions", methods=["DELETE"])
@login_required
def revoke_other_user_sessions():
    """Revoke all other active sessions except the current one."""
    revoked_count = revoke_other_sessions(g.current_user.id, current_session_id=g.current_session.id)
    return jsonify({
        "message": f"Revoked {revoked_count} other active session(s).",
        "revoked_count": revoked_count,
    }), 200


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Log out: revoke current server-side session and clear session cookie."""
    token = get_token_from_request()
    if token:
        token_hash = hash_session_token(token)
        sess = UserSession.query.filter_by(session_hash=token_hash).first()
        if sess:
            sess.is_revoked = True
            sess.revoked_at = datetime.now(timezone.utc)
            db.session.commit()

    resp = jsonify({"message": "Logout successful."})
    return clear_session_cookie(resp), 200


@auth_bp.route("/forgot-password", methods=["POST"])
@limiter.limit("5 per minute")
def forgot_password():
    """
    Accept a password reset request (Step 2.8).
    Returns a generic response whether or not the account exists to prevent enumeration.
    Generates a random token, stores only its SHA-256 hash, and dispatches via dev console.
    """
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()

    if not email or "@" not in email:
        return jsonify({
            "error": "Bad Request",
            "message": "A valid email address is required.",
        }), 400

    user = User.query.filter_by(email=email).first()
    ip_addr = request.remote_addr

    if user and user.is_active:
        raw_token = create_password_reset_token(user, ip_address=ip_addr)
        send_reset_email_dev_console(user.email, raw_token)
        record_security_event(
            EVENT_PASSWORD_RESET_REQUESTED,
            user_id=user.id,
            username=user.username,
            ip_address=ip_addr,
            details={"account_found": True},
        )
    else:
        record_security_event(
            EVENT_PASSWORD_RESET_REQUESTED,
            user_id=None,
            username=None,
            ip_address=ip_addr,
            details={"account_found": False},
        )

    return jsonify({
        "message": "If an account with that email exists, a password reset link has been sent."
    }), 200


@auth_bp.route("/reset-password", methods=["POST"])
@limiter.limit("5 per minute")
def reset_password():
    """
    Complete password reset using a valid single-use reset token (Step 2.8).
    Hashes new password with Argon2id, revokes all active sessions, records a security event,
    and preserves MFA requirements on subsequent logins.
    """
    data = request.get_json(silent=True) or {}
    raw_token = data.get("token", "").strip()
    new_password = data.get("new_password", "")

    if not raw_token or not new_password:
        return jsonify({
            "error": "Bad Request",
            "message": "Reset token and new password are required.",
        }), 400

    token_record, reason = verify_reset_token(raw_token)
    if not token_record:
        return jsonify({
            "error": "Bad Request",
            "message": reason,
        }), 400

    user = db.session.get(User, token_record.user_id)
    if not user or not user.is_active:
        return jsonify({
            "error": "Bad Request",
            "message": "Invalid or expired password reset token.",
        }), 400

    # Validate password strength before consuming token
    validation = validate_password(new_password, username=user.username, email=user.email)
    if not validation["is_valid"]:
        return jsonify({
            "error": "Bad Request",
            "message": "New password does not meet security requirements.",
            "details": validation,
        }), 400

    now = datetime.now(timezone.utc)
    user.password_hash = hash_password(new_password)
    user.password_algorithm = "argon2id"
    user.password_changed_at = now
    user.failed_attempts = 0
    user.lockout_until = None

    # Mark token single-use consumed
    consume_reset_token(token_record)

    # Revoke all active sessions after successful password reset
    revoked_count = revoke_all_sessions(user.id)
    db.session.commit()

    record_security_event(
        EVENT_PASSWORD_RESET_COMPLETED,
        user_id=user.id,
        username=user.username,
        ip_address=request.remote_addr,
        details={"revoked_sessions": revoked_count, "mfa_preserved": user.mfa_enabled},
    )

    return jsonify({
        "message": "Password has been reset successfully. All existing sessions have been revoked. Please log in with your new password.",
        "mfa_required_on_next_login": user.mfa_enabled,
        "revoked_sessions": revoked_count,
    }), 200
