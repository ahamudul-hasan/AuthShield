from datetime import datetime, timezone
from flask import Blueprint, jsonify, request, g
from app.extensions import db
from app.models.user import User
from app.auth.rbac import admin_required, VALID_ROLES
from app.auth.session_manager import revoke_all_sessions
from app.detection.events import (
    record_security_event,
    get_recent_security_events,
    EVENT_ADMIN_ACTION,
)

admin_bp = Blueprint("admin", __name__, url_prefix="/api")


@admin_bp.route("/users", methods=["GET"])
@admin_required
def list_users():
    """Admin-only user-security overview listing accounts without sensitive credentials."""
    users = User.query.order_by(User.id.asc()).all()
    return jsonify({
        "users": [u.to_dict(include_admin_fields=True) for u in users],
        "total": len(users),
    }), 200


@admin_bp.route("/users/<int:user_id>/role", methods=["PATCH"])
@admin_required
def update_user_role(user_id: int):
    """Admin-only endpoint to change a user's role and revoke their old sessions."""
    data = request.get_json(silent=True) or {}
    new_role = data.get("role", "").strip().lower()

    if new_role not in VALID_ROLES:
        return jsonify({
            "error": "Bad Request",
            "message": f"Invalid role. Allowed roles: {', '.join(VALID_ROLES)}.",
        }), 400

    target = db.session.get(User, user_id)
    if not target:
        return jsonify({"error": "NotFound", "message": "User not found."}), 404

    if target.id == g.current_user.id and new_role != "admin":
        return jsonify({
            "error": "Bad Request",
            "message": "Administrators cannot remove their own admin role.",
        }), 400

    old_role = target.role
    target.role = new_role
    target.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    # Rotate/revoke sessions on privilege change (Step 2.7 Task 4)
    revoked_sessions = revoke_all_sessions(target.id) if old_role != new_role else 0

    record_security_event(
        EVENT_ADMIN_ACTION,
        user_id=g.current_user.id,
        username=g.current_user.username,
        ip_address=request.remote_addr,
        details={
            "action": "role_updated",
            "target_user_id": target.id,
            "target_username": target.username,
            "old_role": old_role,
            "new_role": new_role,
            "revoked_sessions": revoked_sessions,
        },
    )

    return jsonify({
        "message": f"User '{target.username}' role updated to '{new_role}'.",
        "user": target.to_dict(include_admin_fields=True),
    }), 200


@admin_bp.route("/users/<int:user_id>/status", methods=["PATCH"])
@admin_required
def update_user_status(user_id: int):
    """Admin-only endpoint to activate or deactivate a user account."""
    data = request.get_json(silent=True) or {}
    if "is_active" not in data or not isinstance(data["is_active"], bool):
        return jsonify({
            "error": "Bad Request",
            "message": "Boolean field 'is_active' is required.",
        }), 400

    target = db.session.get(User, user_id)
    if not target:
        return jsonify({"error": "NotFound", "message": "User not found."}), 404

    if target.id == g.current_user.id and not data["is_active"]:
        return jsonify({
            "error": "Bad Request",
            "message": "Administrators cannot deactivate their own account.",
        }), 400

    target.is_active = data["is_active"]
    target.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    revoked_sessions = revoke_all_sessions(target.id) if not target.is_active else 0

    record_security_event(
        EVENT_ADMIN_ACTION,
        user_id=g.current_user.id,
        username=g.current_user.username,
        ip_address=request.remote_addr,
        details={
            "action": "account_status_updated",
            "target_user_id": target.id,
            "target_username": target.username,
            "is_active": target.is_active,
            "revoked_sessions": revoked_sessions,
        },
    )

    return jsonify({
        "message": f"User '{target.username}' is now {'active' if target.is_active else 'inactive'}.",
        "user": target.to_dict(include_admin_fields=True),
    }), 200


@admin_bp.route("/events", methods=["GET"])
@admin_required
def list_security_events():
    """Admin-only security events endpoint."""
    event_type = request.args.get("event_type")
    events = get_recent_security_events(event_type=event_type)
    return jsonify({
        "events": list(reversed(events)),
        "total": len(events),
    }), 200
