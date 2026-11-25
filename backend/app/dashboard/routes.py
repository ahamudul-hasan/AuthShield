from flask import Blueprint, jsonify
from app.auth.rbac import admin_required
from app.models.user import User
from app.models.session import UserSession
from app.detection.events import get_recent_security_events

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


@dashboard_bp.route("/stats", methods=["GET"])
@dashboard_bp.route("/summary", methods=["GET"])
@admin_required
def dashboard_stats():
    """Admin-only dashboard statistics endpoint."""
    total_users = User.query.count()
    active_sessions = UserSession.query.filter_by(is_revoked=False).count()
    recent_events = len(get_recent_security_events())

    return jsonify({
        "status": "ok",
        "total_users": total_users,
        "total_events": recent_events,
        "active_alerts": 0,
        "active_sessions": active_sessions,
    }), 200
