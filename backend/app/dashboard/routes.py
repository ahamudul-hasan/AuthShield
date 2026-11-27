from flask import Blueprint, jsonify
from app.auth.rbac import admin_required
from app.models.user import User
from app.models.session import UserSession
from app.detection.event_repository import count_total_events
from app.detection.alert_manager import count_active_alerts

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


@dashboard_bp.route("/stats", methods=["GET"])
@dashboard_bp.route("/summary", methods=["GET"])
@admin_required
def dashboard_stats():
    """Admin-only dashboard statistics endpoint."""
    total_users = User.query.count()
    active_sessions = UserSession.query.filter_by(is_revoked=False).count()
    total_events = count_total_events()
    active_alerts = count_active_alerts()

    return jsonify({
        "status": "ok",
        "total_users": total_users,
        "total_events": total_events,
        "active_alerts": active_alerts,
        "active_sessions": active_sessions,
    }), 200
