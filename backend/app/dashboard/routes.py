from flask import Blueprint, jsonify

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


@dashboard_bp.route("/stats", methods=["GET"])
def dashboard_stats():
    """Initial dashboard statistics endpoint."""
    return jsonify({
        "status": "ok",
        "total_events": 0,
        "active_alerts": 0,
        "active_sessions": 0
    }), 200
