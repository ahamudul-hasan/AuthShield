from flask import Blueprint, jsonify, request
from app.auth.rbac import admin_required
from app.detection.alert_manager import get_alerts

alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")


@alerts_bp.route("", methods=["GET"])
@admin_required
def list_alerts():
    """Admin-only alerts endpoint."""
    status = request.args.get("status")
    alert_type = request.args.get("alert_type")
    alerts = get_alerts(status=status, alert_type=alert_type)
    return jsonify({
        "status": "ok",
        "alerts": alerts,
        "total": len(alerts),
    }), 200
