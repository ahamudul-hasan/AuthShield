from flask import Blueprint, jsonify
from app.auth.rbac import admin_required

alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")


@alerts_bp.route("", methods=["GET"])
@admin_required
def list_alerts():
    """Admin-only alerts endpoint."""
    return jsonify({
        "status": "ok",
        "alerts": []
    }), 200
