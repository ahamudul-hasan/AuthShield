from flask import Blueprint, jsonify

alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")


@alerts_bp.route("", methods=["GET"])
def list_alerts():
    """Initial alerts endpoint."""
    return jsonify({
        "status": "ok",
        "alerts": []
    }), 200
