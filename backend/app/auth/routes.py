from flask import Blueprint, jsonify

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/status", methods=["GET"])
def auth_status():
    """Initial auth module status endpoint."""
    return jsonify({
        "status": "ready",
        "module": "auth",
        "supported_algorithms": ["argon2id", "bcrypt"]
    }), 200
