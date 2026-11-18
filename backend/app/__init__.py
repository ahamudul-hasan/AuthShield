import os
from flask import Flask, jsonify
from app.config import config_by_name
from app.extensions import db, migrate, cors, limiter


def create_app(config_name=None):
    """Application factory for AuthShield 2.0 backend."""
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)
    app.config.from_object(config_by_name.get(config_name, config_by_name["default"]))

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    cors.init_app(app, supports_credentials=True)
    limiter.init_app(app)

    # Health check endpoint (Step 1.6)
    @app.route("/api/health", methods=["GET"])
    def health_check():
        db_status = "ok"
        try:
            from sqlalchemy import text
            db.session.execute(text("SELECT 1"))
        except Exception:
            db_status = "unreachable"

        return jsonify({
            "status": "ok",
            "service": "authshield-backend",
            "database": db_status
        }), 200

    return app
