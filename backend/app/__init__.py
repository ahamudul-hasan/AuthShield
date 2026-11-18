import os
from flask import Flask, jsonify
from app.config import config_by_name
from app.extensions import db, migrate, cors, limiter
from app.errors import register_error_handlers
from app.auth.routes import auth_bp
from app.alerts.routes import alerts_bp
from app.dashboard.routes import dashboard_bp


def create_app(config_name=None):
    """Application factory for AuthShield 2.0 backend."""
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)
    config_obj = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(config_obj)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    cors.init_app(app, supports_credentials=True)
    limiter.init_app(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(dashboard_bp)

    # Register JSON error handlers
    register_error_handlers(app)

    # Health check endpoint
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
