from flask import jsonify, request
from app.detection.events import record_security_event, EVENT_RATE_LIMITED


def register_error_handlers(app):
    """Register standard JSON error handlers for the REST API."""

    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            "error": "Bad Request",
            "message": str(error.description) if hasattr(error, "description") else "The request was invalid."
        }), 400

    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            "error": "Unauthorized",
            "message": "Authentication required to access this resource."
        }), 401

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            "error": "Forbidden",
            "message": "You do not have permission to perform this action."
        }), 403

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "error": "Not Found",
            "message": "The requested resource could not be found."
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({
            "error": "Method Not Allowed",
            "message": "The method is not allowed for the requested URL."
        }), 405

    @app.errorhandler(429)
    def ratelimit_handler(error):
        record_security_event(
            EVENT_RATE_LIMITED,
            ip_address=request.remote_addr,
            success=False,
            details={"path": request.path, "method": request.method},
        )
        return jsonify({
            "error": "Too Many Requests",
            "message": "Rate limit exceeded. Please try again later."
        }), 429

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unexpected server error occurred."
        }), 500
