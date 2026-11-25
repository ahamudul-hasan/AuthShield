from functools import wraps
from flask import g, jsonify, request
from app.auth.session_manager import login_required
from app.detection.events import record_security_event, EVENT_ADMIN_ACTION

ROLE_USER = "user"
ROLE_ADMIN = "admin"
VALID_ROLES = (ROLE_USER, ROLE_ADMIN)


def require_role(*allowed_roles: str):
    """
    Decorator enforcing session authentication AND role-based authorization.
    - Returns 401 Unauthorized if no valid session exists.
    - Returns 403 Forbidden if the authenticated user lacks one of `allowed_roles`.
    """
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if not user or user.role not in allowed_roles:
                record_security_event(
                    EVENT_ADMIN_ACTION,
                    user_id=user.id if user else None,
                    username=user.username if user else None,
                    ip_address=request.remote_addr,
                    details={
                        "action": "rbac_access_denied",
                        "endpoint": request.path,
                        "method": request.method,
                        "required_roles": list(allowed_roles),
                        "actual_role": user.role if user else None,
                    },
                )
                return jsonify({
                    "error": "Forbidden",
                    "message": "Administrator privileges are required to access this resource.",
                }), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def admin_required(f):
    """Shortcut decorator restricting an endpoint strictly to users with role='admin'."""
    return require_role(ROLE_ADMIN)(f)
