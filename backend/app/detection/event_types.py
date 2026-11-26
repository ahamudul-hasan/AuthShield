"""
Canonical security event type definitions for AuthShield 2.0 (Step 3.1).
All authentication, session, admin, and defense routes must use these shared names
so detection rules, analytics, and audit reports stay consistent.
"""

EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
EVENT_LOGIN_FAILURE = "LOGIN_FAILURE"
EVENT_MFA_SUCCESS = "MFA_SUCCESS"
EVENT_MFA_FAILURE = "MFA_FAILURE"
EVENT_ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
EVENT_PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED"
EVENT_PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED"
EVENT_SESSION_CREATED = "SESSION_CREATED"
EVENT_SESSION_REVOKED = "SESSION_REVOKED"
EVENT_MFA_ENABLED = "MFA_ENABLED"
EVENT_MFA_DISABLED = "MFA_DISABLED"
EVENT_ADMIN_ACTION = "ADMIN_ACTION"
EVENT_IP_BLOCKED = "IP_BLOCKED"
EVENT_IP_UNBLOCKED = "IP_UNBLOCKED"
EVENT_USER_REGISTERED = "USER_REGISTERED"
EVENT_LOGIN_BLOCKED = "LOGIN_BLOCKED"
EVENT_RATE_LIMITED = "RATE_LIMITED"
EVENT_PASSWORD_CHANGED = "PASSWORD_CHANGED"
EVENT_RECOVERY_CODE_USED = "RECOVERY_CODE_USED"

EVENT_DESCRIPTIONS = {
    EVENT_LOGIN_SUCCESS: "Password and required authentication checks succeeded",
    EVENT_LOGIN_FAILURE: "Login failed",
    EVENT_MFA_SUCCESS: "MFA verification succeeded",
    EVENT_MFA_FAILURE: "MFA verification failed",
    EVENT_ACCOUNT_LOCKED: "Account entered a temporary lockout",
    EVENT_PASSWORD_RESET_REQUESTED: "A reset was requested",
    EVENT_PASSWORD_RESET_COMPLETED: "A password reset succeeded",
    EVENT_SESSION_CREATED: "A session was created",
    EVENT_SESSION_REVOKED: "A session was revoked",
    EVENT_MFA_ENABLED: "MFA was enabled",
    EVENT_MFA_DISABLED: "MFA was disabled",
    EVENT_ADMIN_ACTION: "An administrator performed a security action",
    EVENT_IP_BLOCKED: "A configured defense blocked an IP",
    EVENT_IP_UNBLOCKED: "A blocked IP was released",
    EVENT_USER_REGISTERED: "A new account was created",
    EVENT_LOGIN_BLOCKED: "A login attempt was rejected because the account was locked",
    EVENT_RATE_LIMITED: "A request exceeded a rate limit",
    EVENT_PASSWORD_CHANGED: "A signed-in user changed their password",
    EVENT_RECOVERY_CODE_USED: "A recovery code was used",
}

ALL_EVENT_TYPES = frozenset(EVENT_DESCRIPTIONS.keys())


def is_valid_event_type(event_type: str) -> bool:
    """Return True if event_type is a recognized canonical AuthShield event name."""
    return event_type in ALL_EVENT_TYPES
