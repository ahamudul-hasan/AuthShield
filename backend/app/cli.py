import click
from flask import Flask
from app.extensions import db
from app.models.user import User
from app.auth.password import hash_password
from app.auth.validator import validate_password
from app.detection.events import record_security_event, EVENT_ADMIN_ACTION


def register_cli_commands(app: Flask) -> None:
    """Register administrative Flask CLI commands."""

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True, help="Administrator username")
    @click.option("--email", prompt=True, help="Administrator email address")
    @click.option(
        "--password",
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
        help="Administrator password",
    )
    def create_admin_command(username: str, email: str, password: str):
        """Create an administrator account securely via the command line (Step 2.9)."""
        clean_username = username.strip()
        clean_email = email.strip().lower()

        if not clean_username:
            raise click.ClickException("Username cannot be empty.")
        if not clean_email or "@" not in clean_email:
            raise click.ClickException("A valid email address is required.")

        if User.query.filter_by(username=clean_username).first():
            raise click.ClickException(f"Username '{clean_username}' is already registered.")
        if User.query.filter_by(email=clean_email).first():
            raise click.ClickException(f"Email '{clean_email}' is already registered.")

        validation = validate_password(password, username=clean_username, email=clean_email)
        if not validation["is_valid"]:
            reasons = "; ".join(validation["errors"])
            raise click.ClickException(f"Password rejected: {reasons}")

        admin_user = User(
            username=clean_username,
            email=clean_email,
            password_hash=hash_password(password),
            password_algorithm="argon2id",
            role="admin",
            is_active=True,
        )
        db.session.add(admin_user)
        db.session.commit()

        record_security_event(
            EVENT_ADMIN_ACTION,
            user_id=admin_user.id,
            username=admin_user.username,
            ip_address="127.0.0.1",
            details={"action": "cli_create_admin"},
        )

        click.echo(f"Administrator '{clean_username}' created successfully (ID: {admin_user.id}).")
