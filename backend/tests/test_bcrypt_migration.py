import pytest
import bcrypt
from argon2 import PasswordHasher, Type
from app import create_app
from app.extensions import db
from app.models.user import User
from app.auth.password import identify_algorithm, verify_password, needs_rehash, hash_password


@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_identify_algorithm_variants():
    """Verify algorithm identifier correctly detects argon2id, bcrypt variants, md5, and unknown."""
    # Argon2 variants
    assert identify_algorithm("$argon2id$v=19$m=19456,t=2,p=1$...") == "argon2id"
    assert identify_algorithm("$argon2i$v=19$m=19456,t=2,p=1$...") == "argon2id"
    assert identify_algorithm("$argon2d$v=19$m=19456,t=2,p=1$...") == "argon2id"

    # Bcrypt prefix variants
    assert identify_algorithm("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy") == "bcrypt"
    assert identify_algorithm("$2b$12$SEwxkOJD1Zwe7oJfaWyC2.ygEPT3dQoYdz3dxlIfVvNlIGYqlp1R.") == "bcrypt"
    assert identify_algorithm("$2y$12$e8rO2zM.l2rDkYmO3kF9.ezJqVpT3dQoYdz3dxlIfVvNlIGYqlp1R.") == "bcrypt"
    assert identify_algorithm("$2x$12$e8rO2zM.l2rDkYmO3kF9.ezJqVpT3dQoYdz3dxlIfVvNlIGYqlp1R.") == "bcrypt"

    # MD5 (32-character hexadecimal)
    assert identify_algorithm("e10adc3949ba59abbe56e057f20f883e") == "md5"
    assert identify_algorithm("482C811DA5D5B4BC6D497FFA98491E38") == "md5"

    # Edge cases / unknown
    assert identify_algorithm("") == "unknown"
    assert identify_algorithm(None) == "unknown"
    assert identify_algorithm("plaintextpassword") == "unknown"
    assert identify_algorithm("$pbkdf2-sha256$29000$...") == "unknown"


def test_verify_password_bcrypt():
    """Verify bcrypt hashes can be verified with correct and incorrect passwords."""
    plain = "SuperSecureLegacyPassword#2024"
    h10 = bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
    h12 = bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")

    # Correct passwords
    assert verify_password(plain, h10) is True
    assert verify_password(plain, h12) is True

    # Incorrect passwords
    assert verify_password("WrongPassword", h10) is False
    assert verify_password("wrongpassword", h12) is False

    # Edge cases
    assert verify_password("", h10) is False
    assert verify_password(plain, "") is False
    assert verify_password(plain, "corrupted_bcrypt_hash") is False


def test_needs_rehash_for_bcrypt_and_argon2():
    """Test that needs_rehash correctly identifies bcrypt and weak Argon2 for upgrading."""
    # Bcrypt hashes MUST always need rehashing to Argon2id
    bcrypt_h = bcrypt.hashpw(b"legacy_pwd", bcrypt.gensalt(rounds=10)).decode("utf-8")
    assert needs_rehash(bcrypt_h) is True

    # Standard Argon2id hash should NOT need rehashing
    fresh_argon = hash_password("test_pwd")
    assert needs_rehash(fresh_argon) is False

    # Older Argon2id hash with lower parameters (e.g. t=1, m=8192) MUST need rehashing
    weak_hasher = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1, type=Type.ID)
    weak_argon = weak_hasher.hash("test_pwd")
    assert needs_rehash(weak_argon) is True


def test_bcrypt_user_migration_on_login(client, app):
    """
    Test the Step 2.3 migration flow:
    1. Seed a user with bcrypt hash.
    2. Attempt login with wrong password -> fails, hash untouched.
    3. Login with correct password -> succeeds, hash upgraded to Argon2id in DB.
    4. Confirm password itself was not changed.
    """
    legacy_password = "CourseworkP11Password!"
    bcrypt_hash = bcrypt.hashpw(legacy_password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")

    with app.app_context():
        user = User(
            username="p11_legacy_user",
            email="p11_legacy@example.com",
            password_hash=bcrypt_hash,
            password_algorithm="bcrypt"
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    # Step 1: Wrong password attempt
    res_wrong = client.post("/api/auth/login", json={
        "username": "p11_legacy_user",
        "password": "WrongPasswordAttempt"
    })
    assert res_wrong.status_code == 401

    # Verify hash is still the original bcrypt hash
    with app.app_context():
        u = db.session.get(User, user_id)
        assert u.password_hash == bcrypt_hash
        assert u.password_algorithm == "bcrypt"
        assert u.failed_attempts == 1

    # Step 2: Correct password login
    res_correct = client.post("/api/auth/login", json={
        "username": "p11_legacy_user",
        "password": legacy_password
    })
    assert res_correct.status_code == 200
    data = res_correct.get_json()
    assert data["message"] == "Login successful."
    assert data["hash_upgraded"] is True
    assert data["password_algorithm"] == "argon2id"

    # Step 3: Inspect database record
    with app.app_context():
        u_upgraded = db.session.get(User, user_id)
        assert u_upgraded.password_algorithm == "argon2id"
        assert u_upgraded.password_hash.startswith("$argon2id$v=19$")
        assert u_upgraded.password_hash != bcrypt_hash
        assert u_upgraded.failed_attempts == 0

        # Password itself unchanged: verifies against newly stored Argon2id hash
        assert verify_password(legacy_password, u_upgraded.password_hash) is True


def test_subsequent_login_after_upgrade(client, app):
    """Confirm subsequent login uses Argon2id without triggering another upgrade."""
    legacy_password = "AnotherLegacyUser123"
    bcrypt_hash = bcrypt.hashpw(legacy_password.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")

    with app.app_context():
        user = User(
            username="relogin_user",
            email="relogin@example.com",
            password_hash=bcrypt_hash,
            password_algorithm="bcrypt"
        )
        db.session.add(user)
        db.session.commit()

    # First login (upgrades from bcrypt to Argon2id)
    res1 = client.post("/api/auth/login", json={
        "username": "relogin_user",
        "password": legacy_password
    })
    assert res1.status_code == 200
    assert res1.get_json()["hash_upgraded"] is True

    # Record the newly generated Argon2id hash
    with app.app_context():
        u = User.query.filter_by(username="relogin_user").first()
        argon_hash_first = u.password_hash
        assert argon_hash_first.startswith("$argon2id$v=19$")

    # Second login with same password (should verify with Argon2id and NOT upgrade again)
    res2 = client.post("/api/auth/login", json={
        "username": "relogin_user",
        "password": legacy_password
    })
    assert res2.status_code == 200
    assert res2.get_json()["hash_upgraded"] is False

    with app.app_context():
        u = User.query.filter_by(username="relogin_user").first()
        assert u.password_hash == argon_hash_first
        assert u.password_algorithm == "argon2id"


def test_real_coursework_hashes_migration(client, app):
    """
    Test migration with the actual hashes from the P11 coursework database (legacy/database/users.db).
    testvictim (rounds=12) and victim_r10 (rounds=10) with known password 'password123'.
    """
    hashes = {
        "testvictim": "$2b$12$SEwxkOJD1Zwe7oJfaWyC2.ygEPT3dQoYdz3dxlIfVvNlIGYqlp1R.",
        "victim_r10": "$2b$10$CE5kWeuN4ulTOPCK4uj64.nNRTcfjJtB5pCRymesKe/NFKuMt/Mmq",
    }
    password = "password123"

    with app.app_context():
        for username, h in hashes.items():
            u = User(
                username=username,
                email=f"{username}@coursework.local",
                password_hash=h,
                password_algorithm="bcrypt"
            )
            db.session.add(u)
        db.session.commit()

    for username in hashes.keys():
        res = client.post("/api/auth/login", json={
            "username": username,
            "password": password
        })
        assert res.status_code == 200
        assert res.get_json()["hash_upgraded"] is True

        with app.app_context():
            user = User.query.filter_by(username=username).first()
            assert user.password_algorithm == "argon2id"
            assert user.password_hash.startswith("$argon2id$v=19$")
            assert verify_password(password, user.password_hash) is True
