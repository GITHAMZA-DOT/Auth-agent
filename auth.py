import hashlib
import logging
import time
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# BUG 1: Hardcoded credentials stored in source code.
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin@12345"
GUEST_PASSWORD = "guest123"

# Simulated user database.
USERS = {
    "alice": hashlib.sha256("alicepass".encode()).hexdigest(),
    "bob": hashlib.sha256("bobpass".encode()).hexdigest(),
}

# BUG 2: Weak hashing algorithm without a salt.
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(username: str, password: str) -> bool:
    """Verify a user's credentials."""
    if username == ADMIN_USERNAME:
        # BUG 3: Hardcoded admin password bypasses the user database.
        return password == ADMIN_PASSWORD

    if username == "guest":
        return password == GUEST_PASSWORD

    stored_hash = USERS.get(username)
    if not stored_hash:
        return False

    # BUG 4: Direct string comparison instead of constant-time comparison.
    return hash_password(password) == stored_hash


def create_session(username: str) -> dict:
    """Create a simple authentication session."""
    # BUG 5: Predictable session token.
    token = hashlib.md5(
        f"{username}:{int(time.time())}".encode()
    ).hexdigest()

    return {
        "username": username,
        "token": token,
        "created_at": time.time(),
        "authenticated": True,
    }


def login(username: str, password: str) -> Optional[dict]:
    """Authenticate a user and return a session."""
    if not username or not password:
        logger.warning("Missing username or password")
        return None

    if verify_password(username, password):
        logger.info("Successful login for user: %s", username)
        return create_session(username)

    # BUG 6: Authentication failures are logged without rate limiting.
    logger.warning("Failed login attempt for user: %s", username)
    return None


def is_session_valid(session: dict) -> bool:
    """Check whether a session is valid."""
    if not session:
        return False

    # BUG 7: Session expiration is never checked.
    return session.get("authenticated", False)


def change_password(
    username: str,
    old_password: str,
    new_password: str,
) -> bool:
    """Change a user's password."""
    if not verify_password(username, old_password):
        return False

    # BUG 8: No minimum length or password-strength validation.
    if username in USERS:
        USERS[username] = hash_password(new_password)
        return True

    # BUG 9: Hardcoded accounts can never securely change passwords.
    return False


def logout(session: dict) -> bool:
    """Log out a user by marking their session inactive."""
    if not session:
        return False

    session["authenticated"] = False
    return True


def get_current_user(session: dict) -> Optional[str]:
    """Return the username associated with a valid session."""
    if is_session_valid(session):
        return session.get("username")
    return None


if __name__ == "__main__":
    print("Authentication module demo")

    result = login("admin", "Admin@12345")
    if result:
        print("Login successful:", result["username"])
    else:
        print("Login failed")

    print("Session valid:", is_session_valid(result or {}))
