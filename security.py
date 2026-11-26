import os
import hmac
import json
import time
import base64
import hashlib
from cryptography.fernet import Fernet


def _get_fernet() -> Fernet:
    key = os.getenv("VAULT_MASTER_KEY", "").strip()
    if not key:
        raise RuntimeError("VAULT_MASTER_KEY is not set in .env")
    return Fernet(key.encode("utf-8"))


def encrypt_secret(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    return _get_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return f"{base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_b64, dk_b64 = stored_hash.split("$", 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def issue_token(employee_id: int, username: str) -> str:
    secret = os.getenv("TOKEN_SECRET", "").encode("utf-8")
    ttl_sec = int(os.getenv("TOKEN_TTL_HOURS", "12")) * 3600
    payload = {
        "eid": employee_id,
        "usr": username,
        "exp": int(time.time()) + ttl_sec,
    }
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_token(token: str) -> dict:
    secret = os.getenv("TOKEN_SECRET", "").encode("utf-8")
    try:
        body, sig = token.split(".", 1)
        expected_sig = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            raise ValueError("Invalid token signature.")
        payload = json.loads(base64.urlsafe_b64decode(body.encode()).decode())
        if payload.get("exp", 0) < int(time.time()):
            raise ValueError("Session expired. Sign in again.")
        return payload
    except Exception as exc:
        raise ValueError(str(exc))