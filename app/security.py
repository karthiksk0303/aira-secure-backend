import os
import jwt
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =========================
# AES-256-GCM ENCRYPTION
# =========================

KEY_FILE = ".encryption_key"


def get_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()

    key = AESGCM.generate_key(bit_length=256)

    with open(KEY_FILE, "wb") as f:
        f.write(key)

    os.chmod(KEY_FILE, 0o600)

    return key


KEY = get_or_create_key()


def encrypt_data(data: str) -> str:
    aes = AESGCM(KEY)

    nonce = os.urandom(12)

    encrypted = aes.encrypt(
        nonce,
        data.encode("utf-8"),
        None
    )

    return (nonce + encrypted).hex()


def decrypt_data(encrypted_hex: str) -> str:
    aes = AESGCM(KEY)

    encrypted = bytes.fromhex(encrypted_hex)

    nonce = encrypted[:12]
    ciphertext = encrypted[12:]

    decrypted = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return decrypted.decode("utf-8")


# =========================
# JWT AUTHENTICATION
# =========================

JWT_SECRET_FILE = ".jwt_secret"
JWT_ALGORITHM = "HS256"


def get_jwt_secret():
    with open(JWT_SECRET_FILE, "r") as f:
        return f.read().strip()


def create_access_token(username: str, role: str):
    now = datetime.now(timezone.utc)

    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=30)
    }

    return jwt.encode(
        payload,
        get_jwt_secret(),
        algorithm=JWT_ALGORITHM
    )


def decode_access_token(token: str):
    return jwt.decode(
        token,
        get_jwt_secret(),
        algorithms=[JWT_ALGORITHM]
    )

