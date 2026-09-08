import os
import jwt
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Encryption key must come from Vercel Environment Variables
KEY_HEX = os.environ.get("ENCRYPTION_KEY")

if not KEY_HEX:
    raise RuntimeError("ENCRYPTION_KEY is not configured")

KEY = bytes.fromhex(KEY_HEX)

if len(KEY) != 32:
    raise RuntimeError("ENCRYPTION_KEY must be 32 bytes")

def encrypt_data(data: str) -> str:
    aes = AESGCM(KEY)
    nonce = os.urandom(12)
    encrypted = aes.encrypt(nonce, data.encode("utf-8"), None)
    return (nonce + encrypted).hex()

def decrypt_data(encrypted_hex: str) -> str:
    aes = AESGCM(KEY)
    encrypted = bytes.fromhex(encrypted_hex)
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    decrypted = aes.decrypt(nonce, ciphertext, None)
    return decrypted.decode("utf-8")


JWT_ALGORITHM = "HS256"

def get_jwt_secret():
    secret = os.environ.get("JWT_SECRET")

    if not secret:
        raise RuntimeError("JWT_SECRET is not configured")

    return secret

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
