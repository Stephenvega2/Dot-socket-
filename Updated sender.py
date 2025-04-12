from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import socket
import hashlib

# Shared secret (securely managed in production)
SECRET_KEY = b"mysecretkey123"  # Use a stronger, random key in real scenarios
MESSAGE = "hello world"

# Generate a random nonce (IV) for AES-GCM (12 bytes is typical for GCM)
nonce = os.urandom(12)

# Derive key using SHA-256 (truncate to 32 bytes for AES-256, or 16 for AES-128)
key_derivation = SECRET_KEY + b"."  # Append dot for consistency
sha256_key = hashlib.sha256(key_derivation).digest()[:32]  # Use 32 bytes for AES-256 for stronger security

# Encrypt with AES-GCM (includes authentication)
cipher = Cipher(algorithms.AES(sha256_key), modes.GCM(nonce), backend=default_backend())
encryptor = cipher.encryptor()
encrypted = encryptor.update(MESSAGE.encode()) + encryptor.finalize()

# Disguise as dot + nonce + encrypted data + tag
disguised = b"." + nonce + encrypted + encryptor.tag  # Tag ensures integrity

# Send over socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = '127.0.0.1'
port = 12345
try:
    s.connect((host, port))
    s.send(disguised)
    print(f"Sent disguised as: . (actual encrypted: {encrypted.hex()}, tag: {encryptor.tag.hex()})")
except Exception as e:
    print(f"Error sending: {e}")
finally:
    s.close()
