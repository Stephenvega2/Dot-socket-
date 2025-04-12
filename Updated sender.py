from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import socket
import hashlib

# Shared secret (securely managed in production)
SECRET_KEY = b"mysecretkey123"  # Use a stronger, random key in real scenarios
MESSAGE = "hello world"

# Generate a random IV (Initialization Vector) for AES
iv = os.urandom(16)

# Derive key using SHA-256 (truncate to 16 bytes for AES-128)
key_derivation = SECRET_KEY + b"."  # Append dot for consistency
sha256_key = hashlib.sha256(key_derivation).digest()[:16]  # Truncate to 16 bytes for AES-128

# Pad message to be multiple of 16 bytes (AES block size)
padding_length = 16 - (len(MESSAGE) % 16)
MESSAGE += chr(padding_length) * padding_length

# Encrypt with AES in CBC mode
cipher = Cipher(algorithms.AES(sha256_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted = encryptor.update(MESSAGE.encode()) + encryptor.finalize()

# Disguise as dot + IV + encrypted data
disguised = b"." + iv + encrypted

# Send over socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = '127.0.0.1'
port = 12345
try:
    s.connect((host, port))
    s.send(disguised)
    print(f"Sent disguised as: . (actual encrypted: {encrypted.hex()})")
except Exception as e:
    print(f"Error sending: {e}")
finally:
    s.close()
