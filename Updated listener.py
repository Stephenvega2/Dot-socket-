from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket
import hashlib

# Shared secret
SECRET_KEY = b"mysecretkey123"

# Set up socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = '127.0.0.1'
port = 12345
s.bind((host, port))
s.listen(1)

print("Waiting for connection from sender...")
try:
    conn, addr = s.accept()
    print(f"Connection from: {addr}")

    # Receive data
    data = conn.recv(1024)
    if not data or data[0:1] != b".":
        print("Invalid data received")
        conn.close()
        s.close()
        exit()

    # Extract IV and encrypted data
    iv = data[1:17]  # First 16 bytes after dot are IV
    encrypted = data[17:]

    # Derive the same key using SHA-256
    key_derivation = SECRET_KEY + b"."  # Append dot for consistency
    sha256_key = hashlib.sha256(key_derivation).digest()[:16]  # Truncate to 16 bytes for AES-128

    # Decrypt
    cipher = Cipher(algorithms.AES(sha256_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()

    # Remove padding
    padding_len = ord(padded[-1])
    decrypted = padded[:-padding_len].decode('utf-8')

    print(f"h: {decrypted}")  # Output the message

except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()
    s.close()
