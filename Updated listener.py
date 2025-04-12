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

    # Extract nonce, encrypted data, and tag
    nonce = data[1:13]  # First 12 bytes after dot are nonce
    encrypted = data[13:-16]  # Everything after nonce, before last 16 bytes (tag)
    tag = data[-16:]  # Last 16 bytes are the authentication tag

    # Derive the same key using SHA-256
    key_derivation = SECRET_KEY + b"."  # Append dot for consistency
    sha256_key = hashlib.sha256(key_derivation).digest()[:32]  # Use 32 bytes for AES-256

    # Decrypt with AES-GCM (verify integrity)
    cipher = Cipher(algorithms.AES(sha256_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()

    print(f"h: {decrypted.decode('utf-8')}")  # Output the message

except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()
    s.close()
