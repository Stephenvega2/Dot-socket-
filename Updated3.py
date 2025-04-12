from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
import socket
import hashlib

# Set up socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = '127.0.0.1'
port = 12345
s.bind((host, port))
s.listen(1)

print("Waiting for connection from sender...")
backend = default_backend()

try:
    conn, addr = s.accept()
    print(f"Connection from: {addr}")

    # Set up Diffie-Hellman
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=backend)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    # Exchange public keys
    conn.send(public_key.public_bytes(encoding=dh.Encoding.PEM, format=dh.PublicFormat.SubjectPublicKeyInfo))
    received_public_key_data = conn.recv(2048)  # Receive sender's public key
    
    received_public_key = dh.DHPublicKey.from_public_bytes(received_public_key_data, backend)
    shared_secret = private_key.exchange(received_public_key)
    
    # Derive AES key
    sha256_key = hashlib.sha256(shared_secret).digest()[:32]

    # Receive encrypted data
    data = conn.recv(1024)
    if not data or len(data) < 29:  # Ensure minimum length (1 marker + 12 nonce + 16 tag)
        print("Invalid data received")
        conn.close()
        s.close()
        exit()

    # Extract random marker, nonce, encrypted data, and tag
    random_marker = data[0:1]  # First byte is the marker
    nonce = data[1:13]  # Next 12 bytes are nonce
    encrypted = data[13:-16]  # Everything after nonce, before last 16 bytes (tag)
    tag = data[-16:]  # Last 16 bytes are the authentication tag

    # Decrypt with AES-GCM
    cipher = Cipher(algorithms.AES(sha256_key), modes.GCM(nonce, tag), backend=backend)
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()

    print(f"Received and decrypted: {decrypted.decode('utf-8')}")

except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()
    s.close()
