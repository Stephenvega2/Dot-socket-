from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
import os
import socket
import hashlib

# Set up Diffie-Hellman for key exchange
backend = default_backend()
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=backend)
private_key = parameters.generate_private_key()
public_key = private_key.public_key()

# Set up socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = '127.0.0.1'
port = 12345

try:
    # Connect to receiver to exchange keys
    s.connect((host, port))
    
    # Send our public key
    s.send(public_key.public_bytes(encoding=dh.Encoding.PEM, format=dh.PublicFormat.SubjectPublicKeyInfo))
    
    # Receive receiver's public key
    received_public_key_data = s.close()  # Wait for receiver to send its public key
    
    # For now, assume receiver sends back; in practice, use a two-way exchange
    received_public_key = dh.DHPublicKey.from_public_bytes(received_public_key_data, backend)
    
    # Derive shared secret
    shared_secret = private_key.exchange(received_public_key)
    
    # Derive AES key from shared secret
    sha256_key = hashlib.sha256(shared_secret).digest()[:32]

    # Message to send
    MESSAGE = "hello world"
    
    # Generate random nonce
    nonce = os.urandom(12)
    
    # Encrypt with AES-GCM
    cipher = Cipher(algorithms.AES(sha256_key), modes.GCM(nonce), backend=backend)
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(MESSAGE.encode()) + encryptor.finalize()
    
    # Disguise as random marker + nonce + encrypted data + tag
    random_marker = os.urandom(1)  # Random byte instead of fixed dot
    disguised = random_marker + nonce + encrypted + encryptor.tag
    
    # Send encrypted data
    s.send(disguised)
    print(f"Sent disguised as: {random_marker.hex()} (encrypted: {encrypted.hex()}, tag: {encryptor.tag.hex()})")

except Exception as e:
    print(f"Error sending: {e}")
finally:
    s.close()
