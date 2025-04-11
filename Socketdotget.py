import socket
import hashlib

# Shared secret (must match receiver)
SECRET_KEY = "mysecret"

# Original message
message = "hello world"
full_message = message + "."  # Always end with a dot

# Derive a key using the secret and dot
dot = "."
key_derivation = SECRET_KEY + dot
encryption_key = hashlib.md5(key_derivation.encode()).hexdigest()[:16]

# Encrypt the message: convert to bytes and XOR
encrypted_bytes = bytearray()
for i, char in enumerate(full_message):
    key_byte = ord(encryption_key[i % len(encryption_key)])
    encrypted_bytes.append(ord(char) ^ key_byte)

# Disguise as a dot: send the encrypted data encoded in a single character (e.g., dot)
disguised_message = "."  # What outsiders see

# Send over socket (the disguised dot contains the encrypted data in its "metadata")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = '127.0.0.1'  # Localhost
port = 12345
s.connect((host, port))

# Send the disguised dot and the encrypted data
s.send(disguised_message.encode('utf-8') + bytes(encrypted_bytes))  # Dot first, then encrypted data
print(f"Sent disguised as: {disguised_message} (actual encrypted: {bytes(encrypted_bytes).hex()})")

s.close()
