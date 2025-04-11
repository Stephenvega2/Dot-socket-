import socket
import hashlib

# Shared secret (must match sender)
SECRET_KEY = "mysecret"

# Set up socket to receive
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = '127.0.0.1'  # Localhost
port = 12345
s.bind((host, port))
s.listen(1)

print("Waiting for connection from sender...")
conn, addr = s.accept()
print(f"Connection from: {addr}")

# Receive the disguised message (first character should be dot, followed by encrypted data)
data = conn.recv(1024)  # Receive all data
if not data:
    print("No data received")
    conn.close()
    s.close()
    exit()

# Split: first byte is the dot, rest is encrypted data
disguised_dot = data[0:1].decode('utf-8')
encrypted_data = bytearray(data[1:])

print(f"Received disguised as: {disguised_dot}")

# Derive the same key using the secret and expected dot
dot = "."
key_derivation = SECRET_KEY + dot
decryption_key = hashlib.md5(key_derivation.encode()).hexdigest()[:16]

# Decrypt the data: XOR back
decrypted_bytes = bytearray()
for i, byte in enumerate(encrypted_data):
    key_byte = ord(decryption_key[i % len(decryption_key)])
    decrypted_bytes.append(byte ^ key_byte)

# Convert back to string
decrypted_message = decrypted_bytes.decode('utf-8')

# Check if it ends with a dot and print as 'h'
if decrypted_message.endswith('.'):
    h = decrypted_message  # Store as 'h'
    print(f"h: {h}")  # This is what you wanted: print(h) with the dot
else:
    print("Invalid message: no dot at end")

conn.close()
s.close()
