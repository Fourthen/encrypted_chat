import socket
import threading
import sys
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

# --------------------------
# Diffie-Hellman parameters
# --------------------------
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
G = 2

def dh_generate_private_key():
    return int.from_bytes(get_random_bytes(32), 'big')

def dh_generate_public_key(priv):
    return pow(G, priv, P)

def dh_generate_shared_key(priv, other_pub):
    shared = pow(other_pub, priv, P)
    return HKDF(shared.to_bytes(64, 'big'), 32, b'', SHA256)

# --------------------------
# Connect to server
# --------------------------
try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('192.168.0.41', 9812))
    print("Connected to server!")
except Exception as e:
    print(f"Could not connect to server: {e}")
    sys.exit(1)

try:
    # --------------------------
    # 1. Username
    # --------------------------
    prompt = client.recv(1024).decode()
    username = input(prompt)
    client.send(username.encode())

    # --------------------------
    # 2. Diffie-Hellman key exchange
    # --------------------------
    priv = dh_generate_private_key()
    pub = dh_generate_public_key(priv)

    other_pub_data = client.recv(256)
    if len(other_pub_data) != 256:
        print("Key exchange failed")
        sys.exit(1)
    other_pub = int.from_bytes(other_pub_data, 'big')  # receive server public key
    
    client.send(pub.to_bytes(256, 'big'))  # send client public key
    key = dh_generate_shared_key(priv, other_pub)

    # Receive connection confirmation
    welcome_msg = client.recv(1024).decode()
    print(welcome_msg)

except Exception as e:
    print(f"Error during connection setup: {e}")
    sys.exit(1)

# --------------------------
# 3. Sending messages
# --------------------------
def send_message(msg):
    try:
        cipher = ChaCha20_Poly1305.new(key=key)
        ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
        client.send(cipher.nonce)
        client.send(tag)
        client.send(len(ciphertext).to_bytes(4, 'big'))
        client.send(ciphertext)
    except Exception as e:
        print(f"Error sending message: {e}")

# --------------------------
# 4. Receiving messages
# --------------------------
def receive_messages():
    while True:
        try:
            nonce = client.recv(12)
            if not nonce or len(nonce) != 12:  # Connection closed
                print("\nDisconnected from server.")
                break
                
            tag = client.recv(16)
            if len(tag) != 16:
                break
                
            length_data = client.recv(4)
            if len(length_data) != 4:
                break
            length = int.from_bytes(length_data, 'big')
            
            ciphertext = client.recv(length)
            if len(ciphertext) != length:
                break

            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            print(f"\n{decrypted.decode()}")
            print("You: ", end="", flush=True)
        except Exception as e:
            print(f"\nDisconnected from server.")
            break

# Start receiving messages in a separate thread
threading.Thread(target=receive_messages, daemon=True).start()

# Main loop: read input and send
try:
    while True:
        msg = input("You: ")
        send_message(msg)
except KeyboardInterrupt:
    print("\nExiting...")
finally:
    client.close()