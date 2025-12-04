import socket
import threading
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

# --------------------------
# Diffie-Hellman parameters
# --------------------------
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
G = 2

# Generate private DH key (secret)
def dh_generate_private_key():
    return int.from_bytes(get_random_bytes(32), 'big')

# Generate public DH key from private key
def dh_generate_public_key(priv):
    return pow(G, priv, P)

# Generate shared key from own private key and other's public key
def dh_generate_shared_key(priv, other_pub):
    shared = pow(other_pub, priv, P)
    return HKDF(shared.to_bytes(64, 'big'), 32, b'', SHA256)

# --------------------------
# Server setup
# --------------------------
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 9812))
server.listen(5)  # Accept multiple clients
print("Server listening on port 9812...")

clients = []  # List of tuples: (conn, key, username)
clients_lock = threading.Lock()

# Handle a single client
def handle_client(conn, addr):
    username = None
    key = None
    
    try:
        # --------------------------
        # 1. Username exchange
        # --------------------------
        conn.send(b"Enter your username: ")
        username_data = conn.recv(1024)
        if not username_data:
            print(f"Client {addr} disconnected during username exchange")
            conn.close()
            return
        username = username_data.decode().strip()
        print(f"Username received: {username}")

        # --------------------------
        # 2. Diffie-Hellman key exchange
        # --------------------------
        priv = dh_generate_private_key()
        pub = dh_generate_public_key(priv)

        conn.send(pub.to_bytes(256, 'big'))       # send server public key
        other_pub_data = conn.recv(256)
        if len(other_pub_data) != 256:
            print(f"Invalid key exchange from {username}")
            conn.close()
            return
        other_pub = int.from_bytes(other_pub_data, 'big')  # receive client public key
        key = dh_generate_shared_key(priv, other_pub)

        with clients_lock:
            clients.append((conn, key, username))
        print(f"{username} connected from {addr}.")

        conn.send(b"You are connected! You can start chatting.\n")

        # --------------------------
        # 3. Receive messages and broadcast
        # --------------------------
        while True:
            # Receive nonce, tag, length, and ciphertext
            nonce = conn.recv(12)
            if not nonce or len(nonce) != 12:
                break
                
            tag = conn.recv(16)
            if len(tag) != 16:
                break
                
            length_data = conn.recv(4)
            if len(length_data) != 4:
                break
            length = int.from_bytes(length_data, 'big')
            
            ciphertext = conn.recv(length)
            if len(ciphertext) != length:
                break

            # Decrypt message
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            message_text = decrypted.decode()

            # Format message with username and broadcast to all other clients
            formatted_msg = f"{username}: {message_text}"
            
            with clients_lock:
                for c, k, u in clients:
                    if c != conn:
                        try:
                            # Re-encrypt with each client's key
                            cipher2 = ChaCha20_Poly1305.new(key=k)
                            ct, tag2 = cipher2.encrypt_and_digest(formatted_msg.encode())
                            msg_len = len(ct).to_bytes(4, 'big')
                            c.send(cipher2.nonce + tag2 + msg_len + ct)
                        except:
                            pass  # Client might have disconnected

    except Exception as e:
        print(f"Error with {username or addr}: {e}")
    finally:
        if username and key:
            with clients_lock:
                try:
                    clients.remove((conn, key, username))
                except ValueError:
                    pass
            print(f"{username} disconnected.")
        conn.close()

# Accept clients indefinitely
while True:
    try:
        conn, addr = server.accept()
        print(f"New connection from {addr}")
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.close()
        break
    except Exception as e:
        print(f"Server error: {e}")