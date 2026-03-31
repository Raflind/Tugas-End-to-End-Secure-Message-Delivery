import sys
import socket
import struct
import base64

from utils import (
    load_private_key, load_public_key,
    rsa_decrypt_key,
    aes_decrypt,
    compute_hash, verify_hash,
    verify_signature,
    parse_payload,
)
BIND_IP = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
PORT    = int(sys.argv[2]) if len(sys.argv) > 2 else 65432

BOB_PRIVATE_KEY_PATH   = "keys/bob_private.pem"
ALICE_PUBLIC_KEY_PATH  = "keys/alice_public.pem"

print(f"Listening on {BIND_IP}:{PORT}\n")

bob_priv  = load_private_key(BOB_PRIVATE_KEY_PATH)
alice_pub = load_public_key(ALICE_PUBLIC_KEY_PATH)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND_IP, PORT))
    server.listen(1)

    conn, addr = server.accept()
    with conn:
        sender_ip, sender_port = addr
        print(f"Connection from {sender_ip}:{sender_port}")
        raw_len = conn.recv(4)
        msg_len = struct.unpack(">I", raw_len)[0]
        data = b""
        while len(data) < msg_len:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk

        print(f"Received {len(data)} bytes")

        conn.sendall(b"ACK: Payload received by Bob")

p = parse_payload(data)
print(f"Ciphertext (b64): {base64.b64encode(p['ciphertext']).decode()[:64]}...")
aes_key = rsa_decrypt_key(p["encrypted_key"], bob_priv)
plaintext = aes_decrypt(p["iv"], p["ciphertext"], aes_key)
plaintext_str = plaintext.decode("utf-8")
received_hash  = p["hash"]
computed_hash  = compute_hash(plaintext)
hash_ok        = verify_hash(plaintext, received_hash)

sig_ok = verify_signature(received_hash, p["signature"], alice_pub)

decryption_ok = True

if decryption_ok and hash_ok and sig_ok:
    print(f"Pesan:")
    print(f"{plaintext_str}")
else:
    print(f"Signature, Hash tidak sesuai")
