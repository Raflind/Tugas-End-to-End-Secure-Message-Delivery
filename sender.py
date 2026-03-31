import sys
import socket
import struct
import base64
from utils import (
    load_private_key, load_public_key,
    aes_generate_key, aes_encrypt,
    rsa_encrypt_key,
    compute_hash,
    sign,
    build_payload,
    serialize_public_key,
)

RECEIVER_IP   = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
RECEIVER_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 65432

ALICE_PRIVATE_KEY_PATH = "keys/alice_private.pem"
ALICE_PUBLIC_KEY_PATH  = "keys/alice_public.pem"
BOB_PUBLIC_KEY_PATH    = "keys/bob_public.pem"

SENDER_ID   = "Alice"
RECEIVER_ID = "Bob"

plaintext_str = input("Masukan pesan: ")
plaintext = plaintext_str.encode("utf-8")


print(f"Pesan : {plaintext_str}")

aes_key = aes_generate_key()

print(f"AES : Key {aes_key.hex()}")

iv, ciphertext = aes_encrypt(plaintext, aes_key)

print(f"IV         : {iv.hex()}")
print(f"Ciphertext : {base64.b64encode(ciphertext).decode()}")

bob_pub = load_public_key(BOB_PUBLIC_KEY_PATH)
encrypted_key = rsa_encrypt_key(aes_key, bob_pub)

hash_digest = compute_hash(plaintext)

print(f"    {hash_digest.hex()}")
alice_priv = load_private_key(ALICE_PRIVATE_KEY_PATH)
signature  = sign(hash_digest, alice_priv)

print(f"    {base64.b64encode(signature).decode()[:64]}...")

alice_pub     = load_public_key(ALICE_PUBLIC_KEY_PATH)
alice_pub_pem = serialize_public_key(alice_pub)

payload = build_payload(
    sender            = SENDER_ID,
    receiver          = RECEIVER_ID,
    iv                = iv,
    ciphertext        = ciphertext,
    encrypted_key     = encrypted_key,
    hash_digest       = hash_digest,
    signature         = signature,
    sender_public_key = alice_pub_pem,
)

print(f"\nMengirim ke {RECEIVER_IP}:{RECEIVER_PORT} ...")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((RECEIVER_IP, RECEIVER_PORT))
    length_prefix = struct.pack(">I", len(payload))
    s.sendall(length_prefix + payload)
    ack = s.recv(256)
