import os
from utils import generate_rsa_keypair, save_private_key, save_public_key

KEYS_DIR = "keys"
os.makedirs(KEYS_DIR, exist_ok=True)

for name in ("alice", "bob"):
    print(f"\nGenerating RSA-2048 key-pair for {name.upper()}...")
    priv, pub = generate_rsa_keypair(key_size=2048)
    save_private_key(priv, f"{KEYS_DIR}/{name}_private.pem")
    save_public_key(pub,  f"{KEYS_DIR}/{name}_public.pem")
