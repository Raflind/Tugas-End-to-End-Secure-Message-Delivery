import os
import json
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(key_size: int = 2048):
    """Generate an RSA key-pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def save_private_key(private_key, filepath: str, password: bytes = None):
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password else serialization.NoEncryption()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption
    )
    with open(filepath, "wb") as f:
        f.write(pem)
    print(f"  [✓] Private key saved → {filepath}")


def save_public_key(public_key, filepath: str):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filepath, "wb") as f:
        f.write(pem)
    print(f"  [✓] Public key saved  → {filepath}")


def load_private_key(filepath: str, password: bytes = None):
    with open(filepath, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password,
                                                   backend=default_backend())


def load_public_key(filepath: str):
    with open(filepath, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def aes_generate_key() -> bytes:
    return os.urandom(32)


def aes_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    pad_len = 16 - (len(plaintext) % 16)
    plaintext_padded = plaintext + bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
    return iv, ciphertext


def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len]


def rsa_encrypt_key(symmetric_key: bytes, recipient_public_key) -> bytes:
    return recipient_public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt_key(encrypted_key: bytes, recipient_private_key) -> bytes:
    return recipient_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def compute_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def verify_hash(data: bytes, expected_hash: bytes) -> bool:
    return hashlib.sha256(data).digest() == expected_hash

def sign(data: bytes, signer_private_key) -> bytes:
    return signer_private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(data: bytes, signature: bytes, signer_public_key) -> bool:
    try:
        signer_public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def build_payload(sender: str, receiver: str,
                  iv: bytes, ciphertext: bytes,
                  encrypted_key: bytes, hash_digest: bytes,
                  signature: bytes) -> bytes:
    payload = {
        "sender":        sender,
        "receiver":      receiver,
        "iv":            base64.b64encode(iv).decode(),
        "ciphertext":    base64.b64encode(ciphertext).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "hash":          base64.b64encode(hash_digest).decode(),
        "signature":     base64.b64encode(signature).decode(),
    }
    return json.dumps(payload, indent=2).encode()


def parse_payload(raw: bytes) -> dict:
    p = json.loads(raw)
    return {
        "sender":        p["sender"],
        "receiver":      p["receiver"],
        "iv":            base64.b64decode(p["iv"]),
        "ciphertext":    base64.b64decode(p["ciphertext"]),
        "encrypted_key": base64.b64decode(p["encrypted_key"]),
        "hash":          base64.b64decode(p["hash"]),
        "signature":     base64.b64decode(p["signature"]),
    }
