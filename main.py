"""
This script defines an API using FastAPI for symmetric and asymmetric encryption operations.

Endpoints:
- GET /symmetric/key: Returns a randomly generated symmetric key.
- POST /symmetric/key: Sets the symmetric key on the server.
- POST /symmetric/encode: Encrypts a message using the symmetric key.
- POST /symmetric/decode: Decrypts a message using the symmetric key.
- GET /asymmetric/key: Returns a new pair of asymmetric keys.
- GET /asymmetric/key/ssh: Returns the public and private keys in OpenSSH format.
- POST /asymmetric/key: Sets the asymmetric keys on the server.
- POST /asymmetric/verify: Verifies a message's signature.
- POST /asymmetric/sign: Signs a message.
- POST /asymmetric/encode: Encrypts a message using the asymmetric public key.
- POST /asymmetric/decode: Decrypts a message using the asymmetric private key.
"""

from cryptography.hazmat.primitives.serialization import load_ssh_public_key, load_pem_private_key
from fastapi import FastAPI, HTTPException, status
from symmetric import *
from asymmetric import *

app = FastAPI()


@app.get("/symmetric/key", tags=["symmetric"])
async def get_symmetric_key():
    """Returns a randomly generated symmetric key."""
    global symmetric_key
    symmetric_key = generate_symmetric_key()
    return {"key": symmetric_key.hex()}


@app.post("/symmetric/key", tags=["symmetric"])
async def set_symmetric_key(key: str):
    """Sets the symmetric key on the server."""
    global symmetric_key
    symmetric_key = bytes.fromhex(key)


@app.post("/symmetric/encode", tags=["symmetric"])
async def encrypt_message(message: str):
    """Encrypts a message using the symmetric key."""
    if symmetric_key is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Symmetric key not set")
    encrypted_message = encrypt_message_with_symmetric_key(message, symmetric_key)
    return {"encrypted_message": encrypted_message.decode()}


@app.post("/symmetric/decode", tags=["symmetric"])
async def decrypt_message(encrypted_message: str):
    """Decrypts a message using the symmetric key."""
    if symmetric_key is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Symmetric key not set")
    decrypted_message = decrypt_message_with_symmetric_key(bytes(encrypted_message, 'utf-8'), symmetric_key)
    return {"decrypted_message": decrypted_message}


@app.get("/asymmetric/key", tags=["asymmetric"])
async def get_asymmetric_key():
    """Returns a new pair of asymmetric keys."""
    global asymmetric_private_key, asymmetric_public_key
    asymmetric_private_key, asymmetric_public_key = generate_asymmetric_keys()
    return {"private_key": asymmetric_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).hex(),
            "public_key": asymmetric_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}


@app.get("/asymmetric/key/ssh", tags=["asymmetric"])
async def get_ssh_asymmetric_key():
    """Returns the public and private keys in OpenSSH format."""
    if asymmetric_private_key is None or asymmetric_public_key is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Asymmetric keys not generated")
    ssh_public_key = asymmetric_public_key.public_bytes(encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH).decode()
    ssh_private_key = asymmetric_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()).decode()
    return {"public_key": ssh_public_key, "private_key": ssh_private_key}


@app.post("/asymmetric/key", tags=["asymmetric"])
async def set_asymmetric_key(private_key: str, public_key: str):
    """Sets the asymmetric keys on the server."""
    global asymmetric_private_key, asymmetric_public_key
    # Deserialize the private key from hex string
    asymmetric_private_key = serialization.load_pem_private_key(bytes.fromhex(private_key), password=None, backend=default_backend())
    # Deserialize the public key from hex string
    asymmetric_public_key = serialization.load_pem_public_key(bytes.fromhex(public_key), backend=default_backend())


@app.post("/asymmetric/verify", tags=["asymmetric"])
async def verify_message_signature(message: str, signature: str):
    """Verifies a message's signature."""
    if asymmetric_private_key is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Asymmetric private key not set")
    verified = verify_signature_with_public_key(message.encode(), bytes.fromhex(signature), asymmetric_public_key)
    return {"verified": verified}


@app.post("/asymmetric/sign", tags=["asymmetric"])
async def sign_message(message: str):
    """Signs a message."""
    if asymmetric_private_key is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Asymmetric private key not set")
    signature = sign_message_with_private_key(message.encode(), asymmetric_private_key)
    return {"signature": signature.hex()}


@app.post("/asymmetric/encode", tags=["asymmetric"])
async def encrypt_message_asymmetric(message: str):
    """Encrypts a message using the asymmetric public key."""
    if asymmetric_public_key is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Asymmetric public key not set")
    encrypted_message = asymmetric_public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {"encrypted_message": encrypted_message.hex()}


@app.post("/asymmetric/decode", tags=["asymmetric"])
async def decrypt_message_asymmetric(encrypted_message: str):
    """Decrypts a message using the asymmetric private key."""
    if asymmetric_private_key is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Asymmetric private key not set")
    decrypted_message = asymmetric_private_key.decrypt(
        bytes.fromhex(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {"decrypted_message": decrypted_message.decode()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
