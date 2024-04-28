"""
Module providing functions for asymmetric encryption operations using RSA algorithm.

This module includes functions for generating asymmetric keys, signing messages with a private key,
and verifying message signatures with a public key.

Functions:
- generate_asymmetric_keys(): Generates a new pair of asymmetric (public, private) keys.
- sign_message_with_private_key(message, private_key): Signs a message using the provided private key.
- verify_signature_with_public_key(message, signature, public_key): Verifies a message's signature using the provided public key.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

asymmetric_private_key = None
asymmetric_public_key = None


def generate_asymmetric_keys():
    """
    Generates a new pair of asymmetric (public, private) keys.

    Returns:
    - private_key: The generated private key.
    - public_key: The corresponding public key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message_with_private_key(message, private_key):
    """
    Signs a message using the provided private key.

    Args:
    - message: The message to sign.
    - private_key: The private key to use for signing.

    Returns:
    - signature: The signature of the message.
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature_with_public_key(message, signature, public_key):
    """
    Verifies a message's signature using the provided public key.

    Args:
    - message: The message whose signature to verify.
    - signature: The signature to verify.
    - public_key: The public key corresponding to the private key used for signing.

    Returns:
    - bool: True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False
