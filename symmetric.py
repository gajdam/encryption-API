"""
Module providing functions for symmetric encryption operations using Fernet.

This module includes functions for generating symmetric keys, encrypting messages with a symmetric key,
and decrypting messages with a symmetric key.

Functions:
- generate_symmetric_key(): Generates a new symmetric key.
- encrypt_message_with_symmetric_key(message, key): Encrypts a message using the provided symmetric key.
- decrypt_message_with_symmetric_key(encrypted_message, key): Decrypts a message using the provided symmetric key.
"""

from cryptography.fernet import Fernet

symmetric_key = None


def generate_symmetric_key():
    """
    Generates a new symmetric key.

    Returns:
    - str: The generated symmetric key.
    """
    return Fernet.generate_key()


def encrypt_message_with_symmetric_key(message, key):
    """
    Encrypts a message using the provided symmetric key.

    Args:
    - message: The message to encrypt.
    - key: The symmetric key used for encryption.

    Returns:
    - bytes: The encrypted message.
    """
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())


def decrypt_message_with_symmetric_key(encrypted_message, key):
    """
    Decrypts a message using the provided symmetric key.

    Args:
    - encrypted_message: The encrypted message to decrypt.
    - key: The symmetric key used for decryption.

    Returns:
    - str: The decrypted message.
    """
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()
