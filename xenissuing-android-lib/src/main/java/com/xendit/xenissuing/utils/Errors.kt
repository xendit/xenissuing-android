package com.xendit.xenissuing.utils

class DecryptionError(message: String?) : Exception("Failed to decrypt: $message")

class EncryptionError(message: String?) : Exception("Failed to encrypt: $message")

class SessionIdError(message: String?) :
    Exception("Failed to generate session id: $message")

class WrongPublicKeyError(message: String?) :
    Exception("Something happen while decoding publicKey: $message")

