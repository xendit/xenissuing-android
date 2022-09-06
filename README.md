# Xenissuing

This SDK comprises of the following modules :
- XenCrypt: this module handles encryption between XenIssuing and your Android application.

## XenCrypt

XenCrypt is a module to help you set up encryption between XenIssuing and your application.

### Requirements

To be able to use XenCrypt, you will need to use a private key provided by Xendit.

### Usage
```android
import XenCrypt
try {
    val xenKey = Base64.encode("BASE64_ENCODED_KEY_PROVIDED_BY_XENDIT".toByteArray())
    val xenCrypt = XenCrypt(xenKey);
    val sessionData = xenCrypt.generateSessionId(sessionKey)

    val decrypted = xenCrypt.decrypt(secret, iv, privateKey);

    val encrypted = xenCrypt.encryption(plain, privateKey, iv)
} catch (error: Exception) {
    throw error
}
