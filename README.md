[![Maven Central](https://img.shields.io/maven-central/v/com.apollographql.federation/federation-graphql-java-support.svg)](https://maven-badges.herokuapp.com/maven-central/com.apollographql.federation/federation-graphql-java-support)
[Maven Central](https://img.shields.io/badge/JVM-%3E%3D11-brightgreen)

# Xenissuing

This SDK comprises of the following modules :
- XenCrypt: this module handles encryption between XenIssuing and your Android application.

## XenCrypt

XenCrypt is a module to help you set up encryption between XenIssuing and your application.

### Requirements

To be able to use XenCrypt, you will need to use a private key provided by Xendit.

It includes several methods:
- `generateSessionId` will encrypt a session key randomly generated used for symmetric encryption with Xenissuing.
- `encrypt` would be used when setting sensitive data.
- `decrypt` would be used whenever receiving sensitive data from Xenissuing.

### Usage
```android
import XenCrypt
try {
    val xenKey = Base64.encode("BASE64_ENCODED_KEY_PROVIDED_BY_XENDIT")
    val xenCrypt = XenCrypt(xenKey);

    // sessionKey - randomly generated 32 length string, use xenCrypt.getSessionKey(), or implement own

    val sessionId = xenCrypt.generateSessionId(sessionKey)
    
    // plain - plain text to be encrypted (cvv2 ect..)
    
    val encrypted = xenCrypt.encryption(plain, privateKey, iv)

    val decrypted = xenCrypt.decrypt(secret, iv, privateKey);
} catch (error: Exception) {
    throw error
}
