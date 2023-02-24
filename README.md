![Maven Central](https://img.shields.io/badge/-Maven%20Central-blue)
![Java Support](https://img.shields.io/badge/JVM-%3E%3D11-brightgreen)
# Xenissuing
This SDK comprises of the following modules :
- XenIssuing: this module handles encryption between XenIssuing and your Android application.
## SecureSession
SecureSession is a module to help you set up encryption between XenIssuing and your application.
### Requirements
To be able to use XenIssuing, you will need to use a private key provided by Xendit.
It includes several methods:
- `getKey` will encrypt a session key randomly generated used for asymmetric encryption with Xenissuing.
- `encrypt` would be used when setting sensitive data.
- `decryptCardData` would be used whenever receiving sensitive card data from Xenissuing.
### Usage
```android
import SecureSession
try {
    // xenKey is base64 encoded portion without headers and footers *(see example bellow)
    val xenKey = Base64.encode("BASE64_PUBLIC_KEY")
    val session = SecureSession(xenKey);
    // you can make an API call using this key
    val key = session.getKey()
    
    // plain - plain text to be encrypted (cvv2 ect..)
    
    val encrypted = session.encryption(plain, iv)
    val decrypted = session.decryptCardData(secret, iv);
} catch (error: Exception) {
    throw error
}
```

``` android
// You can also initiate XenCrypt using file path name
    val xenditPublicKeyPathFileName = "src/path_to_file/publickey.crt"
    val session = SecureSession(null, xenditPublicKeyPathFileName)
```

``` 
// Example of valid xenKey
val xenKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArY3DXFJ2M0EHbsD9r+2XgFVtpYEQR5bxnQZVHVxtVzQP8u2cv/1APs2cft+8E682wKGY7SFUEsFsoqxoak7qsfXYL/mOdvQe6XDyNC7N6oo9Zb8dUKtuy8qPb1bVeTbxAwDVUzIdJpiRVI69fAGCW7aF3jTAV7Q+Z5qUTaLUFyKvu3+j8u/A58Nw5fjOENTLHBZRrXhFtQC1eql2O6FiQRJBDACYtzhyFBMyT/B7SKNPkEvLm1w4AQEWxxwL93B8vxstfpatbJJvorJaDEl/glncxJVtZ0lBeB3dkWdro/TrhpPD7CHKlBIUKRfvq1TgmMFs9SP90DxD9l9mE+AUAwIDAQAB"
```