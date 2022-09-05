package utils

import android.util.Base64
import java.io.UnsupportedEncodingException
import java.security.*
import java.security.spec.X509EncodedKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

class AsymmetricCryptography(cipher: Cipher) {
    var cipher: Cipher

    init {
        this.cipher = cipher
    }

    @Throws(Exception::class)
    fun getPublicKey(base64: String?): PublicKey {
        val privateKeyPEM = base64
            ?.replace("-----BEGIN PUBLIC KEY-----", "")
            ?.replace(System.lineSeparator().toRegex(), "")
            ?.replace("\n","")
            ?.replace("-----END PUBLIC KEY-----", "")

        val keyBytes = Base64.decode(privateKeyPEM, Base64.NO_WRAP)
        val spec = X509EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePublic(spec)
    }

    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchPaddingException::class,
        UnsupportedEncodingException::class,
        IllegalBlockSizeException::class,
        BadPaddingException::class,
        InvalidKeyException::class
    )
    fun encrypt(sessionKey: String, key: PublicKey?): String {
        this.cipher.init(Cipher.ENCRYPT_MODE, key)

        return org.apache.commons.codec.binary.Base64.encodeBase64String(cipher.doFinal(sessionKey.toByteArray(charset("UTF-8"))))
    }

    @Throws(Exception::class)
    fun getSessionKey(): String {
        val secureRandom = SecureRandom.getInstance("SHA1PRNG")
        val byteArray = ByteArray(24)
        secureRandom.nextBytes(byteArray)
        return String(Base64.encode(byteArray, Base64.NO_WRAP))
    }

    @Throws(
        InvalidKeyException::class,
        UnsupportedEncodingException::class,
        IllegalBlockSizeException::class,
        BadPaddingException::class
    )
    fun decrypt(msg: String?, key: PrivateKey?): String {
        cipher.init(Cipher.DECRYPT_MODE, key)

        return String(cipher.doFinal(Base64.decode(msg, Base64.NO_WRAP)))
    }
}