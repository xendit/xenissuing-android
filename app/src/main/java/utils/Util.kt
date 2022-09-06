package utils

import android.util.Base64
import org.apache.commons.codec.binary.Base64.encodeBase64String as encodeBase64String
import java.io.UnsupportedEncodingException
import java.security.*
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

class AsymmetricCryptography(cipher: Cipher) {
    var cipher: Cipher

    init {
        this.cipher = cipher
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

        return encodeBase64String(cipher.doFinal(sessionKey.toByteArray(charset("UTF-8"))))
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