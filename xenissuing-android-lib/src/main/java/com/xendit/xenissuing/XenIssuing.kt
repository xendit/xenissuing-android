package com.xendit.xenissuing

import android.util.Base64
import com.sun.mail.util.BASE64DecoderStream
import com.sun.mail.util.BASE64EncoderStream
import org.bouncycastle.jce.provider.BouncyCastleProvider
import com.xendit.xenissuing.utils.DecryptionError
import com.xendit.xenissuing.utils.EncryptionError
import com.xendit.xenissuing.utils.SessionIdError
import java.io.File
import java.io.InputStream
import java.security.spec.X509EncodedKeySpec
import java.security.*
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.Exception

class SecureSession constructor(xenditKey: String = "") {
    private val xenditPublicKey: PublicKey
    var sessionKey: String

    init {
        Security.addProvider(BouncyCastleProvider())

        if(xenditKey?.isNotEmpty()) {
            this.xenditPublicKey = this.generatePublicKey(xenditKey)
            this.sessionKey = this.generateSessionKey();
        } else {
            throw IllegalArgumentException("xenditKey and filePath is null")
        }
    }

    /**
     * Returns generated Session ID using Private Xendit Key
     * @param {string} sessionKey base64 encoded session key.
     */
    fun getKey(): String{
        try {
            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
            cipher.init(Cipher.ENCRYPT_MODE, this.xenditPublicKey)
            val utf8 = this.sessionKey.toByteArray(charset("UTF8"))
            val encryptedSessionKey = cipher.doFinal(utf8)
            return String(Base64.encode(encryptedSessionKey, Base64.NO_WRAP))
        } catch (error: SessionIdError) {
            throw SessionIdError(error.message)
        }
    }

    /**
     * Returns decrypted secret in base64.
     * @param {string} ivB64 base64 encoded initialization vector used during encryption.
     * @param {string} secret base64 encoded secret.
     * @param {string} sessionKeyB64 base64 encoded session key used for encryption.
     */
    @Throws(DecryptionError::class, AEADBadTagException::class)
    fun decryptCardData(secret: String, iv: String): String{
        try {
            val aesdCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv1: ByteArray = Base64.decode(iv, Base64.NO_WRAP)
            val ivSpec = IvParameterSpec(iv1)
            val decodedKey: ByteArray = Base64.decode(
                this.sessionKey,
                Base64.NO_WRAP
            ) // SESSION-KEY is the key generated at client side and passed during request i.e. 32 character random string

            val aesKey: SecretKey = SecretKeySpec(decodedKey, 0, decodedKey.size, "AES")

            aesdCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec)
            val dec: ByteArray = BASE64DecoderStream.decode(secret.toByteArray(charset("UTF-8")))

            val utf8 = aesdCipher.doFinal(dec)

            return String(utf8, charset("UTF-8")) // Final decrypted cvv2
        }
        catch (error: Exception) {
            throw DecryptionError(error.message)
        }
    }

    @Throws(Exception::class)
    private fun generateSessionKey(): String {
        val secureRandom = SecureRandom.getInstance("SHA1PRNG")
        val byteArray = ByteArray(24)
        secureRandom.nextBytes(byteArray)
        return String(Base64.encode(byteArray, Base64.NO_WRAP))
    }

    private fun generatePublicKey(xenditKey: String): PublicKey {
        val data: ByteArray = Base64.decode(xenditKey, Base64.NO_WRAP)
        val spec = X509EncodedKeySpec(data)
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePublic(spec)
    }

    private fun readPublicKeyFile(filePath: String): String {
        val inputStream: InputStream = File(filePath).inputStream()
        val inputString = inputStream.bufferedReader().use { it.readText() }
        return inputString
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\n", "")
            .trim();
    }



}