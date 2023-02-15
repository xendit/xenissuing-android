package com.example.xenissuing_android

import android.util.Base64
import com.sun.mail.util.BASE64EncoderStream
import com.xendit.xenissuing.SecureSession
import com.xendit.xenissuing.utils.DecryptionError
import com.xendit.xenissuing.utils.EncryptionError
import com.xendit.xenissuing.utils.WrongPublicKeyError
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.slot
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.io.File
import java.io.InputStream
import java.security.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

const val filePath  = "src/test/java/com/example/xenissuing_android/resources/publickey.crt"
val xenditPublicKey = readPublicKeyFile(filePath)

fun readPublicKeyFile(pathName: String): String {
    val inputStream: InputStream = File(pathName).inputStream()
    val inputString = inputStream.bufferedReader().use { it.readText() }
    return inputString
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace("\n", "")
        .trim();
}

@Throws(Exception::class)
fun ivKeyGenerator(): String {
    val secureRandom = SecureRandom.getInstance("SHA1PRNG")
    val byteArray = ByteArray(16)
    secureRandom.nextBytes(byteArray)
    return String(Base64.encode(byteArray, Base64.NO_WRAP))
}


/**
 * Returns encrypted secret in base64.
 * @param {string} plain secret to encrypt.
 * @param {string} sessionKey base64 encoded session key used for encryption.
 * @param {string} iv initialization vector in bytes.
 */
@Throws(EncryptionError::class, InvalidAlgorithmParameterException::class)
fun encryption(sessionKey: String, plain: String, ivB64: String): String {
    try {
        val decodedKey: ByteArray = Base64.decode(
            sessionKey,
            Base64.NO_WRAP
        )  // use 32 characters session key generated at first step

        val aesKey: SecretKey = SecretKeySpec(decodedKey, 0, decodedKey.size, "AES")
        val iv: ByteArray = Base64.decode(ivB64, Base64.NO_WRAP)
        val ivSpec = IvParameterSpec(iv)

        val aeseCipher = Cipher.getInstance("AES/GCM/NoPadding")
        aeseCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec)
        val utf8 = plain.toByteArray(charset("UTF8"))
        val encryptedCVV = aeseCipher.doFinal(utf8)
        return String(BASE64EncoderStream.encode(encryptedCVV)) // pass encrypted cvv2 in request
    } catch (error: Exception) {
        throw EncryptionError(error.message)
    }
}



class XenCryptUnitTest{
    companion object {
        init {
            this.`Bypass android_util_Base64 to java_util_Base64`()
        }
        @BeforeAll
        @JvmStatic fun `Bypass android_util_Base64 to java_util_Base64`() {
            mockkStatic(Base64::class)
            val arraySlot = slot<ByteArray>()

            every {
                Base64.encodeToString(capture(arraySlot), Base64.DEFAULT)
            } answers {
                java.util.Base64.getEncoder().encodeToString(arraySlot.captured)
            }

            every {
                Base64.encode(capture(arraySlot), Base64.NO_WRAP)
            } answers {
                java.util.Base64.getEncoder().encode(arraySlot.captured)
            }

            val stringSlot = slot<String>()
            every {
                Base64.decode(capture(stringSlot), Base64.NO_WRAP)
            } answers {
                java.util.Base64.getDecoder().decode(stringSlot.captured)
            }
        }
    }

    @Test
    @DisplayName("Test session-id data generation from string")
    fun generateKeyFromKeyString() {
        val validPublicKey = xenditPublicKey
        val session = SecureSession(validPublicKey)
        val key = session.getKey()
        val decodedSessionId: ByteArray = Base64.decode(key, Base64.NO_WRAP)
        assertEquals(decodedSessionId.size, 256)
    }

    @Test
    @DisplayName("Test session-id should throw error")
    fun generateKeyInvalidParams() {
      try {
          SecureSession("")
      } catch (exception: IllegalArgumentException){
          assertEquals(exception.message, "xenditKey and filePath is null")
      }
    }


    @Test
    @DisplayName("should decrypt plain text")
    fun decryptTheCardData() {
        val xenditKey = xenditPublicKey
        val plain = "test"
        val session = SecureSession(xenditKey)
        val iv = ivKeyGenerator()
        val encryptedSecret = encryption(session.sessionKey, plain, iv)
        val decrypted = session.decryptCardData(encryptedSecret, iv)
        assertEquals(decrypted, plain)
    }

    @Test
    @DisplayName("should not decrypt plain text if provided different iv then was provided during encryption")
    fun decryptWithWrongIv() {
        val xenditKey = xenditPublicKey
        val plain = "test"
        val session = SecureSession(xenditKey)
        val iv = ivKeyGenerator()
        val secondIv = ivKeyGenerator()
        val encryptedSecret = encryption(session.sessionKey, plain, iv)

        try {
            session.decryptCardData(encryptedSecret, secondIv)
        } catch (error: DecryptionError) {
            assertEquals(error.message, "Failed to decrypt: mac check in GCM failed")
        }
    }


    @Test
    @DisplayName("should throw an error during decryption if the provided session key is more than 32 bytes")
    fun insertWrongSessionKey() {
        val xenditKey = xenditPublicKey
        val plain = "test"
        val session = SecureSession(xenditKey)

        val secureRandom = SecureRandom.getInstance("SHA1PRNG")
        // Wrong length
        val byteArray = ByteArray(64)
        secureRandom.nextBytes(byteArray)
        val sessionKey = String(Base64.encode(byteArray, Base64.NO_WRAP))

        val iv = ivKeyGenerator()

        try {
            encryption(sessionKey, plain, iv)
        } catch (error: EncryptionError) {
            error.message?.contains("Failed to encrypt")?.let { assertTrue(it) }
        }
    }

    @Test
    @DisplayName("should not decrypt plain text if the provided during decryption iv is not encoded")
    fun insertWrongIv() {
        val xenditKey = xenditPublicKey
        val plain = "test"
        val session = SecureSession(xenditKey)

        // Generate wrong iv
        val secureRandom = SecureRandom.getInstance("SHA1PRNG")
        val byteArray = ByteArray(16)
        secureRandom.nextBytes(byteArray)
        val iv = String(byteArray)

        try {
            encryption(session.sessionKey, plain, iv)
        } catch (error: EncryptionError) {
            error.message?.contains("Failed to encrypt")?.let { assertTrue(it) }
        }
    }
}