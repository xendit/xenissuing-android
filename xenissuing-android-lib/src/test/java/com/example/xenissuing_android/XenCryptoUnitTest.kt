package com.example.xenissuing_android

import android.util.Base64
import com.xendit.xenissuing.XenCrypt
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
    fun generateSessionIdFromKeyString() {
        val validPublicKey = xenditPublicKey
        val xenCrypt = XenCrypt(validPublicKey)
        val sessionKey = xenCrypt.getSessionKey()
        val sessionId = xenCrypt.generateSessionId(sessionKey)
        val decodedSessionId: ByteArray = Base64.decode(sessionId, Base64.NO_WRAP)
        assertEquals(decodedSessionId.size, 256)
    }

    @Test
    @DisplayName("Test session-id data generation from path name")
    fun generateSessionIdFromPathname() {
        val xenCrypt = XenCrypt(null, filePath)
        val sessionKey = xenCrypt.getSessionKey()
        val sessionId = xenCrypt.generateSessionId(sessionKey)
        val decodedSessionId: ByteArray = Base64.decode(sessionId, Base64.NO_WRAP)
        assertEquals(decodedSessionId.size, 256)
    }
    @Test
    @DisplayName("Test session-id should throw error")
    fun generateSessionId() {
      try {
          XenCrypt(null, null)
      } catch (exception: IllegalArgumentException){
          assertEquals(exception.message, "xenditKey and filePath is null")
      }
    }


    @Test
    @DisplayName("should decrypt plain text")
    fun decrypt() {
        val xenditKey = xenditPublicKey
        val plain = "test"
        val xenCrypt = XenCrypt(xenditKey)
        val sessionKey = xenCrypt.getSessionKey()
        val iv = xenCrypt.ivKeyGenerator()
        val encryptedSecret = xenCrypt.encryption(plain, sessionKey, iv)

        val decrypted = xenCrypt.decrypt(encryptedSecret, iv, sessionKey)
        assertEquals(decrypted, plain)
    }


    @Test
    @DisplayName("should not decrypt plain text if provided different session key then was provided during encryption")
    fun decryptWithWrongPrivatKey() {
        val xenditKey = xenditPublicKey
        val plain = "test"
        val xenCrypt = XenCrypt(xenditKey)
        val privateEncryptionKey = xenCrypt.getSessionKey()
        val privateDecryptionKey = xenCrypt.getSessionKey()
        val iv = xenCrypt.ivKeyGenerator()
        val encryptedSecret = xenCrypt.encryption(plain, privateEncryptionKey, iv)

        try {
            xenCrypt.decrypt(encryptedSecret, iv, privateDecryptionKey)
        } catch (error: DecryptionError) {
            assertEquals(error.message, "Failed to decrypt: mac check in GCM failed")
        }
    }

    @Test
    @DisplayName("should not decrypt plain text if provided different iv then was provided during encryption")
    fun decryptWithWrongIv() {
        val xenditKey = xenditPublicKey
        val plain = "test"
        val xenCrypt = XenCrypt(xenditKey)
        val privateKey = xenCrypt.getSessionKey()
        val iv = xenCrypt.ivKeyGenerator()
        val secondIv = xenCrypt.ivKeyGenerator()
        val encryptedSecret = xenCrypt.encryption(plain, privateKey, iv)

        try {
            xenCrypt.decrypt(encryptedSecret, secondIv, privateKey)
        } catch (error: DecryptionError) {
            assertEquals(error.message, "Failed to decrypt: mac check in GCM failed")
        }
    }

    @Test
    @DisplayName("should throw an error if passed wrong public key")
    fun insertWrongPublicKey() {
        val xenditKey = xenditPublicKey
        try {
            XenCrypt(xenditKey)
        } catch (error: WrongPublicKeyError) {
            error.message?.contains("Something happen while decoding publicKey")
                ?.let { assertTrue(it) }
        }
    }

    @Test
    @DisplayName("should throw an error during decryption if the provided session key is more than 32 bytes")
    fun insertWrongPrivateKey() {
        val xenditKey = xenditPublicKey
        val plain = "test"
        val xenCrypt = XenCrypt(xenditKey)

        val secureRandom = SecureRandom.getInstance("SHA1PRNG")
        // Wrong length
        val byteArray = ByteArray(64)
        secureRandom.nextBytes(byteArray)
        val privateKey = String(Base64.encode(byteArray, Base64.NO_WRAP))

        val iv = xenCrypt.ivKeyGenerator()

        try {
            xenCrypt.encryption(plain, privateKey, iv)
        } catch (error: EncryptionError) {
            error.message?.contains("Failed to encrypt")?.let { assertTrue(it) }
        }
    }

    @Test
    @DisplayName("should not decrypt plain text if the provided during decryption iv is not encoded")
    fun insertWrongIv() {
        val xenditKey = xenditPublicKey
        val plain = "test"
        val xenCrypt = XenCrypt(xenditKey)

        val privateKey = xenCrypt.getSessionKey()
        // Generate wrong iv
        val secureRandom = SecureRandom.getInstance("SHA1PRNG")
        val byteArray = ByteArray(16)
        secureRandom.nextBytes(byteArray)
        val iv = String(byteArray)

        try {
            xenCrypt.encryption(plain, privateKey, iv)
        } catch (error: EncryptionError) {
            error.message?.contains("Failed to encrypt")?.let { assertTrue(it) }
        }
    }
}