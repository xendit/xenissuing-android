package com.example.xenissuing_android

import XenCrypt
import android.util.Base64
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.slot
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import utils.DecryptionError
import utils.EncryptionError
import utils.WrongPublicKeyError
import java.security.*

fun generateXenditKey(): String {
    val secureRandom = SecureRandom.getInstance("SHA1PRNG")
    val byteArray = ByteArray(32)
    secureRandom.nextBytes(byteArray)
    return String(Base64.encode(byteArray, Base64.NO_WRAP))
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
    @DisplayName("Test session-id data generation")
    fun generateSessionId() {
        val xenditKey = generateXenditKey()

        val xenCrypt = XenCrypt(xenditKey)
        val sessionKey = xenCrypt.getSessionKey()
        val sessionData = xenCrypt.generateSessionId(sessionKey)

        val decodedKey: ByteArray = Base64.decode(sessionData.encryptedSessionKey, Base64.NO_WRAP)
        val decodedIv: ByteArray = Base64.decode(sessionData.iv, Base64.NO_WRAP)

        assertEquals(decodedKey.size, 48)
        assertEquals(decodedIv.size, 16)
    }

    @Test
    @DisplayName("should decrypt plain text")
    fun decrypt() {
        val xenditKey = generateXenditKey()
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
        val xenditKey = generateXenditKey()
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
        val xenditKey = generateXenditKey()
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
        val xenditKey = generateXenditKey()
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
        val xenditKey = generateXenditKey()
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
        val xenditKey = generateXenditKey()
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