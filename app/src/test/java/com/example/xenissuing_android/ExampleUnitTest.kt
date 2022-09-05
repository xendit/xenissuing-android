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
import java.nio.charset.StandardCharsets
import java.security.*

fun encodeKey(keyBytes: ByteArray): String {
    return String(java.util.Base64.getMimeEncoder().encode(keyBytes), StandardCharsets.UTF_8)
}

fun generatePublicKey(): String {
    val kp: KeyPair?
    val kpg: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    kp = kpg.generateKeyPair()

    val publicKey: PublicKey = kp.public
    val publicKeyBytes: String = encodeKey(publicKey.getEncoded())

    return addHeaders(publicKeyBytes)
}

fun addHeaders(key: String): String {
    val headLine = "-----BEGIN PUBLIC KEY-----\n"
    val footLine = "\n-----END PUBLIC KEY-----"
    return headLine + key + footLine
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
    val generatedRsaPublic = generatePublicKey()
    var RSA_PUBLIC = java.util.Base64.getEncoder().encode(generatedRsaPublic.toByteArray())

    @Test
    @DisplayName("Test session-id generation")
    fun generateSessionId() {
        val base64regex = Regex("^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?\$")
        val xenCrypt = XenCrypt(String(RSA_PUBLIC))
        val sessionKey = xenCrypt.getSessionKey()
        val sessionData = xenCrypt.generateSessionId(sessionKey)

        base64regex.matches(sessionData.sessionId)
        assertEquals(base64regex.matches(sessionData.sessionId), true)
    }

    @Test
    @DisplayName("should decrypt plain text")
    fun decrypt() {
        val plain = "test"
        val xenCrypt = XenCrypt(String(RSA_PUBLIC))
        val sessionKey = xenCrypt.getSessionKey()
        val iv = xenCrypt.ivKeyGenerator()
        val encryptedSecret = xenCrypt.encryption(plain, sessionKey, iv)

        val decrypted = xenCrypt.decrypt(encryptedSecret, iv, sessionKey)
        assertEquals(decrypted, plain)
    }

    @Test
    @DisplayName("should not decrypt plain text if provided different session key then was provided during encryption")
    fun decryptWithWrongPrivatKey() {
        val plain = "test"
        val xenCrypt = XenCrypt(String(RSA_PUBLIC))
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
        val plain = "test"
        val xenCrypt = XenCrypt(String(RSA_PUBLIC))
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
        try {
            XenCrypt(generatedRsaPublic)
        } catch (error: WrongPublicKeyError) {
            error.message?.contains("Something happen while decoding publicKey")
                ?.let { assertTrue(it) }
        }
    }

    @Test
    @DisplayName("should throw an error during decryption if the provided session key is more than 32 bytes")
    fun insertWrongPrivateKey() {
        val plain = "test"
        val xenCrypt = XenCrypt(String(RSA_PUBLIC))

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
        val plain = "test"
        val xenCrypt = XenCrypt(String(RSA_PUBLIC))

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