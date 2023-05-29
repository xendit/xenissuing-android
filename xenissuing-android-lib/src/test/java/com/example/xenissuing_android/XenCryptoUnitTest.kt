package com.example.xenissuing_android

import android.util.Base64
import com.xendit.xenissuing.XenIssuing
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
import java.net.URLDecoder
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
    fun generateKey() {
        val validPublicKey = xenditPublicKey
        val session = XenIssuing.createSecureSession(validPublicKey)
        val key = session.getKey()
        val decodedSessionId: ByteArray = Base64.decode(URLDecoder.decode(key, "utf-8"), Base64.NO_WRAP)
        assertEquals(decodedSessionId.size, 256)
    }
    @Test
    @DisplayName("Test to get the base 64 session key")
    fun getSessionKeyB64() {
        val validPublicKey = xenditPublicKey
        val session = XenIssuing.createSecureSession(validPublicKey)
        val key = session.getSessionKeyB64()
    }

    @Test
    @DisplayName("Test session-id should throw error")
    fun generateKeyInvalidParams() {
        try {
            XenIssuing.createSecureSession("")
        } catch (exception: IllegalArgumentException){
            assertEquals(exception.message, "xenditKey and filePath is null")
        }
    }
    @Test
    @DisplayName("should decrypt plain text")
    fun decryptTheCardData() {
        val xenditKey = xenditPublicKey
        val plain = "test"
        val session = XenIssuing.createSecureSession(xenditKey)
        val iv = session.ivKeyGenerator()
        val encryptedSecret = session.encryption(plain, iv)
        val decrypted = session.decryptCardData(encryptedSecret, iv)
        assertEquals(decrypted, plain)
    }
    @Test
    @DisplayName("should not decrypt plain text if provided different iv then was provided during encryption")
    fun decryptWithWrongIv() {
        val xenditKey = xenditPublicKey
        val plain = "test"
        val session = XenIssuing.createSecureSession(xenditKey)
        val iv = session.ivKeyGenerator()
        val secondIv = session.ivKeyGenerator()
        val encryptedSecret = session.encryption(plain, iv)

        try {
            session.decryptCardData(encryptedSecret, secondIv)
        } catch (error: DecryptionError) {
            assertEquals(error.message, "Failed to decrypt: mac check in GCM failed")
        }
    }

    @Test
    @DisplayName("should throw an error if passed wrong public key")
    fun insertWrongPublicKey() {
        val xenditKey = xenditPublicKey
        try {
            XenIssuing.createSecureSession(xenditKey)
        } catch (error: WrongPublicKeyError) {
            error.message?.contains("Something happen while decoding publicKey")
                ?.let { assertTrue(it) }
        }
    }

    @Test
    @DisplayName("should not decrypt plain text if the provided during decryption iv is not encoded")
    fun insertWrongIv() {
        val xenditKey = xenditPublicKey
        val plain = "test"
        val session = XenIssuing.createSecureSession(xenditKey)

        // Generate wrong iv
        val secureRandom = SecureRandom.getInstance("SHA1PRNG")
        val byteArray = ByteArray(16)
        secureRandom.nextBytes(byteArray)
        val iv = String(byteArray)

        try {
            session.encryption(plain, iv)
        } catch (error: EncryptionError) {
            error.message?.contains("Failed to encrypt")?.let { assertTrue(it) }
        }
    }
}