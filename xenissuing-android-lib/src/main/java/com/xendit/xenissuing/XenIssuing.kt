package com.xendit.xenissuing
import com.xendit.xenissuing.SecureSession
class XenIssuing {
    companion object {
        fun createSecureSession(publicKey: String): SecureSession {
            return SecureSession(publicKey);
        }
    }
}