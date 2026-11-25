package io.github.xchacha20_poly1305.yan.internal

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.security.Provider
import java.security.SecureRandom
import java.security.spec.EncodedKeySpec
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal class RawKeySpec(encoded: ByteArray) : EncodedKeySpec(encoded) {
    override fun getFormat(): String = "raw"
}

internal object CryptoPrimitives {
    val EMPTY_BYTES: ByteArray = ByteArray(0)
    private val ZERO_32: ByteArray = ByteArray(32)
    private val ZERO_64: ByteArray = ByteArray(64)

    fun randomBytes(size: Int, provider: Provider): ByteArray {
        val out = ByteArray(size)
        SecureRandom.getInstance("SHA1PRNG", provider).nextBytes(out)
        return out
    }

    fun newHmacSha256(key: ByteArray, provider: Provider): Mac {
        // RFC 2104 pads keys shorter than block size (64 bytes) with zeros;
        // SecretKeySpec rejects 0-length arrays, so substitute 64 zero bytes.
        val effectiveKey = if (key.isEmpty()) {
            ZERO_64
        } else {
            key
        }
        val mac = Mac.getInstance("HmacSHA256", provider)
        mac.init(SecretKeySpec(effectiveKey, "RAW"))
        return mac
    }

    fun hmacSha256(key: ByteArray, data: ByteArray, provider: Provider): ByteArray {
        val mac = newHmacSha256(key, provider)
        mac.update(data)
        return mac.doFinal()
    }

    fun hkdfSha256(
        ikm: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        length: Int = 32,
        provider: Provider,
    ): ByteArray {
        require(length in 0..(255 * 32)) { "Invalid HKDF output length: $length" }
        val effectiveSalt = if (salt.isEmpty()) ZERO_32 else salt
        val prk = hmacSha256(effectiveSalt, ikm, provider)
        try {
            val mac = newHmacSha256(prk, provider)
            val output = ByteArray(length)
            var t = EMPTY_BYTES
            var offset = 0
            var counter = 1
            while (offset < length) {
                mac.reset()
                if (t.isNotEmpty()) {
                    mac.update(t)
                }
                if (info.isNotEmpty()) {
                    mac.update(info)
                }
                mac.update(counter.toByte())
                t = mac.doFinal()
                val copyLen = minOf(t.size, length - offset)
                System.arraycopy(t, 0, output, offset, copyLen)
                offset += copyLen
                counter++
            }
            zero(t)
            return output
        } finally {
            zero(prk)
        }
    }

    fun chacha20Poly1305Seal(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        offset: Int = 0,
        length: Int = plaintext.size,
        aad: ByteArray = EMPTY_BYTES,
        provider: Provider,
    ): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305", provider)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        if (aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }
        return cipher.doFinal(plaintext, offset, length)
    }

    fun chacha20Poly1305Open(
        key: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        offset: Int = 0,
        length: Int = ciphertext.size,
        aad: ByteArray = EMPTY_BYTES,
        provider: Provider,
    ): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305", provider)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        if (aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }
        return cipher.doFinal(ciphertext, offset, length)
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    fun isAllZero(bytes: ByteArray): Boolean {
        var acc = 0
        for (value in bytes) {
            acc = acc or (value.toInt() and 0xFF)
        }
        return acc == 0
    }

    fun zero(bytes: ByteArray?) {
        if (bytes != null) {
            Arrays.fill(bytes, 0.toByte())
        }
    }

    fun zero(chars: CharArray?) {
        if (chars != null) {
            Arrays.fill(chars, '\u0000')
        }
    }

    fun readAllCompat(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    fun readFullyCompat(
        input: InputStream,
        dst: ByteArray,
        offset: Int = 0,
        length: Int = dst.size,
    ): Int {
        var total = 0
        while (total < length) {
            val n = input.read(dst, offset + total, length - total)
            if (n < 0) break
            total += n
        }
        return total
    }
}
