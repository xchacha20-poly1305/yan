package io.github.xchacha20_poly1305.yan.internal

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.AEADBadTagException

internal object CryptoPrimitives {
    val EMPTY_BYTES: ByteArray = ByteArray(0)
    private val random = SecureRandom()

    fun randomBytes(size: Int): ByteArray = ByteArray(size).also(random::nextBytes)

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = HMac(SHA256Digest())
        val parameters = KeyParameter(key)
        try {
            mac.init(parameters)
            mac.update(data, 0, data.size)
            return ByteArray(mac.macSize).also { mac.doFinal(it, 0) }
        } finally {
            zero(parameters.key)
        }
    }

    fun hkdfSha256(
        ikm: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        length: Int = 32,
    ): ByteArray {
        require(length in 0..(255 * 32)) { "Invalid HKDF output length: $length" }
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(ikm, salt, info))
        return ByteArray(length).also { hkdf.generateBytes(it, 0, length) }
    }

    fun chacha20Poly1305Seal(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        offset: Int = 0,
        length: Int = plaintext.size,
    ): ByteArray = chacha20Poly1305(true, key, nonce, plaintext, offset, length)

    fun chacha20Poly1305Open(
        key: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        offset: Int = 0,
        length: Int = ciphertext.size,
    ): ByteArray = chacha20Poly1305(false, key, nonce, ciphertext, offset, length)

    private fun chacha20Poly1305(
        encrypt: Boolean,
        key: ByteArray,
        nonce: ByteArray,
        input: ByteArray,
        offset: Int,
        length: Int,
    ): ByteArray {
        val cipher = ChaCha20Poly1305()
        val parameters = KeyParameter(key)
        val output = ByteArray(length + if (encrypt) 16 else -16)
        var completed = false
        try {
            cipher.init(encrypt, ParametersWithIV(parameters, nonce))
            val written = cipher.processBytes(input, offset, length, output, 0)
            cipher.doFinal(output, written)
            completed = true
            return output
        } catch (e: InvalidCipherTextException) {
            throw AEADBadTagException(e.message).apply { initCause(e) }
        } finally {
            zero(parameters.key)
            if (!completed) zero(output)
        }
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    fun zero(bytes: ByteArray?) {
        if (bytes != null) {
            Arrays.fill(bytes, 0.toByte())
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
