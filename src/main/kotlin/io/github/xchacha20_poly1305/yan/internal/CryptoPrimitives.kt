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

    fun hmacSha256(key: ByteArray, data: ByteArray, length: Int): ByteArray {
        val mac = HMac(SHA256Digest())
        val parameters = KeyParameter(key)
        try {
            mac.init(parameters)
            mac.update(data, 0, length)
            return ByteArray(mac.macSize).also {
                mac.doFinal(it, 0)
            }
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
    ): ByteArray = ByteArray(length + StreamCipher.TAG_SIZE).also {
        chacha20Poly1305(true, key, nonce, plaintext, offset, length, it)
    }

    fun chacha20Poly1305Open(
        key: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        offset: Int = 0,
        length: Int = ciphertext.size,
    ): ByteArray = ByteArray(length - StreamCipher.TAG_SIZE).also {
        chacha20Poly1305(false, key, nonce, ciphertext, offset, length, it)
    }

    fun chacha20Poly1305(
        encrypt: Boolean,
        key: ByteArray,
        nonce: ByteArray,
        input: ByteArray,
        offset: Int,
        length: Int,
        output: ByteArray,
    ): Int {
        val cipher = ChaCha20Poly1305()
        val parameters = KeyParameter(key)
        var completed = false
        try {
            cipher.init(encrypt, ParametersWithIV(parameters, nonce))
            val written = cipher.processBytes(input, offset, length, output, 0)
            val total = written + cipher.doFinal(output, written)
            completed = true
            return total
        } catch (e: InvalidCipherTextException) {
            throw AEADBadTagException(e.message).apply {
                initCause(e)
            }
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

    fun memoryOutput(capacity: Long): ByteArrayOutputStream =
        if (capacity <= Int.MAX_VALUE - 8) {
            ByteArrayOutputStream(capacity.toInt())
        } else {
            ByteArrayOutputStream()
        }

    fun readAllCompat(input: InputStream, estimatedSize: Int = 8192): ByteArray {
        // Bound allocations by the bytes actually read. A caller's ciphertext size
        // can include malformed trailing data beyond the authenticated plaintext.
        val blockSize = StreamCipher.CHUNK_SIZE
        var buffer = ByteArray(estimatedSize.coerceIn(1, blockSize))
        var length = readFullyCompat(input, buffer)
        if (length < buffer.size) {
            return buffer.copyOf(length)
        }

        var next = input.read()
        if (next < 0) return buffer

        val blocks = ArrayList<ByteArray>()
        var total = 0
        while (next >= 0) {
            if (total > Int.MAX_VALUE - length) {
                throw OutOfMemoryError("Input is too large for a byte array")
            }
            blocks.add(buffer)
            total += length
            buffer = ByteArray(blockSize)
            buffer[0] = next.toByte()
            length = 1 + readFullyCompat(input, buffer, 1, blockSize - 1)
            next = if (length == blockSize) {
                input.read()
            } else {
                -1
            }
        }

        if (total > Int.MAX_VALUE - length) {
            throw OutOfMemoryError("Input is too large for a byte array")
        }
        val result = ByteArray(total + length)
        var offset = 0
        for (block in blocks) {
            System.arraycopy(block, 0, result, offset, block.size)
            offset += block.size
        }
        System.arraycopy(buffer, 0, result, offset, length)
        return result
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
