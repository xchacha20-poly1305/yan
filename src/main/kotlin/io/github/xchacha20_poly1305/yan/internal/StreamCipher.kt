package io.github.xchacha20_poly1305.yan.internal

import io.github.xchacha20_poly1305.yan.ArmorFormatException
import io.github.xchacha20_poly1305.yan.PayloadDecryptionException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.util.Arrays

internal object StreamCipher {
    const val CHUNK_SIZE: Int = 64 * 1024
    const val TAG_SIZE: Int = 16
    const val ENC_CHUNK_SIZE: Int = CHUNK_SIZE + TAG_SIZE
    const val PAYLOAD_NONCE_SIZE: Int = 16
    const val AEAD_NONCE_SIZE: Int = 12

    fun incrementCounter(nonce: ByteArray): Boolean {
        for (i in (AEAD_NONCE_SIZE - 2) downTo 0) {
            val next = (nonce[i].toInt() and 0xFF) + 1
            nonce[i] = next.toByte()
            if (next <= 0xFF) {
                return true
            }
        }
        return false
    }

    fun isCounterZero(nonce: ByteArray): Boolean {
        for (i in 0 until (AEAD_NONCE_SIZE - 1)) {
            if (nonce[i].toInt() != 0) {
                return false
            }
        }
        return true
    }
}

internal class StreamEncryptOutputStream(
    private val out: OutputStream,
    fileKey: ByteArray,
    payloadNonce: ByteArray? = null,
) : OutputStream() {
    private val payloadKey: ByteArray
    private val aeadNonce = ByteArray(StreamCipher.AEAD_NONCE_SIZE)
    private var plainBuf = CryptoPrimitives.EMPTY_BYTES
    private var encBuf: ByteArray? = null
    private val singleByte = ByteArray(1)
    private var plainLen = 0
    private var closed = false

    init {
        val nonce = if (payloadNonce != null) {
            require(payloadNonce.size == StreamCipher.PAYLOAD_NONCE_SIZE) {
                "Invalid payload nonce size: ${payloadNonce.size}"
            }
            payloadNonce.copyOf()
        } else {
            CryptoPrimitives.randomBytes(StreamCipher.PAYLOAD_NONCE_SIZE)
        }
        payloadKey = CryptoPrimitives.hkdfSha256(
            ikm = fileKey,
            salt = nonce,
            info = "payload".toByteArray(StandardCharsets.US_ASCII),
            length = 32,
        )
        try {
            out.write(nonce)
        } catch (t: Throwable) {
            CryptoPrimitives.zero(payloadKey)
            throw t
        }
    }

    override fun write(b: Int) {
        singleByte[0] = b.toByte()
        write(singleByte, 0, 1)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (closed) {
            throw IOException("Stream is already closed")
        }
        if (off < 0 || len < 0 || off > b.size - len) {
            throw IndexOutOfBoundsException("Invalid offset/length: off=$off, len=$len, size=${b.size}")
        }
        if (len == 0) return

        var position = off
        var remaining = len
        while (remaining > 0) {
            if (plainLen == StreamCipher.CHUNK_SIZE) {
                flushChunk(isFinal = false)
            }
            // A following byte proves this chunk is nonfinal.
            if (plainLen == 0 && remaining > StreamCipher.CHUNK_SIZE) {
                try {
                    sealChunk(b, position, StreamCipher.CHUNK_SIZE, isFinal = false)
                } catch (t: Throwable) {
                    // Keep the same chunk pending if the caller retries after a failed write.
                    bufferInput(b, position, StreamCipher.CHUNK_SIZE)
                    throw t
                }
                advanceCounter()
                position += StreamCipher.CHUNK_SIZE
                remaining -= StreamCipher.CHUNK_SIZE
                continue
            }
            val toCopy = minOf(remaining, StreamCipher.CHUNK_SIZE - plainLen)
            bufferInput(b, position, toCopy)
            position += toCopy
            remaining -= toCopy
        }
    }

    override fun flush() {
        if (!closed) {
            out.flush()
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        try {
            flushChunk(isFinal = true)
            out.flush()
            out.close()
        } finally {
            CryptoPrimitives.zero(payloadKey)
            CryptoPrimitives.zero(plainBuf)
            CryptoPrimitives.zero(encBuf)
            CryptoPrimitives.zero(aeadNonce)
            CryptoPrimitives.zero(singleByte)
        }
    }

    private fun bufferInput(input: ByteArray, offset: Int, length: Int) {
        val required = plainLen + length
        if (required > plainBuf.size) {
            val capacity = when {
                required <= 1024 -> 1024
                required <= 4096 -> 4096
                else -> StreamCipher.CHUNK_SIZE
            }
            val previous = plainBuf
            plainBuf = previous.copyOf(capacity)
            CryptoPrimitives.zero(previous)
        }
        System.arraycopy(input, offset, plainBuf, plainLen, length)
        plainLen = required
    }

    private fun flushChunk(isFinal: Boolean) {
        sealChunk(plainBuf, 0, plainLen, isFinal)
        Arrays.fill(plainBuf, 0, plainLen, 0.toByte())
        plainLen = 0
        if (!isFinal) advanceCounter()
    }

    private fun sealChunk(input: ByteArray, offset: Int, length: Int, isFinal: Boolean) {
        aeadNonce[StreamCipher.AEAD_NONCE_SIZE - 1] = if (isFinal) {
            0x01
        } else {
            0x00
        }
        val ciphertext = encBuf ?: ByteArray(length + StreamCipher.TAG_SIZE).also {
            encBuf = it
        }
        val written = CryptoPrimitives.chacha20Poly1305(
            encrypt = true,
            key = payloadKey,
            nonce = aeadNonce,
            input = input,
            offset = offset,
            length = length,
            output = ciphertext,
        )
        out.write(ciphertext, 0, written)
    }

    private fun advanceCounter() {
        if (!StreamCipher.incrementCounter(aeadNonce)) {
            throw IOException("STREAM chunk counter overflow")
        }
    }
}

internal class StreamDecryptInputStream(
    private val src: InputStream,
    fileKey: ByteArray,
    preDerivedPayloadKey: ByteArray? = null,
) : InputStream() {
    private val fileKeyCopy: ByteArray? = if (preDerivedPayloadKey == null) {
        fileKey.copyOf()
    } else {
        null
    }
    private var payloadKey: ByteArray? = preDerivedPayloadKey?.copyOf()
    private var initialized: Boolean = preDerivedPayloadKey != null
    private val aeadNonce = ByteArray(StreamCipher.AEAD_NONCE_SIZE)
    private var encBuf = ByteArray(4096)
    private var plainBuf = CryptoPrimitives.EMPTY_BYTES
    private val singleByte = ByteArray(1)
    private var plainPos = 0
    private var plainLimit = 0
    private var eof = false
    private var closed = false
    private var pendingError: IOException? = null

    override fun read(): Int {
        val n = read(singleByte, 0, 1)
        return if (n < 0) {
            -1
        } else {
            (singleByte[0].toInt() and 0xFF)
        }
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (off < 0 || len < 0 || off > b.size - len) {
            throw IndexOutOfBoundsException("Invalid offset/length: off=$off, len=$len, size=${b.size}")
        }
        if (closed) {
            throw IOException("Stream is already closed")
        }
        if (len == 0) return 0

        if (plainPos < plainLimit) {
            val available = plainLimit - plainPos
            val toCopy = minOf(len, available)
            System.arraycopy(plainBuf, plainPos, b, off, toCopy)
            plainPos += toCopy
            if (plainPos == plainLimit) {
                plainPos = 0
                plainLimit = 0
            }
            return toCopy
        }

        pendingError?.let { throw it }
        if (eof) return -1

        ensureInitialized()
        decryptNextChunk()

        if (plainPos < plainLimit) {
            val toCopy = minOf(len, plainLimit - plainPos)
            System.arraycopy(plainBuf, plainPos, b, off, toCopy)
            plainPos += toCopy
            if (plainPos == plainLimit) {
                plainPos = 0
                plainLimit = 0
            }
            return toCopy
        }

        pendingError?.let { throw it }
        return -1
    }

    override fun close() {
        if (closed) return
        closed = true
        try {
            src.close()
        } finally {
            CryptoPrimitives.zero(fileKeyCopy)
            CryptoPrimitives.zero(payloadKey)
            CryptoPrimitives.zero(encBuf)
            CryptoPrimitives.zero(plainBuf)
            CryptoPrimitives.zero(aeadNonce)
            CryptoPrimitives.zero(singleByte)
        }
    }

    private fun ensureInitialized() {
        if (initialized) return
        val fileKey = fileKeyCopy!!
        try {
            val fileNonce = ByteArray(StreamCipher.PAYLOAD_NONCE_SIZE)
            val n = try {
                CryptoPrimitives.readFullyCompat(src, fileNonce, 0, fileNonce.size)
            } catch (e: ArmorFormatException) {
                pendingError = e
                throw e
            } catch (e: IOException) {
                val decryptionException = PayloadDecryptionException("Failed to read payload nonce", e)
                pendingError = decryptionException
                throw decryptionException
            }
            if (n < StreamCipher.PAYLOAD_NONCE_SIZE) {
                val decryptionException = PayloadDecryptionException("Truncated payload nonce")
                pendingError = decryptionException
                throw decryptionException
            }
            payloadKey = CryptoPrimitives.hkdfSha256(
                ikm = fileKey,
                salt = fileNonce,
                info = "payload".toByteArray(StandardCharsets.US_ASCII),
                length = 32,
            )
            initialized = true
        } finally {
            CryptoPrimitives.zero(fileKey)
        }
    }

    private fun decryptNextChunk() {
        val key = payloadKey!!
        val bytesRead = try {
            val initialRead = CryptoPrimitives.readFullyCompat(src, encBuf)
            if (initialRead == encBuf.size && encBuf.size < StreamCipher.ENC_CHUNK_SIZE) {
                encBuf = encBuf.copyOf(StreamCipher.ENC_CHUNK_SIZE)
                initialRead + CryptoPrimitives.readFullyCompat(
                    src, encBuf, initialRead, encBuf.size - initialRead,
                )
            } else {
                initialRead
            }
        } catch (e: ArmorFormatException) {
            pendingError = e
            throw e
        } catch (e: IOException) {
            val decryptionException = PayloadDecryptionException("Failed to read payload chunk", e)
            pendingError = decryptionException
            throw decryptionException
        }

        if (bytesRead == 0) {
            val decryptionException = PayloadDecryptionException("Unexpected EOF without final payload chunk")
            pendingError = decryptionException
            throw decryptionException
        }

        var isFinal = false
        val decryptedLength: Int
        if (bytesRead < StreamCipher.ENC_CHUNK_SIZE) {
            if (bytesRead < StreamCipher.TAG_SIZE) {
                val decryptionException = PayloadDecryptionException("Truncated payload chunk ($bytesRead bytes)")
                pendingError = decryptionException
                throw decryptionException
            }
            if (!StreamCipher.isCounterZero(aeadNonce) && bytesRead == StreamCipher.TAG_SIZE) {
                val decryptionException = PayloadDecryptionException("Final STREAM chunk cannot be empty")
                pendingError = decryptionException
                throw decryptionException
            }
            isFinal = true
            aeadNonce[StreamCipher.AEAD_NONCE_SIZE - 1] = 0x01
            decryptedLength = try {
                openChunk(key, bytesRead)
            } catch (e: GeneralSecurityException) {
                val decryptionException = PayloadDecryptionException("Failed to decrypt final payload chunk", e)
                pendingError = decryptionException
                throw decryptionException
            }
        } else {
            aeadNonce[StreamCipher.AEAD_NONCE_SIZE - 1] = 0x00
            decryptedLength = try {
                openChunk(key, bytesRead)
            } catch (_: GeneralSecurityException) {
                isFinal = true
                aeadNonce[StreamCipher.AEAD_NONCE_SIZE - 1] = 0x01
                try {
                    openChunk(key, bytesRead)
                } catch (e: GeneralSecurityException) {
                    val decryptionException = PayloadDecryptionException("Failed to decrypt payload chunk", e)
                    pendingError = decryptionException
                    throw decryptionException
                }
            }
        }

        // The AEAD only authenticates its output when doFinal succeeds.
        plainPos = 0
        plainLimit = decryptedLength

        if (isFinal) {
            CryptoPrimitives.zero(key)
            val probe = try {
                src.read()
            } catch (e: ArmorFormatException) {
                pendingError = e
                return
            } catch (e: IOException) {
                pendingError = e
                return
            }
            if (probe != -1) {
                pendingError = PayloadDecryptionException("Trailing data after end of encrypted payload")
            } else {
                eof = true
            }
        } else if (!StreamCipher.incrementCounter(aeadNonce)) {
            val decryptionException = PayloadDecryptionException("STREAM chunk counter overflow")
            pendingError = decryptionException
            throw decryptionException
        }
    }

    private fun openChunk(key: ByteArray, length: Int): Int {
        val required = length - StreamCipher.TAG_SIZE
        if (required > plainBuf.size) {
            val next = ByteArray(required)
            CryptoPrimitives.zero(plainBuf)
            plainBuf = next
        }
        return CryptoPrimitives.chacha20Poly1305(
            encrypt = false,
            key = key,
            nonce = aeadNonce,
            input = encBuf,
            offset = 0,
            length = length,
            output = plainBuf,
        )
    }
}
