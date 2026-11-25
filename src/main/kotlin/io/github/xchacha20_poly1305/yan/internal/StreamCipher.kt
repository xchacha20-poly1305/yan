package io.github.xchacha20_poly1305.yan.internal

import io.github.xchacha20_poly1305.yan.ArmorFormatException
import io.github.xchacha20_poly1305.yan.PayloadDecryptionException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException

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
    private val plainBuf = ByteArray(StreamCipher.CHUNK_SIZE)
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

        var pos = off
        var remaining = len
        while (remaining > 0) {
            if (plainLen == StreamCipher.CHUNK_SIZE) {
                flushChunk(isFinal = false)
            }
            val toCopy = minOf(remaining, StreamCipher.CHUNK_SIZE - plainLen)
            System.arraycopy(b, pos, plainBuf, plainLen, toCopy)
            plainLen += toCopy
            pos += toCopy
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
            CryptoPrimitives.zero(aeadNonce)
            CryptoPrimitives.zero(singleByte)
        }
    }

    private fun flushChunk(isFinal: Boolean) {
        aeadNonce[StreamCipher.AEAD_NONCE_SIZE - 1] = if (isFinal) {
            0x01
        } else {
            0x00
        }
        val ciphertext = CryptoPrimitives.chacha20Poly1305Seal(
            key = payloadKey,
            nonce = aeadNonce,
            plaintext = plainBuf,
            offset = 0,
            length = plainLen,
        )
        out.write(ciphertext)
        zero(plainBuf, 0, plainLen)
        plainLen = 0
        if (!isFinal && !StreamCipher.incrementCounter(aeadNonce)) {
            throw IOException("STREAM chunk counter overflow")
        }
    }

    private fun zero(bytes: ByteArray, fromIndex: Int, toIndex: Int) {
        for (i in fromIndex until toIndex) {
            bytes[i] = 0
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
    private val encBuf = ByteArray(StreamCipher.ENC_CHUNK_SIZE)
    private val plainBuf = ByteArray(StreamCipher.CHUNK_SIZE)
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
            CryptoPrimitives.readFullyCompat(src, encBuf, 0, StreamCipher.ENC_CHUNK_SIZE)
        } catch (e: ArmorFormatException) {
            pendingError = e
            throw e
        } catch (e: IOException) {
            val decryptionException = PayloadDecryptionException("Failed to read payload chunk", e)
            pendingError = decryptionException
            throw decryptionException
        }

        if (bytesRead == 0) {
            val ex = PayloadDecryptionException("Unexpected EOF without final payload chunk")
            pendingError = ex
            throw ex
        }

        var isFinal = false
        val decrypted: ByteArray
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
            decrypted = try {
                CryptoPrimitives.chacha20Poly1305Open(
                    key = key,
                    nonce = aeadNonce,
                    ciphertext = encBuf,
                    offset = 0,
                    length = bytesRead,
                )
            } catch (e: GeneralSecurityException) {
                val decryptionException = PayloadDecryptionException("Failed to decrypt final payload chunk", e)
                pendingError = decryptionException
                throw decryptionException
            }
        } else {
            aeadNonce[StreamCipher.AEAD_NONCE_SIZE - 1] = 0x00
            decrypted = try {
                CryptoPrimitives.chacha20Poly1305Open(
                    key = key,
                    nonce = aeadNonce,
                    ciphertext = encBuf,
                    offset = 0,
                    length = bytesRead,
                )
            } catch (_: GeneralSecurityException) {
                isFinal = true
                aeadNonce[StreamCipher.AEAD_NONCE_SIZE - 1] = 0x01
                try {
                    CryptoPrimitives.chacha20Poly1305Open(
                        key = key,
                        nonce = aeadNonce,
                        ciphertext = encBuf,
                        offset = 0,
                        length = bytesRead,
                    )
                } catch (e: GeneralSecurityException) {
                    val decryptionException = PayloadDecryptionException("Failed to decrypt payload chunk", e)
                    pendingError = decryptionException
                    throw decryptionException
                }
            }
        }

        System.arraycopy(decrypted, 0, plainBuf, 0, decrypted.size)
        plainPos = 0
        plainLimit = decrypted.size
        CryptoPrimitives.zero(decrypted)

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
}
