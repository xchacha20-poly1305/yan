package io.github.xchacha20_poly1305.yan

import io.github.xchacha20_poly1305.yan.internal.Base64Strict
import io.github.xchacha20_poly1305.yan.internal.CryptoPrimitives
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets

/**
 * Strict RFC 7468 ASCII armor encoder and decoder for `age` files (`AGE ENCRYPTED FILE`).
 */
public object Armor {
    public const val BEGIN_LINE: String = "-----BEGIN AGE ENCRYPTED FILE-----"
    public const val END_LINE: String = "-----END AGE ENCRYPTED FILE-----"

    private const val COLUMNS_PER_LINE = 64
    private const val BYTES_PER_LINE = 48
    private const val MAX_OUTSIDE_WHITESPACE = 1024

    /**
     * Wraps [output] so bytes written to the returned stream are encoded as strict ASCII-armored
     * PEM (`AGE ENCRYPTED FILE`). Closing the returned stream writes the PEM footer and closes
     * [output].
     */
    @JvmStatic
    public fun wrap(output: OutputStream): OutputStream = ArmoredOutputStream(output)

    /**
     * Wraps [input] so strict ASCII-armored PEM (`AGE ENCRYPTED FILE`) data is decoded on read.
     * Malformed PEM framing, non-canonical base64, or trailing non-whitespace data throws
     * [ArmorFormatException].
     */
    @JvmStatic
    public fun unwrap(input: InputStream): InputStream = ArmoredInputStream(input)

    /**
     * Encodes binary `age` data into a canonical ASCII-armored PEM string.
     */
    @JvmStatic
    public fun encode(data: ByteArray): String {
        val out = ByteArrayOutputStream(((data.size + 2) / 3) * 4 + 128)
        wrap(out).use { it.write(data) }
        return String(out.toByteArray(), StandardCharsets.US_ASCII)
    }

    /**
     * Decodes an ASCII-armored PEM string back to binary `age` bytes.
     */
    @JvmStatic
    @Throws(ArmorFormatException::class)
    public fun decode(armored: String): ByteArray {
        return decode(armored.toByteArray(StandardCharsets.UTF_8))
    }

    /**
     * Decodes ASCII-armored PEM bytes back to binary `age` bytes.
     */
    @JvmStatic
    @Throws(ArmorFormatException::class)
    public fun decode(armored: ByteArray): ByteArray {
        unwrap(ByteArrayInputStream(armored)).use { stream ->
            return CryptoPrimitives.readAllCompat(stream)
        }
    }

    private class ArmoredOutputStream(private val dst: OutputStream) : OutputStream() {
        private var started = false
        private var closed = false
        private val rawBuf = ByteArray(BYTES_PER_LINE)
        private var rawLen = 0
        private val singleByte = ByteArray(1)

        override fun write(byte: Int) {
            singleByte[0] = byte.toByte()
            write(singleByte, 0, 1)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (closed) {
                throw IOException("ArmoredOutputStream is already closed")
            }
            if (off < 0 || len < 0 || off > b.size - len) {
                throw IndexOutOfBoundsException("Invalid offset/length: off=$off, len=$len, size=${b.size}")
            }
            if (len == 0) return
            ensureStarted()

            var pos = off
            var remaining = len
            while (remaining > 0) {
                if (rawLen == BYTES_PER_LINE) {
                    flushFullLine()
                }
                val toCopy = minOf(remaining, BYTES_PER_LINE - rawLen)
                System.arraycopy(b, pos, rawBuf, rawLen, toCopy)
                rawLen += toCopy
                pos += toCopy
                remaining -= toCopy
            }
        }

        override fun flush() {
            if (!closed) {
                dst.flush()
            }
        }

        override fun close() {
            if (closed) return
            closed = true
            try {
                ensureStarted()
                if (rawLen > 0) {
                    val slice = rawBuf.copyOf(rawLen)
                    val encoded = Base64Strict.encodePadded(slice)
                    dst.write(encoded.toByteArray(StandardCharsets.US_ASCII))
                    dst.write('\n'.code)
                    CryptoPrimitives.zero(slice)
                }
                dst.write(END_BYTES)
                dst.write('\n'.code)
                dst.flush()
                dst.close()
            } finally {
                CryptoPrimitives.zero(rawBuf)
                CryptoPrimitives.zero(singleByte)
            }
        }

        private fun ensureStarted() {
            if (started) return
            dst.write(BEGIN_BYTES)
            dst.write('\n'.code)
            started = true
        }

        private fun flushFullLine() {
            val encoded = Base64Strict.encodePadded(rawBuf)
            dst.write(encoded.toByteArray(StandardCharsets.US_ASCII))
            dst.write('\n'.code)
            rawLen = 0
        }

        private companion object {
            val BEGIN_BYTES: ByteArray = BEGIN_LINE.toByteArray(StandardCharsets.US_ASCII)
            val END_BYTES: ByteArray = END_LINE.toByteArray(StandardCharsets.US_ASCII)
        }
    }

    private class ArmoredInputStream(private val src: InputStream) : InputStream() {
        private var started = false
        private var eof = false
        private var closed = false
        private var pendingError: ArmorFormatException? = null
        private var unread: ByteArray = CryptoPrimitives.EMPTY_BYTES
        private var unreadPos = 0
        private val singleByte = ByteArray(1)

        override fun read(): Int {
            val n = read(singleByte, 0, 1)
            return if (n < 0) -1 else (singleByte[0].toInt() and 0xFF)
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (off < 0 || len < 0 || off > b.size - len) {
                throw IndexOutOfBoundsException("Invalid offset/length: off=$off, len=$len, size=${b.size}")
            }
            if (closed) {
                throw IOException("ArmoredInputStream is already closed")
            }
            if (len == 0) return 0

            if (unreadPos < unread.size) {
                val toCopy = minOf(len, unread.size - unreadPos)
                System.arraycopy(unread, unreadPos, b, off, toCopy)
                unreadPos += toCopy
                if (unreadPos == unread.size) {
                    CryptoPrimitives.zero(unread)
                    unread = CryptoPrimitives.EMPTY_BYTES
                    unreadPos = 0
                }
                return toCopy
            }

            pendingError?.let { throw it }
            if (eof) return -1

            try {
                readNextChunk()
            } catch (e: ArmorFormatException) {
                pendingError = e
                throw e
            }

            if (unreadPos < unread.size) {
                val toCopy = minOf(len, unread.size - unreadPos)
                System.arraycopy(unread, unreadPos, b, off, toCopy)
                unreadPos += toCopy
                if (unreadPos == unread.size) {
                    CryptoPrimitives.zero(unread)
                    unread = CryptoPrimitives.EMPTY_BYTES
                    unreadPos = 0
                }
                return toCopy
            }

            pendingError?.let { throw it }
            return -1
        }

        override fun close() {
            if (closed) return
            closed = true
            CryptoPrimitives.zero(unread)
            unread = CryptoPrimitives.EMPTY_BYTES
            unreadPos = 0
            src.close()
        }

        private fun readNextChunk() {
            if (!started) {
                var removedWhitespace = 0
                while (true) {
                    val line = readLineStrict()
                        ?: throw ArmorFormatException("Unexpected EOF before armor begin line")
                    if (isAllAsciiWhitespace(line.text)) {
                        removedWhitespace += line.rawLength
                        if (removedWhitespace > MAX_OUTSIDE_WHITESPACE) {
                            throw ArmorFormatException("Too much leading whitespace before armor header")
                        }
                        continue
                    }
                    if (line.text != BEGIN_LINE) {
                        throw ArmorFormatException("Invalid armor begin line")
                    }
                    started = true
                    break
                }
            }

            val line = readLineStrict()
                ?: throw ArmorFormatException("Unexpected EOF inside armored body")
            if (line.text == END_LINE) {
                drainTrailingWhitespace()
                eof = true
                return
            }
            if (line.text.isEmpty()) {
                throw ArmorFormatException("Empty line in armored body")
            }
            if (line.text.length > COLUMNS_PER_LINE) {
                throw ArmorFormatException("Armor line exceeds $COLUMNS_PER_LINE columns")
            }
            val decoded = try {
                Base64Strict.decodePadded(line.text)
            } catch (e: IllegalArgumentException) {
                throw ArmorFormatException("Invalid base64 in armored body", e)
            }
            if (decoded.size > BYTES_PER_LINE) {
                throw ArmorFormatException("Armor line exceeds $BYTES_PER_LINE decoded bytes")
            }

            unread = decoded
            unreadPos = 0

            if (decoded.size < BYTES_PER_LINE) {
                val endLine = readLineStrict()
                    ?: throw ArmorFormatException("Unexpected EOF before armor end line")
                if (endLine.text != END_LINE) {
                    throw ArmorFormatException("Expected armor end line after short body line")
                }
                try {
                    drainTrailingWhitespace()
                    eof = true
                } catch (e: ArmorFormatException) {
                    pendingError = e
                }
            }
        }

        private fun drainTrailingWhitespace() {
            var count = 0
            while (count < MAX_OUTSIDE_WHITESPACE) {
                val b = src.read()
                if (b < 0) return
                count++
                if (!isWhitespaceByte(b)) {
                    throw ArmorFormatException("Trailing data after armored file")
                }
            }
            throw ArmorFormatException("Too much trailing whitespace after armored file")
        }

        private fun readLineStrict(): LineResult? {
            val buf = ByteArrayOutputStream(72)
            var rawLen = 0
            var endedWithLf = false
            while (true) {
                val b = src.read()
                if (b < 0) {
                    if (rawLen == 0) return null
                    break
                }
                rawLen++
                if (b == '\n'.code) {
                    endedWithLf = true
                    break
                }
                if (b > 0x7F) {
                    throw ArmorFormatException("Non-ASCII byte in armored stream")
                }
                buf.write(b)
                if (rawLen > MAX_OUTSIDE_WHITESPACE + 64) {
                    throw ArmorFormatException("Armor line is too long")
                }
            }
            val bytes = buf.toByteArray()
            val end = if (endedWithLf && bytes.isNotEmpty() && bytes[bytes.size - 1] == '\r'.code.toByte()) {
                bytes.size - 1
            } else {
                bytes.size
            }
            return LineResult(
                text = String(bytes, 0, end, StandardCharsets.US_ASCII),
                rawLength = rawLen,
            )
        }

        private fun isAllAsciiWhitespace(s: String): Boolean {
            for (i in s.indices) {
                if (!isWhitespaceByte(s[i].code)) {
                    return false
                }
            }
            return true
        }

        private fun isWhitespaceByte(b: Int): Boolean {
            return b == ' '.code || b == '\t'.code || b == '\n'.code || b == '\r'.code || b == 0x0B || b == 0x0C
        }

        private class LineResult(val text: String, val rawLength: Int)
    }
}
