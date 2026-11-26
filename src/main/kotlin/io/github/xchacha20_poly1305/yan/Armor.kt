package io.github.xchacha20_poly1305.yan

import io.github.xchacha20_poly1305.yan.internal.Base64Strict
import io.github.xchacha20_poly1305.yan.internal.CryptoPrimitives
import java.io.ByteArrayInputStream
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
    private const val MAX_LINE_BYTES = MAX_OUTSIDE_WHITESPACE + COLUMNS_PER_LINE
    private const val LF = 0x0A

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
        val out = CryptoPrimitives.memoryOutput(encodedSize(data.size.toLong()))
        wrap(out).use { it.write(data) }
        return out.toString(StandardCharsets.US_ASCII.name())
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
            return CryptoPrimitives.readAllCompat(stream, decodedSizeBound(armored.size))
        }
    }

    internal fun encodedSize(binarySize: Long): Long {
        val body = ((binarySize + 2) / 3) * 4
        val lineBreaks = (body + COLUMNS_PER_LINE - 1) / COLUMNS_PER_LINE
        return BEGIN_LINE.length + END_LINE.length + 2 + body + lineBreaks
    }

    internal fun decodedSizeBound(armoredSize: Int): Int {
        // The footer need not have a terminating newline. CRLF and outside whitespace
        // can only increase the encoded size for a given amount of binary data.
        val body = maxOf(0, armoredSize - BEGIN_LINE.length - END_LINE.length - 1)
        val lineBreaks = (body.toLong() + COLUMNS_PER_LINE) / (COLUMNS_PER_LINE + 1)
        return (((body - lineBreaks) / 4) * 3).toInt()
    }

    private class ArmoredOutputStream(private val dst: OutputStream) : OutputStream() {
        private var started = false
        private var closed = false
        private val rawBuf = ByteArray(BYTES_PER_LINE)
        private var rawLen = 0
        private val singleByte = ByteArray(1)
        private val encoded = ByteArray((COLUMNS_PER_LINE + 1) * 64)

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

            var position = off
            val end = off + len
            var encodedLen = 0
            if (rawLen > 0) {
                val toCopy = minOf(len, BYTES_PER_LINE - rawLen)
                System.arraycopy(b, position, rawBuf, rawLen, toCopy)
                rawLen += toCopy
                position += toCopy
                if (position == end) {
                    return
                }

                encodedLen = encodeLine(rawBuf, 0, rawLen, encodedLen)
                rawLen = 0
            }

            // Keep the final line buffered until more input arrives or the stream is closed.
            while (end - position > BYTES_PER_LINE) {
                encodedLen = encodeLine(b, position, position + BYTES_PER_LINE, encodedLen)
                position += BYTES_PER_LINE
                if (encodedLen == encoded.size) {
                    dst.write(encoded, 0, encodedLen)
                    encodedLen = 0
                }
            }
            if (encodedLen > 0) {
                dst.write(encoded, 0, encodedLen)
            }
            rawLen = end - position
            System.arraycopy(b, position, rawBuf, 0, rawLen)
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
                    val encodedLen = encodeLine(rawBuf, 0, rawLen, 0)
                    dst.write(encoded, 0, encodedLen)
                }
                dst.write(END_BYTES)
                dst.flush()
                dst.close()
            } finally {
                CryptoPrimitives.zero(rawBuf)
                CryptoPrimitives.zero(singleByte)
                CryptoPrimitives.zero(encoded)
            }
        }

        private fun ensureStarted() {
            if (started) return
            dst.write(BEGIN_BYTES)
            started = true
        }

        private fun encodeLine(source: ByteArray, start: Int, end: Int, offset: Int): Int {
            val lineEnd = offset + Base64Strict.encodePaddedInto(source, encoded, offset, start, end)
            encoded[lineEnd] = LF.toByte()
            return lineEnd + 1
        }

        private companion object {
            val BEGIN_BYTES: ByteArray = (BEGIN_LINE + "\n").toByteArray(StandardCharsets.US_ASCII)
            val END_BYTES: ByteArray = (END_LINE + "\n").toByteArray(StandardCharsets.US_ASCII)
        }
    }

    private class ArmoredInputStream(private val src: InputStream) : InputStream() {
        private var started = false
        private var eof = false
        private var closed = false
        private var pendingError: ArmorFormatException? = null
        private val unread = ByteArray(BYTES_PER_LINE)
        private var unreadLen = 0
        private var unreadPos = 0
        private val line = ByteArray(MAX_LINE_BYTES)
        private var lineLen = 0
        private var rawLineLen = 0
        private val sourceBuffer = ByteArray(8192)
        private var sourcePos = 0
        private var sourceLen = 0
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
            if (len == 0) {
                return 0
            }

            if (unreadPos == unreadLen) {
                pendingError?.let { throw it }
                if (eof) {
                    return -1
                }

                try {
                    readNextChunk()
                } catch (e: ArmorFormatException) {
                    pendingError = e
                    throw e
                }
            }

            if (unreadPos == unreadLen) {
                return -1
            }
            val toCopy = minOf(len, unreadLen - unreadPos)
            System.arraycopy(unread, unreadPos, b, off, toCopy)
            unreadPos += toCopy
            if (unreadPos == unreadLen) {
                CryptoPrimitives.zero(unread)
            }
            return toCopy
        }

        override fun close() {
            if (closed) return
            closed = true
            CryptoPrimitives.zero(unread)
            CryptoPrimitives.zero(singleByte)
            CryptoPrimitives.zero(line)
            CryptoPrimitives.zero(sourceBuffer)
            src.close()
        }

        private fun readNextChunk() {
            if (!started) {
                var removedWhitespace = 0
                while (true) {
                    if (!readLineStrict()) {
                        throw ArmorFormatException("Unexpected EOF before armor begin line")
                    }
                    if (isAllAsciiWhitespace()) {
                        removedWhitespace += rawLineLen
                        if (removedWhitespace > MAX_OUTSIDE_WHITESPACE) {
                            throw ArmorFormatException("Too much leading whitespace before armor header")
                        }
                        continue
                    }
                    if (!lineMatches(BEGIN_LINE)) {
                        throw ArmorFormatException("Invalid armor begin line")
                    }
                    started = true
                    break
                }
            }

            if (!readLineStrict()) {
                throw ArmorFormatException("Unexpected EOF inside armored body")
            }
            if (lineMatches(END_LINE)) {
                drainTrailingWhitespace()
                eof = true
                return
            }
            if (lineLen == 0) {
                throw ArmorFormatException("Empty line in armored body")
            }
            if (lineLen > COLUMNS_PER_LINE) {
                throw ArmorFormatException("Armor line exceeds $COLUMNS_PER_LINE columns")
            }
            unreadLen = try {
                Base64Strict.decodePaddedInto(line, unread, lineLen)
            } catch (e: IllegalArgumentException) {
                throw ArmorFormatException("Invalid base64 in armored body", e)
            }
            unreadPos = 0

            if (unreadLen < BYTES_PER_LINE) {
                if (!readLineStrict()) {
                    throw ArmorFormatException("Unexpected EOF before armor end line")
                }
                if (!lineMatches(END_LINE)) {
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
                if (!hasSourceBytes()) return
                val b = sourceBuffer[sourcePos++].toInt() and 0xFF
                count++
                if (!isWhitespaceByte(b)) {
                    throw ArmorFormatException("Trailing data after armored file")
                }
            }
            throw ArmorFormatException("Too much trailing whitespace after armored file")
        }

        private fun hasSourceBytes(): Boolean {
            if (sourcePos < sourceLen) return true
            sourceLen = src.read(sourceBuffer, 0, sourceBuffer.size)
            sourcePos = 0
            if (sourceLen == 0) {
                val byte = src.read()
                if (byte < 0) return false
                sourceBuffer[0] = byte.toByte()
                sourceLen = 1
            }
            return sourceLen > 0
        }

        private fun readLineStrict(): Boolean {
            var length = 0
            while (hasSourceBytes()) {
                val limit = sourceLen
                while (sourcePos < limit) {
                    val b = sourceBuffer[sourcePos++].toInt() and 0xFF
                    if (b == LF) {
                        rawLineLen = length + 1
                        lineLen = if (length > 0 && line[length - 1] == '\r'.code.toByte()) length - 1 else length
                        return true
                    }
                    if (b > 0x7F) {
                        throw ArmorFormatException("Non-ASCII byte in armored stream")
                    }
                    if (length == MAX_LINE_BYTES) {
                        throw ArmorFormatException("Armor line is too long")
                    }
                    line[length++] = b.toByte()
                }
            }
            rawLineLen = length
            lineLen = length
            return length > 0
        }

        private fun lineMatches(expected: String): Boolean {
            if (lineLen != expected.length) {
                return false
            }
            for (i in 0 until lineLen) {
                if (line[i].toInt() != expected[i].code) {
                    return false
                }
            }
            return true
        }

        private fun isAllAsciiWhitespace(): Boolean {
            for (i in 0 until lineLen) {
                if (!isWhitespaceByte(line[i].toInt())) {
                    return false
                }
            }
            return true
        }

        private fun isWhitespaceByte(b: Int): Boolean {
            return b == ' '.code || b == '\t'.code || b == '\n'.code || b == '\r'.code || b == 0x0B || b == 0x0C
        }
    }
}
