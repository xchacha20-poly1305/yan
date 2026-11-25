package io.github.xchacha20_poly1305.yan.internal

import io.github.xchacha20_poly1305.yan.ArmorFormatException
import io.github.xchacha20_poly1305.yan.HeaderFormatException
import io.github.xchacha20_poly1305.yan.Stanza
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets

internal object HeaderFormat {
    const val VERSION_LINE: String = "age-encryption.org/v1\n"
    const val MAX_HEADER_BYTES: Int = 2 * 1024 * 1024
    const val MAX_STANZAS: Int = 1024
    const val MAX_STANZA_ARGS: Int = 128
    const val COLUMNS_PER_LINE: Int = 64
    const val BYTES_PER_LINE: Int = 48

    private val STANZA_PREFIX_BYTES = byteArrayOf('-'.code.toByte(), '>'.code.toByte())
    private val FOOTER_PREFIX_BYTES = byteArrayOf('-'.code.toByte(), '-'.code.toByte(), '-'.code.toByte())
    private val HEADER_MAC_INFO = "header".toByteArray(StandardCharsets.US_ASCII)

    data class Header(
        val stanzas: List<Stanza>,
        val mac: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Header

            if (stanzas != other.stanzas) return false
            if (!mac.contentEquals(other.mac)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = stanzas.hashCode()
            result = 31 * result + mac.contentHashCode()
            return result
        }
    }

    data class ParsedHeader(
        val header: Header,
        val remaining: InputStream,
    )

    fun parse(input: InputStream): ParsedHeader {
        val bis = input as? BufferedInputStream ?: BufferedInputStream(input)
        val counter = ByteCounter()

        val introLine = try {
            readLineLf(bis, counter)
        } catch (e: ArmorFormatException) {
            throw e
        } catch (e: HeaderFormatException) {
            throw e
        } catch (e: IOException) {
            throw HeaderFormatException("Failed to read age version line", e)
        }

        if (introLine != "age-encryption.org/v1") {
            throw HeaderFormatException("Unexpected age version line")
        }

        val stanzas = ArrayList<Stanza>()
        var macBytes: ByteArray? = null

        while (true) {
            val prefix = try {
                peekThreeBytes(bis, counter)
            } catch (e: ArmorFormatException) {
                throw e
            } catch (e: HeaderFormatException) {
                throw e
            } catch (e: IOException) {
                throw HeaderFormatException("Failed to read header", e)
            }

            if (prefix == null) {
                throw HeaderFormatException("Unexpected EOF reading age header")
            }

            if (prefix.contentEquals(FOOTER_PREFIX_BYTES)) {
                val footerLine = try {
                    readLineLf(bis, counter)
                } catch (e: ArmorFormatException) {
                    throw e
                } catch (e: HeaderFormatException) {
                    throw e
                } catch (e: IOException) {
                    throw HeaderFormatException("Failed to read header MAC line", e)
                }
                val parts = splitArgsStrict(footerLine)
                if (parts.size != 2 || parts[0] != "---") {
                    throw HeaderFormatException("Malformed header closing line")
                }
                val decodedMac = try {
                    Base64Strict.decodeRaw(parts[1])
                } catch (e: IllegalArgumentException) {
                    throw HeaderFormatException("Malformed header MAC encoding", e)
                }
                if (decodedMac.size != 32) {
                    throw HeaderFormatException("Invalid header MAC length: ${decodedMac.size}")
                }
                macBytes = decodedMac
                break
            }

            if (stanzas.size >= MAX_STANZAS) {
                throw HeaderFormatException("Header exceeds maximum stanza count ($MAX_STANZAS)")
            }

            val stanza = readStanza(bis, counter)
            stanzas.add(stanza)
        }

        if (stanzas.isEmpty()) {
            throw HeaderFormatException("Header must contain at least one recipient stanza")
        }

        return ParsedHeader(Header(stanzas, macBytes), bis)
    }

    private fun readStanza(bis: BufferedInputStream, counter: ByteCounter): Stanza {
        val argLine = try {
            readLineLf(bis, counter)
        } catch (e: ArmorFormatException) {
            throw e
        } catch (e: HeaderFormatException) {
            throw e
        } catch (e: IOException) {
            throw HeaderFormatException("Failed to read stanza opening line", e)
        }

        val parts = splitArgsStrict(argLine)
        if (parts.size < 2 || parts[0] != "->") {
            throw HeaderFormatException("Malformed stanza opening line")
        }
        val argCount = parts.size - 2
        if (argCount > MAX_STANZA_ARGS) {
            throw HeaderFormatException("Stanza exceeds maximum argument count ($MAX_STANZA_ARGS)")
        }
        val type = parts[1]
        val args = if (parts.size == 2) {
            emptyList()
        } else {
            parts.subList(2, parts.size)
        }

        val bodyOut = ByteArrayOutputStream()
        while (true) {
            val line = try {
                readLineLf(bis, counter)
            } catch (e: ArmorFormatException) {
                throw e
            } catch (e: HeaderFormatException) {
                throw e
            } catch (e: IOException) {
                throw HeaderFormatException("Failed to read stanza body line", e)
            }

            if (line.length > COLUMNS_PER_LINE) {
                throw HeaderFormatException("Stanza body line exceeds $COLUMNS_PER_LINE characters")
            }

            val decoded = try {
                Base64Strict.decodeRaw(line)
            } catch (e: IllegalArgumentException) {
                throw HeaderFormatException("Malformed stanza body line", e)
            }

            if (decoded.size > BYTES_PER_LINE) {
                throw HeaderFormatException("Stanza body line exceeds $BYTES_PER_LINE decoded bytes")
            }

            bodyOut.write(decoded)
            if (decoded.size < BYTES_PER_LINE) {
                break
            }
        }

        return Stanza(type, args, bodyOut.toByteArray())
    }

    private fun readLineLf(bis: BufferedInputStream, counter: ByteCounter): String {
        val lineBuf = ByteArrayOutputStream(80)
        while (true) {
            if (counter.count >= MAX_HEADER_BYTES) {
                throw HeaderFormatException("Header exceeds $MAX_HEADER_BYTES bytes")
            }
            val b = bis.read()
            if (b < 0) {
                throw HeaderFormatException("Unexpected EOF in header")
            }
            counter.count++
            if (b == '\n'.code) {
                break
            }
            lineBuf.write(b)
        }
        val bytes = lineBuf.toByteArray()
        return String(bytes, StandardCharsets.US_ASCII)
    }

    private fun peekThreeBytes(bis: BufferedInputStream, counter: ByteCounter): ByteArray? {
        if (counter.count + 3 > MAX_HEADER_BYTES) {
            throw HeaderFormatException("Header exceeds $MAX_HEADER_BYTES bytes")
        }
        bis.mark(3)
        val byte0 = bis.read()
        val byte1 = if (byte0 >= 0) {
            bis.read()
        } else {
            -1
        }
        val byte2 = if (byte1 >= 0) {
            bis.read()
        } else {
            -1
        }
        bis.reset()
        if (byte0 < 0 || byte1 < 0 || byte2 < 0) {
            return null
        }
        return byteArrayOf(byte0.toByte(), byte1.toByte(), byte2.toByte())
    }

    private fun splitArgsStrict(line: String): List<String> {
        if (line.isEmpty()) {
            throw HeaderFormatException("Empty header line")
        }
        val result = ArrayList<String>(4)
        var tokenStart = 0
        for (i in line.indices) {
            val char = line[i]
            val code = char.code
            if (code == ' '.code) {
                if (i == tokenStart) {
                    throw HeaderFormatException("Unexpected leading or consecutive space in header line")
                }
                result.add(line.substring(tokenStart, i))
                tokenStart = i + 1
            } else if (!isVchar(code)) {
                throw HeaderFormatException("Invalid character in header line: 0x${code.toString(16)}")
            }
        }
        if (tokenStart >= line.length) {
            throw HeaderFormatException("Trailing space in header line")
        }
        result.add(line.substring(tokenStart))
        return result
    }

    fun isValidVcharString(s: String): Boolean {
        if (s.isEmpty()) return false
        for (i in s.indices) {
            if (!isVchar(s[i].code)) {
                return false
            }
        }
        return true
    }

    private fun isVchar(code: Int): Boolean = code in 0x21..0x7E

    fun marshalWithoutMac(stanzas: List<Stanza>, out: OutputStream) {
        if (stanzas.isEmpty()) {
            throw HeaderFormatException("Header must contain at least one recipient stanza")
        }
        out.write(VERSION_LINE.toByteArray(StandardCharsets.US_ASCII))
        for (stanza in stanzas) {
            marshalStanza(stanza, out)
        }
        out.write(FOOTER_PREFIX_BYTES)
    }

    fun marshal(header: Header, out: OutputStream) {
        marshalWithoutMac(header.stanzas, out)
        val encodedMac = Base64Strict.encodeRaw(header.mac)
        out.write(' '.code)
        out.write(encodedMac.toByteArray(StandardCharsets.US_ASCII))
        out.write('\n'.code)
    }

    fun computeMac(stanzas: List<Stanza>, fileKey: ByteArray): ByteArray {
        val buf = ByteArrayOutputStream()
        marshalWithoutMac(stanzas, buf)
        val hmacKey = CryptoPrimitives.hkdfSha256(
            ikm = fileKey,
            salt = CryptoPrimitives.EMPTY_BYTES,
            info = HEADER_MAC_INFO,
            length = 32,
        )
        try {
            return CryptoPrimitives.hmacSha256(hmacKey, buf.toByteArray())
        } finally {
            CryptoPrimitives.zero(hmacKey)
        }
    }

    private fun marshalStanza(stanza: Stanza, out: OutputStream) {
        if (!isValidVcharString(stanza.type)) {
            throw HeaderFormatException("Invalid stanza type: '${stanza.type}'")
        }
        for (arg in stanza.args) {
            if (!isValidVcharString(arg)) {
                throw HeaderFormatException("Invalid stanza argument: '$arg'")
            }
        }
        out.write(STANZA_PREFIX_BYTES)
        out.write(' '.code)
        out.write(stanza.type.toByteArray(StandardCharsets.US_ASCII))
        for (arg in stanza.args) {
            out.write(' '.code)
            out.write(arg.toByteArray(StandardCharsets.US_ASCII))
        }
        out.write('\n'.code)

        val encoded = Base64Strict.encodeRaw(stanza.rawBody)
        var offset = 0
        while (offset + COLUMNS_PER_LINE <= encoded.length) {
            out.write(encoded.substring(offset, offset + COLUMNS_PER_LINE).toByteArray(StandardCharsets.US_ASCII))
            out.write('\n'.code)
            offset += COLUMNS_PER_LINE
        }
        if (offset < encoded.length) {
            out.write(encoded.substring(offset).toByteArray(StandardCharsets.US_ASCII))
        }
        out.write('\n'.code)
    }

    private class ByteCounter {
        var count: Int = 0
    }
}
