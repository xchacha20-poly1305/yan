import io.github.xchacha20_poly1305.yan.Age
import io.github.xchacha20_poly1305.yan.KeyFormatException
import io.github.xchacha20_poly1305.yan.X25519Identity
import java.io.Reader
import java.io.StringReader
import kotlin.math.min

object KeyFileBenchmark {
    private const val MAX_CHUNK_CHARS = 127
    private const val KEY_FILE_LIMIT = 1 shl 24

    @JvmStatic
    fun main(args: Array<String>) {
        val sampleIdentities = List(64) { X25519Identity.generate() }
        val recipientFileText = buildKeyFile(
            entries = sampleIdentities.map { it.recipient.encode() },
            targetUtf8Bytes = 156 * 1024,
        )
        val identityFileText = buildKeyFile(
            entries = sampleIdentities.take(2).map { it.encode() },
            targetUtf8Bytes = 156 * 1024,
        )
        val recipientUtf8Bytes = recipientFileText.toByteArray(Charsets.UTF_8).size.toLong()
        val identityUtf8Bytes = identityFileText.toByteArray(Charsets.UTF_8).size.toLong()

        verifyKeyFileEdgeCases(sampleIdentities[0])
        sampleIdentities.forEach { it.close() }

        val cases = listOf(
            Benchmark.Case("Recipient file import", recipientUtf8Bytes) {
                val parsed = Age.parseRecipients(ChunkedReader(recipientFileText, MAX_CHUNK_CHARS))
                Benchmark.requireTrue(parsed.size == 64) { "Expected 64 recipients, got ${parsed.size}" }
                Benchmark.blackhole(parsed)
            },
            Benchmark.Case("Identity file import", identityUtf8Bytes) {
                val parsed = Age.parseIdentities(ChunkedReader(identityFileText, MAX_CHUNK_CHARS))
                Benchmark.requireTrue(parsed.size == 2) { "Expected 2 identities, got ${parsed.size}" }
                parsed.forEach {
                    (it as? AutoCloseable)?.close()
                }
                Benchmark.blackhole(parsed)
            },
        )
        Benchmark.run(args, cases)
    }

    private fun buildKeyFile(entries: List<String>, targetUtf8Bytes: Int): String {
        val commentLine = "# comment with multibyte chars: 密钥文件測試 🚀 αβγ\n"
        val builder = StringBuilder(targetUtf8Bytes + 512)
        var entryIndex = 0
        var currentBytes = 0
        val commentBytes = commentLine.toByteArray(Charsets.UTF_8).size
        while (currentBytes < targetUtf8Bytes || entryIndex < entries.size) {
            if (entryIndex < entries.size && (currentBytes % 2048 < 128 || currentBytes >= targetUtf8Bytes)) {
                val line = entries[entryIndex++] + "\n"
                builder.append(line)
                currentBytes += line.toByteArray(Charsets.UTF_8).size
            } else {
                builder.append(commentLine)
                currentBytes += commentBytes
            }
        }
        return builder.toString()
    }

    private fun verifyKeyFileEdgeCases(sampleId: X25519Identity) {
        val recipient = sampleId.recipient.encode()
        // Surrogate pair split across 1-char reads + CRLF
        val splitText = "# emoji \uD83D\uDE80\r\n\r\n$recipient\r\n"
        val parsed = Age.parseRecipients(ChunkedReader(splitText, 1))
        Benchmark.requireTrue(parsed.size == 1 && parsed[0].toString() == recipient) {
            "Split surrogate pair + CRLF parse failed"
        }

        // Malformed UTF-16 in comment
        var badUtf16Rejected = false
        try {
            Age.parseRecipients(StringReader("# lone high \uD800\n$recipient\n"))
        } catch (_: KeyFormatException) {
            badUtf16Rejected = true
        }
        Benchmark.requireTrue(badUtf16Rejected) { "Malformed UTF-16 in comment was not rejected" }

        // Line number reporting
        var lineErrMsg = ""
        try {
            Age.parseRecipients("# c1\n\n$recipient\ninvalid-recipient\n")
        } catch (e: KeyFormatException) {
            lineErrMsg = e.message.orEmpty()
        }
        Benchmark.requireTrue(lineErrMsg.contains("4")) {
            "Expected line number 4 in error message, got: $lineErrMsg"
        }

        // Exact 16 MiB encoded size limit
        val pad = "# " + "a".repeat(1021) + "\n" // 1024 bytes
        val recLine = "$recipient\n"
        val limitReader = object : Reader() {
            private var remaining = KEY_FILE_LIMIT
            private var posInRec = 0

            override fun read(cbuf: CharArray, off: Int, len: Int): Int {
                if (remaining <= 0) return -1
                if (remaining <= recLine.length) {
                    val toCopy = min(len, recLine.length - posInRec)
                    if (toCopy <= 0) return -1
                    recLine.toCharArray(cbuf, off, posInRec, posInRec + toCopy)
                    posInRec += toCopy
                    remaining -= toCopy
                    return toCopy
                }
                val chunk = min(len, remaining - recLine.length)
                var written = 0
                while (written < chunk) {
                    val idx = (KEY_FILE_LIMIT - remaining) % pad.length
                    cbuf[off + written] = if (remaining == recLine.length + 1) {
                        '\n'
                    } else {
                        pad[idx]
                    }
                    written++
                    remaining--
                }
                return written
            }

            override fun close() {}
        }
        val atLimit = Age.parseRecipients(limitReader)
        Benchmark.requireTrue(atLimit.size == 1) { "Exact 16 MiB limit should be accepted" }

        var overLimitRejected = false
        val overLimitReader = StringReader(" ".repeat(KEY_FILE_LIMIT + 1))
        try {
            Age.parseRecipients(overLimitReader)
        } catch (_: KeyFormatException) {
            overLimitRejected = true
        }
        Benchmark.requireTrue(overLimitRejected) { "Over 16 MiB key file was not rejected" }
    }

    private class ChunkedReader(
        private val text: String,
        private val maxChunk: Int,
    ) : Reader() {
        private var pos = 0

        override fun read(cbuf: CharArray, off: Int, len: Int): Int {
            if (pos >= text.length) return -1
            val count = min(min(len, maxChunk), text.length - pos)
            text.toCharArray(cbuf, off, pos, pos + count)
            pos += count
            return count
        }

        override fun close() {}
    }
}
