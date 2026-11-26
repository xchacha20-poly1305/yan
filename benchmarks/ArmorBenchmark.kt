import io.github.xchacha20_poly1305.yan.Armor
import io.github.xchacha20_poly1305.yan.ArmorFormatException
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.Base64

object ArmorBenchmark {
    private const val PAYLOAD_SIZE = 1024 * 1024 + 49
    private const val WRITE_BLOCK = 8191

    @JvmStatic
    fun main(args: Array<String>) {
        val raw = Benchmark.deterministicBytes(PAYLOAD_SIZE)
        val armoredBytes = encodeStreaming(raw)
        verifyArmor(raw, armoredBytes)

        val cases = listOf(
            Benchmark.Case("Armor streaming decode", raw.size.toLong()) {
                val decoded = decodeWithOffset(armoredBytes, raw.size)
                Benchmark.blackhole(decoded)
            },
            Benchmark.Case("Armor streaming encode", raw.size.toLong()) {
                val out = encodeStreaming(raw)
                Benchmark.blackhole(out)
            },
        )
        Benchmark.run(args, cases)
    }

    private fun encodeStreaming(raw: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(raw.size * 4 / 3 + 128)
        Armor.wrap(out).use { armorOut ->
            var position = 0
            while (position < raw.size) {
                val len = minOf(WRITE_BLOCK, raw.size - position)
                armorOut.write(raw, position, len)
                position += len
            }
        }
        return out.toByteArray()
    }

    private fun decodeWithOffset(armored: ByteArray, expectedSize: Int): ByteArray {
        val buf = ByteArray(expectedSize + 64)
        var total = 0
        Armor.unwrap(ByteArrayInputStream(armored)).use { armorIn ->
            while (true) {
                val offset = 17
                val space = minOf(65536, buf.size - offset - total)
                val read = armorIn.read(buf, offset + total, space.coerceAtLeast(1))
                if (read < 0) break
                total += read
            }
        }
        Benchmark.requireTrue(total == expectedSize) { "Decoded size mismatch: $total != $expectedSize" }
        return buf
    }

    private fun verifyArmor(raw: ByteArray, armoredBytes: ByteArray) {
        val canonical = canonicalArmor(raw)
        Benchmark.requireTrue(armoredBytes.contentEquals(canonical)) {
            "Streaming armor output differs from canonical JDK MIME Base64"
        }

        val recoveredBuf = decodeWithOffset(armoredBytes, raw.size)
        for (i in raw.indices) {
            Benchmark.requireTrue(recoveredBuf[17 + i] == raw[i]) {
                "Decoded byte mismatch at index $i"
            }
        }

        for (size in intArrayOf(0, 1, 2, 3, 47, 48, 49, 96, 97)) {
            val sample = Benchmark.deterministicBytes(size, seed = size.toLong() + 99)
            val encoded = encodeStreaming(sample)
            Benchmark.requireTrue(encoded.contentEquals(canonicalArmor(sample))) {
                "Canonical mismatch for size $size"
            }
            Benchmark.requireTrue(Armor.decode(encoded).contentEquals(sample)) {
                "Round-trip mismatch for size $size"
            }
        }

        val crlfAndWhitespace = ("\r\n  \t\r\n" +
            String(armoredBytes, StandardCharsets.US_ASCII).replace("\n", "\r\n") +
            "\r\n  \r\n").toByteArray(StandardCharsets.US_ASCII)
        Benchmark.requireTrue(Armor.decode(crlfAndWhitespace).contentEquals(raw)) {
            "CRLF and outside whitespace decode failed"
        }

        val trailingGarbage = armoredBytes + "extra\n".toByteArray(StandardCharsets.US_ASCII)
        var failed = false
        try {
            Armor.decode(trailingGarbage)
        } catch (_: ArmorFormatException) {
            failed = true
        }
        Benchmark.requireTrue(failed) { "Trailing non-whitespace data was not rejected" }
    }

    private fun canonicalArmor(raw: ByteArray): ByteArray {
        val builder = StringBuilder(raw.size * 4 / 3 + 128)
        builder.append(Armor.BEGIN_LINE).append('\n')
        if (raw.isNotEmpty()) {
            val mime = Base64.getMimeEncoder(64, byteArrayOf('\n'.code.toByte())).encodeToString(raw)
            builder.append(mime).append('\n')
        }
        builder.append(Armor.END_LINE).append('\n')
        return builder.toString().toByteArray(StandardCharsets.US_ASCII)
    }
}
