import io.github.xchacha20_poly1305.yan.Age
import io.github.xchacha20_poly1305.yan.HybridIdentity
import io.github.xchacha20_poly1305.yan.HybridRecipient
import io.github.xchacha20_poly1305.yan.KeyFormatException
import io.github.xchacha20_poly1305.yan.X25519Identity
import io.github.xchacha20_poly1305.yan.X25519Recipient

object Bech32Benchmark {
    private const val HYBRID_KEY_BYTES = 1216L
    private const val X25519_KEY_BYTES = 32L

    @JvmStatic
    fun main(args: Array<String>) {
        val hybiardIdentity = HybridIdentity.generate()
        val hybirdRecipient = hybiardIdentity.recipient
        val hybirdEncoded = hybirdRecipient.encode()

        val x25519Identity = X25519Identity.generate()
        val x25519Recipient = x25519Identity.recipient
        val x25519Encoded = x25519Recipient.encode()

        verifyBech32(hybiardIdentity, hybirdEncoded, x25519Encoded)

        val cases = listOf(
            Benchmark.Case("Hybrid recipient decode", HYBRID_KEY_BYTES) {
                Benchmark.blackhole(HybridRecipient.parse(hybirdEncoded))
            },
            Benchmark.Case("Hybrid recipient encode", HYBRID_KEY_BYTES) {
                Benchmark.blackhole(hybirdRecipient.encode())
            },
            Benchmark.Case("X25519 recipient decode", X25519_KEY_BYTES) {
                Benchmark.blackhole(X25519Recipient.parse(x25519Encoded))
            },
            Benchmark.Case("X25519 recipient encode", X25519_KEY_BYTES) {
                Benchmark.blackhole(x25519Recipient.encode())
            },
        )
        Benchmark.run(args, cases)

        hybiardIdentity.close()
        x25519Identity.close()
    }

    private fun verifyBech32(
        hybirdIdentity: HybridIdentity,
        hybirdEncoded: String,
        x25519Encoded: String,
    ) {
        val parsedHybrid = HybridRecipient.parse(hybirdEncoded)
        val payload = Benchmark.deterministicBytes(64, seed = 9001L)
        val encrypted = Age.encryptBytes(payload, listOf(parsedHybrid))
        Benchmark.requireTrue(Age.decryptBytes(encrypted, listOf(hybirdIdentity)).contentEquals(payload)) {
            "Imported hybrid recipient round-trip failed"
        }

        // Known X25519 encoding check (32 zero bytes)
        val zeroEncoded = withValidChecksum("age", "q".repeat(52))
        val zeroRecipient = X25519Recipient.parse(zeroEncoded)
        Benchmark.requireTrue(zeroRecipient.publicKeyBytes().all { it == 0.toByte() }) {
            "Known X25519 encoding decode mismatch"
        }

        // Rejection checks
        val mixedCase = x25519Encoded.replaceFirstChar { it.uppercaseChar() }
        assertRejected("mixed case") { X25519Recipient.parse(mixedCase) }

        val invalidChar = x25519Encoded.substring(0, x25519Encoded.length - 1) + "b"
        assertRejected("invalid character") { X25519Recipient.parse(invalidChar) }

        val badChecksum = x25519Encoded.substring(0, x25519Encoded.length - 1) +
            if (x25519Encoded.last() == 'q') 'p' else 'q'
        assertRejected("incorrect checksum") { X25519Recipient.parse(badChecksum) }

        // Nonzero padding with valid checksum:
        // Valid 32-byte payload needs 52 5-bit groups (260 bits = 256 + 4 padding bits).
        // Flip the last data char (index length - 7) to have nonzero padding, then recompute checksum.
        val nonzeroPad = withValidChecksum(
            hrp = "age",
            dataChars = x25519Encoded.substring(4, x25519Encoded.length - 6).let { data ->
                val lastIdx = data.length - 1
                val flipped = if (data[lastIdx] == 'q') {
                    'p'
                } else {
                    'q'
                }
                data.substring(0, lastIdx) + flipped
            },
        )
        assertRejected("nonzero padding with valid checksum") { X25519Recipient.parse(nonzeroPad) }
    }

    private fun assertRejected(label: String, block: () -> Unit) {
        var rejected = false
        try {
            block()
        } catch (_: KeyFormatException) {
            rejected = true
        }
        Benchmark.requireTrue(rejected) { "Expected KeyFormatException for $label" }
    }

    private fun withValidChecksum(hrp: String, dataChars: String): String {
        val charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        val values = IntArray(dataChars.length + 6)
        for (i in dataChars.indices) {
            values[i] = charset.indexOf(dataChars[i])
        }
        var chk = 1
        for (char in hrp) {
            chk = polymodStep(chk) xor (char.code ushr 5)
        }
        chk = polymodStep(chk)
        for (char in hrp) {
            chk = polymodStep(chk) xor (char.code and 31)
        }
        for (value in values) {
            chk = polymodStep(chk) xor value
        }
        chk = chk xor 1
        val builder = StringBuilder(hrp.length + 1 + dataChars.length + 6)
        builder.append(hrp).append('1').append(dataChars)
        for (i in 0 until 6) {
            builder.append(charset[(chk ushr (5 * (5 - i))) and 31])
        }
        return builder.toString()
    }

    private fun polymodStep(pre: Int): Int {
        val b = pre ushr 25
        var c = (pre and 0x1ffffff) shl 5
        if ((b and 1) != 0) c = c xor 0x3b6a57b2
        if ((b and 2) != 0) c = c xor 0x26508e6d
        if ((b and 4) != 0) c = c xor 0x1ea119fa
        if ((b and 8) != 0) c = c xor 0x3d4233dd
        if ((b and 16) != 0) c = c xor 0x2a1462b3
        return c
    }
}
