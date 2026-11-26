import io.github.xchacha20_poly1305.yan.Age
import io.github.xchacha20_poly1305.yan.HeaderFormatException
import io.github.xchacha20_poly1305.yan.HeaderMacException
import io.github.xchacha20_poly1305.yan.HybridIdentity
import io.github.xchacha20_poly1305.yan.Identity
import io.github.xchacha20_poly1305.yan.Recipient
import io.github.xchacha20_poly1305.yan.Stanza
import io.github.xchacha20_poly1305.yan.X25519Identity

object HeaderRecipientBenchmark {
    private const val PAYLOAD_SIZE = 133

    @JvmStatic
    fun main(args: Array<String>) {
        val payload = Benchmark.deterministicBytes(PAYLOAD_SIZE, seed = 777L)
        val x25519Identity = X25519Identity.generate()
        val hybirdIdentity = HybridIdentity.generate()

        val ext128 = List(128) { i ->
            val body = Benchmark.deterministicBytes((i * 17) % 513, seed = i.toLong() + 1)
            DummyRecipient("x-ext-$i", listOf("arg0", "arg$i"), body)
        }
        val largeRecipients = ext128 + x25519Identity.recipient
        val largeCt = Age.encryptBytes(payload, largeRecipients)
        val singleXCt = Age.encryptBytes(payload, listOf(x25519Identity.recipient))

        val ext512 = List(512) { idx ->
            DummyRecipient("x-pad-$idx", listOf("a$idx"), Benchmark.deterministicBytes(32, seed = idx.toLong()))
        }
        val x25519SearchEncrypted = Age.encryptBytes(payload, ext512 + x25519Identity.recipient)
        val wrongX25519Identies = List(32) { X25519Identity.generate() }
        val x25519SearchIdentities: List<Identity> = wrongX25519Identies + x25519Identity

        val hybridWrongIdentities = List(8) { HybridIdentity.generate() }
        val hybridRecipients = List(4) { i ->
            if (i == 3) {
                hybirdIdentity.recipient
            } else {
                hybridWrongIdentities[i].recipient
            }
        }
        val hybridSearchEncrypted = Age.encryptBytes(payload, hybridRecipients)
        val hybridSearchIdenties: List<Identity> = hybridWrongIdentities + hybirdIdentity

        verifyHeaderAndRecipients(payload, x25519Identity, hybirdIdentity)

        val cases = listOf(
            Benchmark.Case("Large seal", PAYLOAD_SIZE.toLong()) {
                Benchmark.blackhole(Age.encryptBytes(payload, largeRecipients))
            },
            Benchmark.Case("Large open", PAYLOAD_SIZE.toLong()) {
                Benchmark.blackhole(Age.decryptBytes(largeCt, listOf(x25519Identity)))
            },
            Benchmark.Case("Single X25519 seal", PAYLOAD_SIZE.toLong()) {
                Benchmark.blackhole(Age.encryptBytes(payload, listOf(x25519Identity.recipient)))
            },
            Benchmark.Case("Single X25519 open", PAYLOAD_SIZE.toLong()) {
                Benchmark.blackhole(Age.decryptBytes(singleXCt, listOf(x25519Identity)))
            },
            Benchmark.Case("X25519 search", PAYLOAD_SIZE.toLong()) {
                Benchmark.blackhole(Age.decryptBytes(x25519SearchEncrypted, x25519SearchIdentities))
            },
            Benchmark.Case("Hybrid search", PAYLOAD_SIZE.toLong()) {
                Benchmark.blackhole(Age.decryptBytes(hybridSearchEncrypted, hybridSearchIdenties))
            },
            Benchmark.Case("Repeated hybrid seal", PAYLOAD_SIZE.toLong()) {
                Benchmark.blackhole(Age.encryptBytes(payload, listOf(hybirdIdentity.recipient)))
            },
        )
        Benchmark.run(args, cases)

        x25519Identity.close()
        hybirdIdentity.close()
        wrongX25519Identies.forEach { it.close() }
        hybridWrongIdentities.forEach { it.close() }
    }

    private fun verifyHeaderAndRecipients(
        payload: ByteArray,
        x25519Identies: X25519Identity,
        hybirdIdentities: HybridIdentity,
    ) {
        // MAC rejection
        val encrypted = Age.encryptBytes(payload, listOf(x25519Identies.recipient))
        val macMarker = "\n--- ".toByteArray(Charsets.US_ASCII)
        val macIndex = indexOfBytes(encrypted, macMarker)
        Benchmark.requireTrue(macIndex >= 0) { "Could not locate header MAC" }
        val badMacEncrypted = encrypted.copyOf()
        val flipPos = macIndex + macMarker.size
        badMacEncrypted[flipPos] = if (badMacEncrypted[flipPos] == 'A'.code.toByte()) {
            'B'.code.toByte()
        } else {
            'A'.code.toByte()
        }
        var macRejected = false
        try {
            Age.decryptBytes(badMacEncrypted, listOf(x25519Identies))
        } catch (_: HeaderMacException) {
            macRejected = true
        }
        Benchmark.requireTrue(macRejected) { "Invalid header MAC was not rejected" }

        // Native-before-custom ordering and custom stanza-list order
        val seenOrder = ArrayList<String>()
        val customRecordingId = object : Identity {
            override fun unwrap(stanzas: List<Stanza>): ByteArray? {
                seenOrder.add("custom")
                Benchmark.requireTrue(stanzas.size == 2 && stanzas[0].type == "x-first" && stanzas[1].type == "X25519") {
                    "Unexpected stanza list order: ${stanzas.map { it.type }}"
                }
                return null
            }
        }
        val twoStanzaCt = Age.encryptBytes(
            payload,
            listOf(DummyRecipient("x-first", listOf("1"), byteArrayOf(1, 2, 3)), x25519Identies.recipient),
        )
        Benchmark.requireTrue(Age.decryptBytes(twoStanzaCt, listOf(customRecordingId, x25519Identies)).contentEquals(payload)) {
            "Native-before-custom unwrap failed"
        }
        Benchmark.requireTrue(seenOrder.isEmpty()) { "Custom identity ran before native identity" }

        // Malformed native stanza reporting
        val malformedCt = Age.encryptBytes(
            payload,
            listOf(DummyRecipient("X25519", listOf("badarg"), byteArrayOf(1, 2))),
        )
        var malformedRejected = false
        try {
            Age.decryptBytes(malformedCt, listOf(x25519Identies))
        } catch (_: HeaderFormatException) {
            malformedRejected = true
        }
        Benchmark.requireTrue(malformedRejected) { "Malformed native stanza was not rejected" }

        // Hybrid sanity
        val hCt = Age.encryptBytes(payload, listOf(hybirdIdentities.recipient))
        Benchmark.requireTrue(Age.decryptBytes(hCt, listOf(hybirdIdentities)).contentEquals(payload)) {
            "Hybrid round-trip failed"
        }
    }

    private fun indexOfBytes(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) {
                    continue@outer
                }
            }
            return i
        }
        return -1
    }

    private class DummyRecipient(
        private val type: String,
        private val args: List<String>,
        private val body: ByteArray,
    ) : Recipient {
        override fun wrap(fileKey: ByteArray): List<Stanza> = listOf(Stanza(type, args, body))
    }
}
