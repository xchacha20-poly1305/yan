import io.github.xchacha20_poly1305.yan.Age
import io.github.xchacha20_poly1305.yan.Armor
import io.github.xchacha20_poly1305.yan.PayloadDecryptionException
import io.github.xchacha20_poly1305.yan.X25519Identity
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream

object PayloadBenchmark {
    private const val LARGE_SIZE = 1024 * 1024 + 413
    private const val SMALL_SIZE = 133
    private const val FRAGMENT_SIZE = 8191
    private const val READ_BLOCK = 65536
    private const val CHUNK_SIZE = 65536

    @JvmStatic
    fun main(args: Array<String>) {
        val identity = X25519Identity.generate()
        val recipient = identity.recipient
        val recipients = listOf(recipient)
        val identities = listOf(identity)

        val largePlaintext = Benchmark.deterministicBytes(LARGE_SIZE)
        val smallPlaintext = Benchmark.deterministicBytes(SMALL_SIZE, seed = 42L)

        val largeCiphertext = Age.encryptBytes(largePlaintext, recipients)
        val smallCiphertext = Age.encryptBytes(smallPlaintext, recipients)
        val largeArmored = Age.encryptToArmoredString(largePlaintext, recipients)
        val armorString = Armor.encode(largePlaintext)
        val armorBytes = armorString.toByteArray(Charsets.US_ASCII)

        verifyPayloadBehavior(identity, largePlaintext, smallPlaintext)

        val readBuf = ByteArray(READ_BLOCK + 32)
        val cases = listOf(
            Benchmark.Case("Fragmented seal", LARGE_SIZE.toLong()) {
                val out = ByteArrayOutputStream(largeCiphertext.size)
                Age.encrypt(out, recipients).use { enc ->
                    var pos = 0
                    while (pos < largePlaintext.size) {
                        val len = minOf(FRAGMENT_SIZE, largePlaintext.size - pos)
                        enc.write(largePlaintext, pos, len)
                        pos += len
                    }
                }
                Benchmark.blackhole(out.size())
            },
            Benchmark.Case("Aligned open", LARGE_SIZE.toLong()) {
                var total = 0
                Age.decrypt(ByteArrayInputStream(largeCiphertext), identities).use { dec ->
                    while (true) {
                        val n = dec.read(readBuf, 13, READ_BLOCK)
                        if (n < 0) break
                        total += n
                    }
                }
                Benchmark.requireTrue(total == LARGE_SIZE) { "Unexpected open size: $total" }
                Benchmark.blackhole(total)
            },
            Benchmark.Case("Small seal", SMALL_SIZE.toLong()) {
                val out = ByteArrayOutputStream(256)
                Age.encrypt(out, recipients).use { it.write(smallPlaintext) }
                Benchmark.blackhole(out.size())
            },
            Benchmark.Case("Small open", SMALL_SIZE.toLong()) {
                val out = ByteArray(SMALL_SIZE + 16)
                var total = 0
                Age.decrypt(ByteArrayInputStream(smallCiphertext), identities).use { dec ->
                    while (true) {
                        val n = dec.read(out, total, out.size - total)
                        if (n < 0) break
                        total += n
                    }
                }
                Benchmark.requireTrue(total == SMALL_SIZE) { "Unexpected small open size: $total" }
                Benchmark.blackhole(total)
            },
            Benchmark.Case("Single large write", LARGE_SIZE.toLong()) {
                val out = ByteArrayOutputStream(largeCiphertext.size)
                Age.encrypt(out, recipients).use { it.write(largePlaintext) }
                Benchmark.blackhole(out.size())
            },
            Benchmark.Case("Age encrypt bytes", LARGE_SIZE.toLong()) {
                Benchmark.blackhole(Age.encryptBytes(largePlaintext, recipients))
            },
            Benchmark.Case("Age decrypt bytes", LARGE_SIZE.toLong()) {
                Benchmark.blackhole(Age.decryptBytes(largeCiphertext, identities))
            },
            Benchmark.Case("Age encrypt armored string", LARGE_SIZE.toLong()) {
                Benchmark.blackhole(Age.encryptToArmoredString(largePlaintext, recipients))
            },
            Benchmark.Case("Age decrypt armored string", LARGE_SIZE.toLong()) {
                Benchmark.blackhole(Age.decryptArmoredString(largeArmored, identities))
            },
            Benchmark.Case("Armor encode string", LARGE_SIZE.toLong()) {
                Benchmark.blackhole(Armor.encode(largePlaintext))
            },
            Benchmark.Case("Armor decode bytes", LARGE_SIZE.toLong()) {
                Benchmark.blackhole(Armor.decode(armorBytes))
            },
        )
        Benchmark.run(args, cases)
        identity.close()
    }

    private fun verifyPayloadBehavior(
        identity: X25519Identity,
        largePlaintext: ByteArray,
        smallPlaintext: ByteArray,
    ) {
        val recipients = listOf(identity.recipient)
        val identities = listOf(identity)

        val binCt = Age.encryptBytes(largePlaintext, recipients)
        Benchmark.requireTrue(Age.decryptBytes(binCt, identities).contentEquals(largePlaintext)) {
            "Binary round-trip failed"
        }
        val armStr = Age.encryptToArmoredString(largePlaintext, recipients)
        Benchmark.requireTrue(Age.decryptArmoredString(armStr, identities).contentEquals(largePlaintext)) {
            "Armored round-trip failed"
        }

        for (boundary in intArrayOf(0, CHUNK_SIZE, CHUNK_SIZE * 2)) {
            val data = Benchmark.deterministicBytes(boundary, seed = boundary.toLong() + 7)
            val encrypted = Age.encryptBytes(data, recipients)
            Benchmark.requireTrue(Age.decryptBytes(encrypted, identities).contentEquals(data)) {
                "Exact chunk boundary round-trip failed for $boundary"
            }
        }

        // Retry after a failed write
        var failNext = false
        val flakyOut = ByteArrayOutputStream()
        val failingSink = object : OutputStream() {
            override fun write(b: Int) {
                if (failNext) throw IOException("simulated failure")
                flakyOut.write(b)
            }

            override fun write(b: ByteArray, off: Int, len: Int) {
                if (failNext) throw IOException("simulated failure")
                flakyOut.write(b, off, len)
            }
        }
        val enc = Age.encrypt(failingSink, recipients)
        val twoChunks = Benchmark.deterministicBytes(CHUNK_SIZE + 100, seed = 101L)
        failNext = true
        var threw = false
        try {
            enc.write(twoChunks)
        } catch (_: IOException) {
            threw = true
        }
        Benchmark.requireTrue(threw) { "Expected simulated IOException" }
        failNext = false
        enc.write(twoChunks, CHUNK_SIZE, twoChunks.size - CHUNK_SIZE)
        enc.close()
        Benchmark.requireTrue(Age.decryptBytes(flakyOut.toByteArray(), identities).contentEquals(twoChunks)) {
            "Retry after failed write produced incorrect ciphertext"
        }

        // Corrupt short final chunk leaves read destination untouched
        val corruptShort = Age.encryptBytes(smallPlaintext, recipients)
        corruptShort[corruptShort.size - 1] = (corruptShort[corruptShort.size - 1].toInt() xor 0x01).toByte()
        val dest = ByteArray(smallPlaintext.size) { 0x5A.toByte() }
        var authFailed = false
        Age.decrypt(ByteArrayInputStream(corruptShort), identities).use { dec ->
            try {
                dec.read(dest, 0, dest.size)
            } catch (_: PayloadDecryptionException) {
                authFailed = true
            }
        }
        Benchmark.requireTrue(authFailed) { "Corrupt short final chunk was not rejected" }
        Benchmark.requireTrue(dest.all { it == 0x5A.toByte() }) {
            "Failed authentication modified destination buffer"
        }

        // Corrupt full final chunk
        val fullChunkPlain = Benchmark.deterministicBytes(CHUNK_SIZE, seed = 333L)
        val corruptFull = Age.encryptBytes(fullChunkPlain, recipients)
        corruptFull[corruptFull.size - 1] = (corruptFull[corruptFull.size - 1].toInt() xor 0x80).toByte()
        var fullFailed = false
        try {
            Age.decryptBytes(corruptFull, identities)
        } catch (_: PayloadDecryptionException) {
            fullFailed = true
        }
        Benchmark.requireTrue(fullFailed) { "Corrupt full final chunk was not rejected" }

        // Authenticated final chunk returned before deferred trailing-data error
        val validFull = Age.encryptBytes(fullChunkPlain, recipients)
        val withTrailing = validFull + byteArrayOf(1, 2, 3, 4)
        Age.decrypt(ByteArrayInputStream(withTrailing), identities).use { dec ->
            val out = ByteArray(fullChunkPlain.size)
            var readTotal = 0
            while (readTotal < fullChunkPlain.size) {
                val n = dec.read(out, readTotal, fullChunkPlain.size - readTotal)
                if (n < 0) break
                readTotal += n
            }
            Benchmark.requireTrue(readTotal == fullChunkPlain.size && out.contentEquals(fullChunkPlain)) {
                "Authenticated final chunk was not returned before trailing-data check"
            }
            var trailingRejected = false
            try {
                dec.read()
            } catch (_: PayloadDecryptionException) {
                trailingRejected = true
            }
            Benchmark.requireTrue(trailingRejected) { "Trailing data after final chunk was not rejected" }
        }
    }
}
