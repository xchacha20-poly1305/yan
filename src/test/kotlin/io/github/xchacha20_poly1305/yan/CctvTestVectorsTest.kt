package io.github.xchacha20_poly1305.yan

import io.github.xchacha20_poly1305.yan.internal.CryptoPrimitives
import io.github.xchacha20_poly1305.yan.internal.HeaderFormat
import io.github.xchacha20_poly1305.yan.internal.StreamDecryptInputStream
import io.github.xchacha20_poly1305.yan.internal.StreamEncryptOutputStream
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import org.junit.runners.Parameterized.Parameters
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.zip.InflaterInputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

private fun loadManifest(): List<String> {
    val stream = CctvTestVectorsTest::class.java.getResourceAsStream("/cctv/MANIFEST.txt")
        ?: error("Missing /cctv/MANIFEST.txt resource")
    val text = stream.use {
        String(CryptoPrimitives.readAllCompat(it), StandardCharsets.UTF_8)
    }
    return text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
}

class CctvManifestTest {
    @Test
    fun manifestContainsAll147OfficialVectors() {
        val names = loadManifest()
        assertEquals(147, names.size)
    }
}

@RunWith(Parameterized::class)
class CctvTestVectorsTest(
    private val vectorName: String,
) {
    companion object {
        @JvmStatic
        @Parameters(name = "{0}")
        fun vectors(): List<String> = loadManifest()
    }

    private class Vector(
        val name: String,
        val expect: String,
        val payloadHash: ByteArray?,
        val fileKey: ByteArray?,
        val identities: List<Identity>,
        val armored: Boolean,
        val file: ByteArray,
    ) : Closeable {
        override fun close() {
            for (id in identities) {
                if (id is Closeable) {
                    id.close()
                }
            }
        }
    }

    private fun parseVector(name: String): Vector {
        val raw = (javaClass.getResourceAsStream("/cctv/$name")
            ?: error("Missing test vector: /cctv/$name")).use {
            CryptoPrimitives.readAllCompat(it)
        }

        var expect: String? = null
        var payloadHash: ByteArray? = null
        var fileKey: ByteArray? = null
        val identities = ArrayList<Identity>()
        var armored = false
        var compressed = false

        var position = 0
        while (position < raw.size) {
            val lineEnd = indexOfByte(raw, '\n'.code.toByte(), position)
            if (lineEnd < 0) {
                error("Invalid test vector $name: missing blank separator line")
            }
            if (lineEnd == position) {
                position = lineEnd + 1
                break
            }
            val line = String(raw, position, lineEnd - position, StandardCharsets.UTF_8)
            position = lineEnd + 1
            val sep = line.indexOf(": ")
            if (sep <= 0) {
                error("Invalid metadata line in $name: '$line'")
            }
            val key = line.substring(0, sep)
            val value = line.substring(sep + 2)
            when (key) {
                "expect" -> {
                    require(
                        value in setOf(
                            "success",
                            "HMAC failure",
                            "header failure",
                            "armor failure",
                            "payload failure",
                            "no match",
                        ),
                    ) { "Unknown expect value '$value' in $name" }
                    expect = value
                }
                "payload" -> payloadHash = value.hexToByteArray()
                "file key" -> fileKey = value.hexToByteArray()
                "identity" -> identities.add(Age.parseIdentity(value))
                "passphrase" -> identities.add(ScryptIdentity(value))
                "armored" -> {
                    require(value == "yes") { "Unknown armored value '$value' in $name" }
                    armored = true
                }
                "compressed" -> {
                    require(value == "zlib") { "Unknown compression '$value' in $name" }
                    compressed = true
                }
                "comment" -> {
                    // Informational comment.
                }
                else -> error("Unknown metadata key '$key' in $name")
            }
        }

        val bodyBytes = raw.copyOfRange(position, raw.size)
        val fileBytes = if (compressed) {
            InflaterInputStream(ByteArrayInputStream(bodyBytes)).use {
                CryptoPrimitives.readAllCompat(it)
            }
        } else {
            bodyBytes
        }

        return Vector(
            name = name,
            expect = expect ?: error("Missing expect in $name"),
            payloadHash = payloadHash,
            fileKey = fileKey,
            identities = identities,
            armored = armored,
            file = fileBytes,
        )
    }

    @Test
    fun decrypt() {
        parseVector(vectorName).use { v ->
            verifyDecryptVector(v)
        }
    }

    @Test
    fun roundTrip() {
        parseVector(vectorName).use { v ->
            verifyRoundTripVector(v)
        }
    }

    private fun verifyDecryptVector(vector: Vector) {
        val stream = try {
            Age.decrypt(ByteArrayInputStream(vector.file), vector.identities, armor = vector.armored)
        } catch (e: ArmorFormatException) {
            assertEquals("armor failure", vector.expect, "Unexpected ArmorFormatException for ${vector.name}: ${e.message}")
            return
        } catch (e: HeaderMacException) {
            assertEquals("HMAC failure", vector.expect, "Unexpected HeaderMacException for ${vector.name}: ${e.message}")
            return
        } catch (e: NoMatchingIdentityException) {
            assertEquals("no match", vector.expect, "Unexpected NoMatchingIdentityException for ${vector.name}: ${e.message}")
            return
        } catch (e: HeaderFormatException) {
            assertEquals("header failure", vector.expect, "Unexpected HeaderFormatException for ${vector.name}: ${e.message}")
            return
        }

        if (vector.expect != "success" && vector.expect != "payload failure" && vector.expect != "armor failure") {
            fail("Expected ${vector.expect} for ${vector.name}, but header decryption succeeded")
        }

        val out = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        var streamError: Throwable? = null
        stream.use { input ->
            try {
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                }
            } catch (t: Throwable) {
                streamError = t
            }
        }

        val emitted = out.toByteArray()
        val err = streamError
        if (err != null) {
            when (err) {
                is ArmorFormatException -> assertEquals(
                    "armor failure",
                    vector.expect,
                    "Unexpected ArmorFormatException in stream for ${vector.name}: ${err.message}",
                )
                is PayloadDecryptionException -> assertEquals(
                    "payload failure",
                    vector.expect,
                    "Unexpected PayloadDecryptionException for ${vector.name}: ${err.message}",
                )
                else -> fail("Unexpected exception ${err.javaClass.name} for ${vector.name}: $err")
            }
            vector.payloadHash?.let { expectedHash ->
                assertContentEquals(
                    expectedHash,
                    sha256(emitted),
                    "Partial payload SHA-256 mismatch for ${vector.name} (emitted ${emitted.size} bytes)",
                )
            }
        } else {
            assertEquals("success", vector.expect, "Expected ${vector.expect} for ${vector.name}, but decryption reached EOF cleanly")
            assertContentEquals(
                vector.payloadHash!!,
                sha256(emitted),
                "Decrypted payload SHA-256 mismatch for ${vector.name}",
            )
        }
    }

    private fun verifyRoundTripVector(vector: Vector) {
        if (vector.armored) {
            if (vector.expect == "armor failure") return
            val decoded = Armor.decode(vector.file)
            val reencoded = Armor.encode(decoded)
            val normalized = normalizeArmorExpected(vector.file)
            assertEquals(normalized, reencoded, "Armor round-trip mismatch for ${vector.name}")
            return
        }

        if (vector.expect == "header failure") return

        val parsed = HeaderFormat.parse(ByteArrayInputStream(vector.file))
        val remaining = CryptoPrimitives.readAllCompat(parsed.remaining)
        val rebuilt = ByteArrayOutputStream().apply {
            HeaderFormat.marshal(parsed.header, this)
            write(remaining)
        }.toByteArray()
        assertContentEquals(vector.file, rebuilt, "Header round-trip mismatch for ${vector.name}")

        if (vector.expect != "success") return

        val fileKey = vector.fileKey!!
        assertTrue(remaining.size >= 16, "Expected payload nonce for ${vector.name}")
        val nonce = remaining.copyOfRange(0, 16)

        val plaintext = StreamDecryptInputStream(
            src = ByteArrayInputStream(remaining),
            fileKey = fileKey,
        ).use {
            CryptoPrimitives.readAllCompat(it)
        }

        assertContentEquals(vector.payloadHash!!, sha256(plaintext), "Direct STREAM plaintext hash mismatch for ${vector.name}")

        val reencrypted = ByteArrayOutputStream()
        StreamEncryptOutputStream(
            out = reencrypted,
            fileKey = fileKey,
            payloadNonce = nonce,
        ).use {
            it.write(plaintext)
        }
        assertContentEquals(remaining, reencrypted.toByteArray(), "STREAM round-trip mismatch for ${vector.name}")
    }

    private fun normalizeArmorExpected(raw: ByteArray): String {
        val text = String(raw, StandardCharsets.US_ASCII).replace("\r\n", "\n")
        return text.trim() + "\n"
    }

    private fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    private fun indexOfByte(data: ByteArray, target: Byte, start: Int): Int {
        for (i in start until data.size) {
            if (data[i] == target) {
                return i
            }
        }
        return -1
    }

}
