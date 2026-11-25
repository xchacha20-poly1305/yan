package io.github.xchacha20_poly1305.yan.androidtest

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xchacha20_poly1305.yan.Age
import io.github.xchacha20_poly1305.yan.AgeProvider
import io.github.xchacha20_poly1305.yan.Armor
import io.github.xchacha20_poly1305.yan.ArmorFormatException
import io.github.xchacha20_poly1305.yan.HeaderFormatException
import io.github.xchacha20_poly1305.yan.HeaderMacException
import io.github.xchacha20_poly1305.yan.HybridIdentity
import io.github.xchacha20_poly1305.yan.HybridRecipient
import io.github.xchacha20_poly1305.yan.Identity
import io.github.xchacha20_poly1305.yan.NoMatchingIdentityException
import io.github.xchacha20_poly1305.yan.PayloadDecryptionException
import io.github.xchacha20_poly1305.yan.Recipient
import io.github.xchacha20_poly1305.yan.ScryptIdentity
import io.github.xchacha20_poly1305.yan.ScryptRecipient
import io.github.xchacha20_poly1305.yan.Stanza
import io.github.xchacha20_poly1305.yan.X25519Identity
import io.github.xchacha20_poly1305.yan.X25519Recipient
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.zip.InflaterInputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail

@RunWith(AndroidJUnit4::class)
class AndroidAgeInstrumentedTest {
    private class Vector(
        val name: String,
        val expect: String,
        val payloadHash: ByteArray?,
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

    private fun assets() = InstrumentationRegistry.getInstrumentation().context.assets

    private fun loadManifest(): List<String> {
        val text = assets().open("MANIFEST.txt").use {
            String(readAllCompat(it), StandardCharsets.UTF_8)
        }
        return text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
    }

    private fun parseVector(name: String): Vector {
        val raw = assets().open(name).use { readAllCompat(it) }
        var expect: String? = null
        var payloadHash: ByteArray? = null
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
                "expect" -> expect = value
                "payload" -> payloadHash = decodeHex(value)
                "file key" -> {
                    // Ignored during black-box decrypt verification.
                }
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
            InflaterInputStream(ByteArrayInputStream(bodyBytes)).use { readAllCompat(it) }
        } else {
            bodyBytes
        }

        return Vector(
            name = name,
            expect = expect ?: error("Missing expect in $name"),
            payloadHash = payloadHash,
            identities = identities,
            armored = armored,
            file = fileBytes,
        )
    }

    @Test
    fun all147CctvDecryptVectorsPass() {
        val names = loadManifest()
        assertEquals(147, names.size)
        for (name in names) {
            parseVector(name).use { v ->
                verifyDecryptVector(v)
            }
        }
    }

    @Test
    fun allValidArmoredCctvVectorsRoundTrip() {
        val names = loadManifest()
        assertEquals(147, names.size)
        for (name in names) {
            parseVector(name).use { v ->
                if (v.armored && v.expect != "armor failure") {
                    val decoded = Armor.decode(v.file)
                    val reencoded = Armor.encode(decoded)
                    val normalized = String(v.file, StandardCharsets.US_ASCII)
                        .replace("\r\n", "\n")
                        .trim() + "\n"
                    assertEquals(normalized, reencoded, "Armor round-trip mismatch for $name")
                }
            }
        }
    }

    @Test
    fun x25519HybridScryptAndStreamingRoundTripOnAndroid() {
        X25519Identity.generate().use { xId ->
            X25519Identity.parse(xId.encode()).use { parsedX ->
                assertEquals(xId.recipient, parsedX.recipient)
                assertEquals(
                    xId.recipient.encode(),
                    X25519Recipient.parse(xId.recipient.encode()).encode(),
                )
            }

            HybridIdentity.generate().use { hId ->
                HybridIdentity.parse(hId.encode()).use { parsedH ->
                    assertEquals(hId.recipient, parsedH.recipient)
                    assertEquals(
                        hId.recipient.encode(),
                        HybridRecipient.parse(hId.recipient.encode()).encode(),
                    )
                }

                val sizes = listOf(0, 1, 65535, 65536, 65537, 131072, 131073)
                for (size in sizes) {
                    val plaintext = ByteArray(size) { ((it * 31) xor (it ushr 8)).toByte() }
                    for (armored in listOf(false, true)) {
                        val encrypted = Age.encryptBytes(
                            plaintext = plaintext,
                            recipients = listOf(hId.recipient, xId.recipient),
                            armor = armored,
                        )
                        assertContentEquals(
                            plaintext,
                            Age.decryptBytes(encrypted, listOf(hId), armor = armored),
                        )
                        assertContentEquals(
                            plaintext,
                            Age.decryptBytes(encrypted, listOf(xId), armor = armored),
                        )
                    }
                }

                val keyFile = "# comment\n${xId.encode()}\n${hId.encode()}\n"
                val parsedIds = Age.parseIdentities(keyFile)
                try {
                    val parsedRecs = Age.parseRecipients("${xId.recipient.encode()}\n${hId.recipient.encode()}\n")
                    val ct = Age.encryptToArmoredString("android keyfile".toByteArray(), parsedRecs)
                    val pt = Age.decryptArmoredString(ct, parsedIds)
                    assertEquals("android keyfile", String(pt, StandardCharsets.UTF_8))
                } finally {
                    parsedIds.forEach { (it as Closeable).close() }
                }
            }
        }

        ScryptRecipient("android-passphrase", workFactor = 10).use { rec ->
            val ct = Age.encryptBytes("scrypt on android".toByteArray(), listOf(rec), armor = true)
            ScryptIdentity("android-passphrase", maxWorkFactor = 12).use { id ->
                assertEquals(
                    "scrypt on android",
                    String(Age.decryptBytes(ct, listOf(id), armor = true), StandardCharsets.UTF_8),
                )
            }
            ScryptIdentity("android-passphrase", maxWorkFactor = 9).use { tooLow ->
                assertFailsWith<HeaderFormatException>("Expected HeaderFormatException for workFactor exceeding maxWorkFactor") {
                    Age.decryptBytes(ct, listOf(tooLow), armor = true)
                }
            }
        }

        // Custom Stanza extension & Closeable redaction check.
        val customRecipient = object : Recipient {
            override fun wrap(fileKey: ByteArray): List<Stanza> =
                listOf(Stanza("example.com/xor", listOf("v1"), fileKey.map { (it.toInt() xor 0x5A).toByte() }.toByteArray()))
        }
        val customIdentity = object : Identity {
            override fun unwrap(stanzas: List<Stanza>): ByteArray? {
                val s = stanzas.firstOrNull { it.type == "example.com/xor" } ?: return null
                return s.body.map { (it.toInt() xor 0x5A).toByte() }.toByteArray()
            }
        }
        val customCt = Age.encryptBytes("custom".toByteArray(), listOf(customRecipient))
        assertEquals("custom", String(Age.decryptBytes(customCt, listOf(customIdentity)), StandardCharsets.UTF_8))

        val closedId = HybridIdentity.generate()
        assertFalse(closedId.toString().contains("AGE-SECRET-KEY-PQ-"))
        closedId.close()
        assertFailsWith<IllegalStateException>("Expected IllegalStateException after close()") {
            closedId.encode()
        }
    }

    private fun verifyDecryptVector(v: Vector) {
        val stream = try {
            Age.decrypt(ByteArrayInputStream(v.file), v.identities, armor = v.armored)
        } catch (e: ArmorFormatException) {
            assertEquals("armor failure", v.expect, "Unexpected ArmorFormatException for ${v.name}: ${e.message}")
            return
        } catch (e: HeaderMacException) {
            assertEquals("HMAC failure", v.expect, "Unexpected HeaderMacException for ${v.name}: ${e.message}")
            return
        } catch (e: NoMatchingIdentityException) {
            assertEquals("no match", v.expect, "Unexpected NoMatchingIdentityException for ${v.name}: ${e.message}")
            return
        } catch (e: HeaderFormatException) {
            assertEquals("header failure", v.expect, "Unexpected HeaderFormatException for ${v.name}: ${e.message}")
            return
        }

        assertTrue(
            v.expect == "success" || v.expect == "payload failure" || v.expect == "armor failure",
            "Expected ${v.expect} for ${v.name}, but header decryption succeeded",
        )

        val digest = MessageDigest.getInstance("SHA-256", AgeProvider.defaultProvider())
        val buf = ByteArray(8192)
        var streamError: Throwable? = null
        stream.use { input ->
            try {
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    digest.update(buf, 0, n)
                }
            } catch (t: Throwable) {
                streamError = t
            }
        }

        val actualHash = digest.digest()
        val err = streamError
        if (err != null) {
            when (err) {
                is ArmorFormatException -> assertEquals(
                    "armor failure",
                    v.expect,
                    "Unexpected ArmorFormatException in stream for ${v.name}: ${err.message}",
                )
                is PayloadDecryptionException -> assertEquals(
                    "payload failure",
                    v.expect,
                    "Unexpected PayloadDecryptionException for ${v.name}: ${err.message}",
                )
                else -> fail("Unexpected exception ${err.javaClass.name} for ${v.name}: $err")
            }
            v.payloadHash?.let { expectedHash ->
                assertContentEquals(expectedHash, actualHash, "Partial payload SHA-256 mismatch for ${v.name}")
            }
        } else {
            assertEquals("success", v.expect, "Expected ${v.expect} for ${v.name}, but reached EOF cleanly")
            assertContentEquals(v.payloadHash!!, actualHash, "Payload SHA-256 mismatch for ${v.name}")
        }
    }

    private fun readAllCompat(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private fun indexOfByte(data: ByteArray, target: Byte, start: Int): Int {
        for (i in start until data.size) {
            if (data[i] == target) return i
        }
        return -1
    }

    private fun decodeHex(hex: String): ByteArray {
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            val hi = hex[i * 2].digitToInt(16)
            val lo = hex[i * 2 + 1].digitToInt(16)
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }
}
