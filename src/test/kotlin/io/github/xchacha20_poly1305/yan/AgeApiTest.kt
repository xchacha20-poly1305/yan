package io.github.xchacha20_poly1305.yan

import io.github.xchacha20_poly1305.yan.internal.Base64Strict
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.nio.charset.StandardCharsets
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AgeApiTest {
    @Test
    fun x25519AndHybridKeyGenerationAndParseMatchRecipients() {
        X25519Identity.generate().use { xId ->
            val encoded = xId.encode()
            assertTrue(encoded.startsWith("AGE-SECRET-KEY-1"))
            X25519Identity.parse(encoded).use { parsed ->
                assertEquals(xId.recipient, parsed.recipient)
                assertEquals(xId.recipient.encode(), X25519Recipient.parse(xId.recipient.encode()).encode())
            }
        }

        HybridIdentity.generate().use { hId ->
            val encoded = hId.encode()
            assertTrue(encoded.startsWith("AGE-SECRET-KEY-PQ-1"))
            HybridIdentity.parse(encoded).use { parsed ->
                assertEquals(hId.recipient, parsed.recipient)
                assertEquals(hId.recipient.encode(), HybridRecipient.parse(hId.recipient.encode()).encode())
            }
        }
    }

    @Test
    fun streamingChunkBoundariesBinaryAndArmored() {
        val sizes = listOf(0, 1, 65535, 65536, 65537, 131072, 131073)
        HybridIdentity.generate().use { hybridId ->
            X25519Identity.generate().use { xId ->
                for (size in sizes) {
                    val plaintext = ByteArray(size) { ((it * 31) xor (it ushr 8)).toByte() }
                    for (armored in listOf(false, true)) {
                        val encrypted = Age.encryptBytes(
                            plaintext = plaintext,
                            recipients = listOf(hybridId.recipient, xId.recipient),
                            armor = armored,
                        )
                        val decrypted1 = Age.decryptBytes(encrypted, listOf(hybridId), armor = armored)
                        assertContentEquals(plaintext, decrypted1, "Hybrid decrypt failed for size=$size armored=$armored")

                        val decrypted2 = Age.decryptBytes(encrypted, listOf(xId), armor = armored)
                        assertContentEquals(plaintext, decrypted2, "X25519 decrypt failed for size=$size armored=$armored")
                    }
                }
            }
        }
    }

    @Test
    fun scryptMixingIsRejectedAndWorkFactorLimitRespected() {
        X25519Identity.generate().use { xId ->
            ScryptRecipient("secret", workFactor = 10).use { sRec ->
                assertFailsWith<IllegalArgumentException> {
                    Age.encrypt(ByteArrayOutputStream(), listOf(sRec, xId.recipient))
                }
                val encrypted = Age.encryptBytes("hi".toByteArray(), listOf(sRec))
                ScryptIdentity("secret", maxWorkFactor = 9).use { tooLow ->
                    assertFailsWith<HeaderFormatException> {
                        Age.decryptBytes(encrypted, listOf(tooLow))
                    }
                }
            }
        }
    }

    @Test
    fun keyFileParsingWithCommentsAndCleanupOnError() {
        X25519Identity.generate().use { xId ->
            HybridIdentity.generate().use { hId ->
                val recipientsText = """
                    # generated recipients
                    
                    ${xId.recipient.encode()}
                    ${hId.recipient.encode()}
                """.trimIndent()
                val recs = Age.parseRecipients(recipientsText)
                assertEquals(2, recs.size)

                val identitiesText = "# comment\r\n\r\n${xId.encode()}\r\n${hId.encode()}\r\n"
                val identities = Age.parseIdentities(identitiesText)
                try {
                    assertEquals(2, identities.size)
                    val ct = Age.encryptToArmoredString("file keys".toByteArray(), recs)
                    val pt = Age.decryptArmoredString(ct, identities)
                    assertEquals("file keys", String(pt, StandardCharsets.UTF_8))
                } finally {
                    identities.forEach {
                        (it as Closeable).close()
                    }
                }

                // Invalid second line must reject whole key file
                assertFailsWith<KeyFormatException> {
                    Age.parseIdentities("${xId.encode()}\nAGE-SECRET-KEY-INVALID\n")
                }
            }
        }
    }

    @Test
    fun closeableZeroingRedactionAndCustomProvider() {
        val xId = X25519Identity.generate()
        assertFalse(xId.toString().contains("AGE-SECRET-KEY-"))
        xId.close()
        assertFailsWith<IllegalStateException> { xId.encode() }
        assertFailsWith<IllegalStateException> { xId.unwrap(emptyList()) }

        val hId = HybridIdentity.generate()
        assertFalse(hId.toString().contains("AGE-SECRET-KEY-PQ-"))
        hId.close()
        assertFailsWith<IllegalStateException> { hId.encode() }
        assertFailsWith<IllegalStateException> { hId.unwrap(emptyList()) }

        val sRec = ScryptRecipient("top-secret-pw", workFactor = 10)
        assertFalse(sRec.toString().contains("top-secret-pw"))
        sRec.close()
        assertFailsWith<IllegalStateException> { sRec.wrap(ByteArray(16)) }

        val sId = ScryptIdentity("top-secret-pw")
        assertFalse(sId.toString().contains("top-secret-pw"))
        sId.close()
        assertFailsWith<IllegalStateException> { sId.unwrap(emptyList()) }
    }

    @Test
    fun customRecipientAndIdentityWithOpenStanzaInterface() {
        val customRecipient = object : Recipient {
            override fun wrap(fileKey: ByteArray): List<Stanza> {
                return listOf(Stanza("example.com/xor", listOf("v1"), fileKey.map { (it.toInt() xor 0x5A).toByte() }.toByteArray()))
            }
        }
        val customIdentity = object : Identity {
            override fun unwrap(stanzas: List<Stanza>): ByteArray? {
                val stanza = stanzas.firstOrNull { it.type == "example.com/xor" && it.args == listOf("v1") } ?: return null
                return stanza.body.map { (it.toInt() xor 0x5A).toByte() }.toByteArray()
            }
        }

        val encrypted = Age.encryptBytes("custom stanza".toByteArray(), listOf(customRecipient))
        val decrypted = Age.decryptBytes(encrypted, listOf(customIdentity))
        assertEquals("custom stanza", String(decrypted, StandardCharsets.UTF_8))
    }

    @Test
    fun binaryAndArmoredExplicitSeparation() {
        X25519Identity.generate().use { id ->
            val armored = Age.encryptToArmoredString("armor test".toByteArray(), listOf(id.recipient))
            // Passing armored text to binary decrypt must fail as HeaderFormatException
            assertFailsWith<HeaderFormatException> {
                Age.decrypt(ByteArrayInputStream(armored.toByteArray()), listOf(id))
            }
            // Layered Armor.unwrap + Age.decrypt works equivalently
            val pt = Armor.unwrap(ByteArrayInputStream(armored.toByteArray())).use { unwrapped ->
                Age.decrypt(unwrapped, listOf(id)).use { it.readBytes() }
            }
            assertEquals("armor test", String(pt, StandardCharsets.UTF_8))
            assertTrue(Base64Strict.encodeRaw("hi".toByteArray()).isNotEmpty())

            // Empty identities list: malformed header still fails with HeaderFormatException,
            // while a valid header rejects empty identities with IllegalArgumentException.
            assertFailsWith<HeaderFormatException> {
                Age.decrypt(ByteArrayInputStream(ByteArray(0)), emptyList())
            }
            val validBytes = Age.encryptBytes("ok".toByteArray(), listOf(id.recipient))
            assertFailsWith<IllegalArgumentException> {
                Age.decrypt(ByteArrayInputStream(validBytes), emptyList())
            }
        }
    }
}
