package io.github.xchacha20_poly1305.yan

import io.github.xchacha20_poly1305.yan.internal.Bech32
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Bech32Test {
    @Test
    fun roundTripsStandardAndLongPqKeys() {
        val x25519Pub = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
        val decodedX = Bech32.decode(x25519Pub)
        assertEquals("age", decodedX.hrp)
        assertEquals(32, decodedX.data.size)
        assertFalse(decodedX.isUppercase)
        assertEquals(x25519Pub, Bech32.encode("age", decodedX.data))

        val x25519Sec = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"
        val decodedSec = Bech32.decode(x25519Sec)
        assertEquals("AGE-SECRET-KEY-", decodedSec.hrp)
        assertEquals(32, decodedSec.data.size)
        assertTrue(decodedSec.isUppercase)
        assertEquals(x25519Sec, Bech32.encode("AGE-SECRET-KEY-", decodedSec.data, uppercase = true))

        // Long 1216-byte payload (> 90 chars BIP173 limit)
        val payload = ByteArray(1216) { it.toByte() }
        val encodedPq = Bech32.encode("age1pq", payload)
        assertTrue(encodedPq.length > 1900)
        val decodedPq = Bech32.decode(encodedPq)
        assertEquals("age1pq", decodedPq.hrp)
        assertContentEquals(payload, decodedPq.data)
    }

    @Test
    fun rejectsMixedCaseBadChecksumAndBadPadding() {
        val valid = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
        // Mixed case
        assertFailsWith<IllegalArgumentException> {
            Bech32.decode("Age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj")
        }
        // Corrupted checksum char
        val corrupted = valid.dropLast(1) + if (valid.last() == 'j') 'k' else 'j'
        assertFailsWith<IllegalArgumentException> {
            Bech32.decode(corrupted)
        }
        // Empty HRP or missing separator
        assertFailsWith<IllegalArgumentException> { Bech32.decode("1qpzry9x8") }
        assertFailsWith<IllegalArgumentException> { Bech32.decode("ageqpzry9x8") }
        // Too short checksum
        assertFailsWith<IllegalArgumentException> { Bech32.decode("age1qpzry") }
    }
}
