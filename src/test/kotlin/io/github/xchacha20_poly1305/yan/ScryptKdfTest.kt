package io.github.xchacha20_poly1305.yan

import io.github.xchacha20_poly1305.yan.internal.ScryptKdf
import java.nio.charset.StandardCharsets
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class ScryptKdfTest {
    @Test
    fun matchesRfc7914Section12Vectors() {
        val provider = AgeProvider.defaultProvider()

        val v1 = ScryptKdf.scryptKotlin(
            password = ByteArray(0),
            salt = ByteArray(0),
            n = 16,
            r = 1,
            p = 1,
            dkLen = 64,
            provider = provider,
        )
        assertEquals(
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
            v1.toHexString(),
        )

        val v2 = ScryptKdf.scryptKotlin(
            password = "password".toByteArray(StandardCharsets.UTF_8),
            salt = "NaCl".toByteArray(StandardCharsets.UTF_8),
            n = 1024,
            r = 8,
            p = 16,
            dkLen = 64,
            provider = provider,
        )
        assertEquals(
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
            v2.toHexString(),
        )

        val v3 = ScryptKdf.scryptKotlin(
            password = "pleaseletmein".toByteArray(StandardCharsets.UTF_8),
            salt = "SodiumChloride".toByteArray(StandardCharsets.UTF_8),
            n = 16384,
            r = 8,
            p = 1,
            dkLen = 64,
            provider = provider,
        )
        assertEquals(
            "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
            v3.toHexString(),
        )
    }

    @Test
    fun conscryptNativeAndKotlinFallbackMatchBitForBit() {
        val provider = AgeProvider.defaultProvider()
        val salt = "age-encryption.org/v1/scrypt0123456789abcdef".toByteArray(StandardCharsets.UTF_8)
        for (password in listOf("", "correct horse battery staple", "密码🔑")) {
            val utf8 = password.toByteArray(StandardCharsets.UTF_8)
            for (workFactor in listOf(10, 14)) {
                val nativeOut = ScryptKdf.derive(utf8, password.toCharArray(), salt, workFactor, provider)
                val kotlinOut = ScryptKdf.scryptKotlin(utf8, salt, 1 shl workFactor, 8, 1, 32, provider)
                assertContentEquals(nativeOut, kotlinOut, "Mismatch for password='$password', workFactor=$workFactor")
            }
        }
    }

    @Test
    fun workFactor19FallbackRoundTripWorks() {
        val plaintext = "post-limit scrypt fallback test".toByteArray(StandardCharsets.UTF_8)
        ScryptRecipient("fallback-passphrase", workFactor = 19).use { recipient ->
            val encrypted = Age.encryptBytes(plaintext, listOf(recipient))
            ScryptIdentity("fallback-passphrase", maxWorkFactor = 22).use { identity ->
                val decrypted = Age.decryptBytes(encrypted, listOf(identity))
                assertContentEquals(plaintext, decrypted)
            }
        }
    }

}
