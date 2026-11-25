package io.github.xchacha20_poly1305.yan

import org.bouncycastle.crypto.generators.SCrypt
import kotlin.test.Test
import kotlin.test.assertEquals

class ScryptKdfTest {
    @Test
    fun matchesRfc7914Section12Vectors() {
        val v1 = SCrypt.generate(
            ByteArray(0),
            ByteArray(0),
            16,
            1,
            1,
            64,
        )
        assertEquals(
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
            v1.toHexString(),
        )

        val v2 = SCrypt.generate(
            "password".encodeToByteArray(),
            "NaCl".encodeToByteArray(),
            1024,
            8,
            16,
            64,
        )
        assertEquals(
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
            v2.toHexString(),
        )

        val v3 = SCrypt.generate(
            "pleaseletmein".encodeToByteArray(),
            "SodiumChloride".encodeToByteArray(),
            16384,
            8,
            1,
            64,
        )
        assertEquals(
            "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
            v3.toHexString(),
        )
    }
}
