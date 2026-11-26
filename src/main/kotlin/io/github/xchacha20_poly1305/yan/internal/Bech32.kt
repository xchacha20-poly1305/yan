package io.github.xchacha20_poly1305.yan.internal

internal object Bech32 {
    private const val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private const val CHARSET_UPPER = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"
    private const val CHECKSUM_SIZE = 6
    private val POLYMOD_TERMS = run {
        val coefficients = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
        IntArray(32) { top ->
            var result = 0
            for (i in coefficients.indices) {
                if ((top and (1 shl i)) != 0) {
                    result = result xor coefficients[i]
                }
            }
            result
        }
    }

    private val CHARSET_REV = IntArray(128) { -1 }.apply {
        for (i in CHARSET.indices) {
            this[CHARSET[i].code] = i
        }
    }

    data class Decoded(
        val hrp: String,
        val data: ByteArray,
        val isUppercase: Boolean,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Decoded) return false
            return hrp == other.hrp
                    && data.contentEquals(other.data)
                    && isUppercase == other.isUppercase
        }

        override fun hashCode(): Int {
            var result = hrp.hashCode()
            result = 31 * result + data.contentHashCode()
            result = 31 * result + isUppercase.hashCode()
            return result
        }
    }

    fun encode(hrp: String, data: ByteArray, uppercase: Boolean = false): String {
        if (hrp.isEmpty()) {
            throw IllegalArgumentException("Bech32 HRP must not be empty")
        }
        val payloadSize = (data.size * 8L + 4) / 5
        val builder = StringBuilder((hrp.length + 1L + payloadSize + CHECKSUM_SIZE).toInt())
        for (char in hrp) {
            if (char.code !in 33..126) {
                throw IllegalArgumentException("Invalid HRP character")
            }
            builder.append(if (uppercase) toUpperAscii(char) else toLowerAscii(char))
        }
        builder.append('1')
        val charset = if (uppercase) {
            CHARSET_UPPER
        } else {
            CHARSET
        }
        var checksum = hrpPolymod(hrp, hrp.length)
        var acc = 0
        var bits = 0
        for (byte in data) {
            acc = (acc shl 8) or (byte.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                val value = (acc ushr bits) and 0x1f
                builder.append(charset[value])
                checksum = polymodStep(checksum, value)
            }
        }
        if (bits > 0) {
            val value = (acc shl (5 - bits)) and 0x1f
            builder.append(charset[value])
            checksum = polymodStep(checksum, value)
        }
        repeat(CHECKSUM_SIZE) {
            checksum = polymodStep(checksum, 0)
        }
        checksum = checksum xor 1
        for (i in CHECKSUM_SIZE - 1 downTo 0) {
            builder.append(charset[(checksum ushr (5 * i)) and 0x1f])
        }
        return builder.toString()
    }

    fun decode(bech32: String): Decoded {
        if (bech32.isEmpty()) {
            throw IllegalArgumentException("Empty Bech32 string")
        }
        var hasLower = false
        var hasUpper = false
        for (i in bech32.indices) {
            val code = bech32[i].code
            if (code !in 33..126) {
                throw IllegalArgumentException("Invalid Bech32 character")
            }
            if (code in 'a'.code..'z'.code) {
                hasLower = true
            } else if (code in 'A'.code..'Z'.code) {
                hasUpper = true
            }
        }
        if (hasLower && hasUpper) {
            throw IllegalArgumentException("Mixed case in Bech32 string")
        }

        val sep = bech32.lastIndexOf('1')
        if (sep < 1 || bech32.length - sep - 1 < CHECKSUM_SIZE) {
            throw IllegalArgumentException("Invalid Bech32 separator position")
        }

        val payloadStart = sep + 1
        val payloadEnd = bech32.length - CHECKSUM_SIZE
        val bytes = ByteArray(((payloadEnd - payloadStart) * 5L / 8).toInt())
        var checksum = hrpPolymod(bech32, sep)
        var acc = 0
        var bits = 0
        var byteIndex = 0
        try {
            for (i in payloadStart until bech32.length) {
                val value = CHARSET_REV[toLowerAscii(bech32[i]).code]
                if (value < 0) {
                    throw IllegalArgumentException("Invalid Bech32 data character")
                }
                checksum = polymodStep(checksum, value)
                if (i < payloadEnd) {
                    acc = (acc shl 5) or value
                    bits += 5
                    if (bits >= 8) {
                        bits -= 8
                        bytes[byteIndex++] = (acc ushr bits).toByte()
                    }
                }
            }

            if (checksum != 1) {
                throw IllegalArgumentException("Invalid Bech32 checksum")
            }
            if (bits >= 5 || (acc and ((1 shl bits) - 1)) != 0) {
                throw IllegalArgumentException("Invalid Bech32 padding bits")
            }
            return Decoded(hrp = bech32.substring(0, sep), data = bytes, isUppercase = hasUpper)
        } catch (e: IllegalArgumentException) {
            bytes.fill(0)
            throw e
        }
    }

    private fun toLowerAscii(char: Char): Char {
        return if (char in 'A'..'Z') {
            (char.code + 32).toChar()
        } else {
            char
        }
    }

    private fun toUpperAscii(char: Char): Char {
        return if (char in 'a'..'z') {
            (char.code - 32).toChar()
        } else {
            char
        }
    }

    private fun hrpPolymod(input: String, length: Int): Int {
        var checksum = 1
        for (i in 0 until length) {
            checksum = polymodStep(checksum, toLowerAscii(input[i]).code ushr 5)
        }
        checksum = polymodStep(checksum, 0)
        for (i in 0 until length) {
            checksum = polymodStep(checksum, toLowerAscii(input[i]).code and 0x1f)
        }
        return checksum
    }

    private fun polymodStep(checksum: Int, value: Int): Int {
        return ((checksum and 0x1ffffff) shl 5) xor value xor POLYMOD_TERMS[checksum ushr 25]
    }
}
