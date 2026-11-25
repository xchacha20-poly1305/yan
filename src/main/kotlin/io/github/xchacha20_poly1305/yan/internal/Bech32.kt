package io.github.xchacha20_poly1305.yan.internal

import java.io.ByteArrayOutputStream

internal object Bech32 {
    private const val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private val GENERATOR = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)

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
        val hrpLower = StringBuilder(hrp.length)
        for (i in hrp.indices) {
            val char = hrp[i]
            val code = char.code
            if (code !in 33..126) {
                throw IllegalArgumentException("Invalid HRP character")
            }
            hrpLower.append(toLowerAscii(char))
        }
        val lowerHrpStr = hrpLower.toString()
        val data5 = convertBits(data, 8, 5, pad = true)
        val checksum = createChecksum(lowerHrpStr, data5)

        val builder = StringBuilder(lowerHrpStr.length + 1 + data5.size + checksum.size)
        if (uppercase) {
            for (i in lowerHrpStr.indices) {
                builder.append(toUpperAscii(lowerHrpStr[i]))
            }
        } else {
            builder.append(lowerHrpStr)
        }
        builder.append('1')
        for (data in data5) {
            val char = CHARSET[data]
            builder.append(if (uppercase) toUpperAscii(char) else char)
        }
        for (sum in checksum) {
            val char = CHARSET[sum]
            builder.append(if (uppercase) toUpperAscii(char) else char)
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
        if (sep < 1 || sep + 7 > bech32.length) {
            throw IllegalArgumentException("Invalid Bech32 separator position")
        }

        val hrpRaw = bech32.substring(0, sep)
        val hrpLower = StringBuilder(sep)
        for (i in 0 until sep) {
            hrpLower.append(toLowerAscii(bech32[i]))
        }

        val valuesLen = bech32.length - sep - 1
        val values = IntArray(valuesLen)
        for (i in 0 until valuesLen) {
            val char = toLowerAscii(bech32[sep + 1 + i])
            val code = char.code
            val value = if (code < 128) {
                CHARSET_REV[code]
            } else {
                -1
            }
            if (value < 0) {
                throw IllegalArgumentException("Invalid Bech32 data character")
            }
            values[i] = value
        }

        if (!verifyChecksum(hrpLower.toString(), values)) {
            throw IllegalArgumentException("Invalid Bech32 checksum")
        }

        val payload5 = IntArray(valuesLen - 6)
        System.arraycopy(values, 0, payload5, 0, payload5.size)
        val bytes = convert5To8(payload5)
        return Decoded(hrp = hrpRaw, data = bytes, isUppercase = hasUpper)
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

    private fun polymod(values: IntArray): Int {
        var chk = 1
        for (v in values) {
            val top = chk ushr 25
            chk = ((chk and 0x1ffffff) shl 5) xor v
            for (i in 0 until 5) {
                if (((top ushr i) and 1) != 0) {
                    chk = chk xor GENERATOR[i]
                }
            }
        }
        return chk
    }

    private fun hrpExpand(hrp: String): IntArray {
        val len = hrp.length
        val expanded = IntArray(len * 2 + 1)
        for (i in 0 until len) {
            val char = hrp[i].code
            expanded[i] = char ushr 5
            expanded[i + len + 1] = char and 0x1f
        }
        expanded[len] = 0
        return expanded
    }

    private fun verifyChecksum(hrp: String, values: IntArray): Boolean {
        val expanded = hrpExpand(hrp)
        val combined = IntArray(expanded.size + values.size)
        System.arraycopy(expanded, 0, combined, 0, expanded.size)
        System.arraycopy(values, 0, combined, expanded.size, values.size)
        return polymod(combined) == 1
    }

    private fun createChecksum(hrp: String, data: IntArray): IntArray {
        val expanded = hrpExpand(hrp)
        val combined = IntArray(expanded.size + data.size + 6)
        System.arraycopy(expanded, 0, combined, 0, expanded.size)
        System.arraycopy(data, 0, combined, expanded.size, data.size)
        val mod = polymod(combined) xor 1
        val checksum = IntArray(6)
        for (i in 0 until 6) {
            checksum[i] = (mod ushr (5 * (5 - i))) and 0x1f
        }
        return checksum
    }

    private fun convertBits(data: ByteArray, fromBits: Int, toBits: Int, pad: Boolean): IntArray {
        var acc = 0
        var bits = 0
        val out = IntArray((data.size * fromBits + toBits - 1) / toBits)
        var outIdx = 0
        val maxv = (1 shl toBits) - 1
        val maxAcc = (1 shl (fromBits + toBits - 1)) - 1
        for (b in data) {
            val value = b.toInt() and 0xFF
            acc = ((acc shl fromBits) or value) and maxAcc
            bits += fromBits
            while (bits >= toBits) {
                bits -= toBits
                out[outIdx++] = (acc ushr bits) and maxv
            }
        }
        if (pad && bits > 0) {
            out[outIdx++] = (acc shl (toBits - bits)) and maxv
        }
        return if (outIdx == out.size) {
            out
        } else {
            out.copyOf(outIdx)
        }
    }

    private fun convert5To8(data: IntArray): ByteArray {
        var acc = 0
        var bits = 0
        val out = ByteArrayOutputStream((data.size * 5) / 8 + 1)
        for (value in data) {
            if (value !in 0..<32) {
                throw IllegalArgumentException("Invalid 5-bit Bech32 value")
            }
            acc = (acc shl 5) or value
            bits += 5
            while (bits >= 8) {
                bits -= 8
                out.write((acc ushr bits) and 0xFF)
            }
        }
        if (bits >= 5 || (acc and ((1 shl bits) - 1)) != 0) {
            throw IllegalArgumentException("Invalid Bech32 padding bits")
        }
        return out.toByteArray()
    }
}
