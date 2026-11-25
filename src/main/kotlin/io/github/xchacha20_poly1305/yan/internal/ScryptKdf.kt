package io.github.xchacha20_poly1305.yan.internal

import org.conscrypt.ScryptKeySpec
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.security.Provider
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory

internal object ScryptKdf {
    // Conscrypt JNI hardcodes memory_limit = 1u << 29 (512 MiB); for r=8, p=1,
    // workFactor <= 18 (~256 MiB) runs natively while >= 19 exceeds BoringSSL's cap.
    const val CONSCRYPT_MAX_WORK_FACTOR: Int = 18

    private const val CHUNK_SHIFT = 10 // 1024 blocks per chunk
    private const val CHUNK_BLOCKS = 1 shl CHUNK_SHIFT
    private const val CHUNK_MASK = CHUNK_BLOCKS - 1

    fun derive(
        passphraseUtf8: ByteArray,
        passphraseChars: CharArray?,
        salt: ByteArray,
        workFactor: Int,
        provider: Provider,
    ): ByteArray {
        require(workFactor in 1..30) { "Unsupported scrypt work factor: $workFactor" }
        val cost = 1 shl workFactor
        if (workFactor <= CONSCRYPT_MAX_WORK_FACTOR) {
            val chars = passphraseChars?.clone() ?: decodeUtf8Chars(passphraseUtf8)
            try {
                val spec = ScryptKeySpec(chars, salt, cost, 8, 1, 256)
                val factory = SecretKeyFactory.getInstance("SCRYPT", provider)
                return factory.generateSecret(spec).encoded
            } finally {
                CryptoPrimitives.zero(chars)
            }
        }
        return scryptKotlin(
            password = passphraseUtf8,
            salt = salt,
            n = cost,
            r = 8,
            p = 1,
            dkLen = 32,
            provider = provider,
        )
    }

    internal fun scryptKotlin(
        password: ByteArray,
        salt: ByteArray,
        n: Int,
        r: Int,
        p: Int,
        dkLen: Int,
        provider: Provider,
    ): ByteArray {
        require(n >= 2 && (n and (n - 1)) == 0) { "N must be a power of 2 >= 2" }
        require(r > 0 && p > 0 && dkLen > 0) { "Invalid scrypt parameters" }
        val blockBytesLong = 128L * r.toLong()
        require(blockBytesLong <= Int.MAX_VALUE / p) { "scrypt parameter overflow" }
        val blockBytes = blockBytesLong.toInt()
        val blockWords = 32 * r
        val totalBBytes = blockBytes * p

        val bBytes = pbkdf2HmacSha256Single(password, salt, totalBBytes, provider)
        val bWords = IntArray(blockWords * p)
        val xy = IntArray(blockWords * 2)
        val salsaBuf = IntArray(16)
        val numChunks = (n + CHUNK_BLOCKS - 1) ushr CHUNK_SHIFT
        val chunkedV = Array(numChunks) { chunkIdx ->
            val remaining = n - (chunkIdx shl CHUNK_SHIFT)
            val blocksInChunk = minOf(CHUNK_BLOCKS, remaining)
            IntArray(blocksInChunk * blockWords)
        }

        try {
            bytesToLittleEndianInts(bBytes, bWords)
            for (i in 0 until p) {
                val bOffset = i * blockWords
                roMix(bWords, bOffset, r, n, chunkedV, xy, salsaBuf)
            }
            littleEndianIntsToBytes(bWords, bBytes)
            return pbkdf2HmacSha256Single(password, bBytes, dkLen, provider)
        } finally {
            CryptoPrimitives.zero(bBytes)
            bWords.fill(0)
            xy.fill(0)
            salsaBuf.fill(0)
            for (chunk in chunkedV) {
                chunk.fill(0)
            }
        }
    }

    private fun roMix(
        b: IntArray,
        bOffset: Int,
        r: Int,
        n: Int,
        chunkedV: Array<IntArray>,
        xy: IntArray,
        salsaBuf: IntArray,
    ) {
        val blockWords = 32 * r
        System.arraycopy(b, bOffset, xy, 0, blockWords)

        for (i in 0 until n) {
            val chunk = chunkedV[i ushr CHUNK_SHIFT]
            val dstOff = (i and CHUNK_MASK) * blockWords
            System.arraycopy(xy, 0, chunk, dstOff, blockWords)
            blockMix(xy, 0, xy, blockWords, r, salsaBuf)
            System.arraycopy(xy, blockWords, xy, 0, blockWords)
        }

        val lastBlockWordOffset = (2 * r - 1) * 16
        val nMask = n - 1
        repeat(n) {
            val j = xy[lastBlockWordOffset] and nMask
            val chunk = chunkedV[j ushr CHUNK_SHIFT]
            val vOff = (j and CHUNK_MASK) * blockWords
            for (k in 0 until blockWords) {
                xy[k] = xy[k] xor chunk[vOff + k]
            }
            blockMix(xy, 0, xy, blockWords, r, salsaBuf)
            System.arraycopy(xy, blockWords, xy, 0, blockWords)
        }

        System.arraycopy(xy, 0, b, bOffset, blockWords)
    }

    private fun blockMix(
        src: IntArray,
        srcOffset: Int,
        dst: IntArray,
        dstOffset: Int,
        r: Int,
        x: IntArray,
    ) {
        val lastInOffset = srcOffset + (2 * r - 1) * 16
        System.arraycopy(src, lastInOffset, x, 0, 16)

        val secondHalfBase = dstOffset + r * 16
        for (i in 0 until 2 * r) {
            val inOff = srcOffset + i * 16
            for (k in 0 until 16) {
                x[k] = x[k] xor src[inOff + k]
            }
            salsa20_8(x)
            val outOff = if ((i and 1) == 0) {
                dstOffset + (i ushr 1) * 16
            } else {
                secondHalfBase + (i ushr 1) * 16
            }
            System.arraycopy(x, 0, dst, outOff, 16)
        }
    }

    private fun salsa20_8(b: IntArray) {
        var x0 = b[0]
        var x1 = b[1]
        var x2 = b[2]
        var x3 = b[3]
        var x4 = b[4]
        var x5 = b[5]
        var x6 = b[6]
        var x7 = b[7]
        var x8 = b[8]
        var x9 = b[9]
        var x10 = b[10]
        var x11 = b[11]
        var x12 = b[12]
        var x13 = b[13]
        var x14 = b[14]
        var x15 = b[15]

        for (round in 0 until 4) {
            // Column round
            x4 = x4 xor rotl(x0 + x12, 7)
            x8 = x8 xor rotl(x4 + x0, 9)
            x12 = x12 xor rotl(x8 + x4, 13)
            x0 = x0 xor rotl(x12 + x8, 18)

            x9 = x9 xor rotl(x5 + x1, 7)
            x13 = x13 xor rotl(x9 + x5, 9)
            x1 = x1 xor rotl(x13 + x9, 13)
            x5 = x5 xor rotl(x1 + x13, 18)

            x14 = x14 xor rotl(x10 + x6, 7)
            x2 = x2 xor rotl(x14 + x10, 9)
            x6 = x6 xor rotl(x2 + x14, 13)
            x10 = x10 xor rotl(x6 + x2, 18)

            x3 = x3 xor rotl(x15 + x11, 7)
            x7 = x7 xor rotl(x3 + x15, 9)
            x11 = x11 xor rotl(x7 + x3, 13)
            x15 = x15 xor rotl(x11 + x7, 18)

            // Row round
            x1 = x1 xor rotl(x0 + x3, 7)
            x2 = x2 xor rotl(x1 + x0, 9)
            x3 = x3 xor rotl(x2 + x1, 13)
            x0 = x0 xor rotl(x3 + x2, 18)

            x6 = x6 xor rotl(x5 + x4, 7)
            x7 = x7 xor rotl(x6 + x5, 9)
            x4 = x4 xor rotl(x7 + x6, 13)
            x5 = x5 xor rotl(x4 + x7, 18)

            x11 = x11 xor rotl(x10 + x9, 7)
            x8 = x8 xor rotl(x11 + x10, 9)
            x9 = x9 xor rotl(x8 + x11, 13)
            x10 = x10 xor rotl(x9 + x8, 18)

            x12 = x12 xor rotl(x15 + x14, 7)
            x13 = x13 xor rotl(x12 + x15, 9)
            x14 = x14 xor rotl(x13 + x12, 13)
            x15 = x15 xor rotl(x14 + x13, 18)
        }

        b[0] += x0
        b[1] += x1
        b[2] += x2
        b[3] += x3
        b[4] += x4
        b[5] += x5
        b[6] += x6
        b[7] += x7
        b[8] += x8
        b[9] += x9
        b[10] += x10
        b[11] += x11
        b[12] += x12
        b[13] += x13
        b[14] += x14
        b[15] += x15
    }

    private fun rotl(value: Int, shift: Int): Int = (value shl shift) or (value ushr (32 - shift))

    private fun pbkdf2HmacSha256Single(
        password: ByteArray,
        salt: ByteArray,
        dkLen: Int,
        provider: Provider,
    ): ByteArray {
        val mac: Mac = CryptoPrimitives.newHmacSha256(password, provider)
        val out = ByteArray(dkLen)
        val counter = ByteArray(4)
        var offset = 0
        var blockIndex = 1
        while (offset < dkLen) {
            counter[0] = (blockIndex ushr 24).toByte()
            counter[1] = (blockIndex ushr 16).toByte()
            counter[2] = (blockIndex ushr 8).toByte()
            counter[3] = blockIndex.toByte()
            mac.reset()
            if (salt.isNotEmpty()) {
                mac.update(salt)
            }
            mac.update(counter)
            val block = mac.doFinal()
            val copyLen = minOf(block.size, dkLen - offset)
            System.arraycopy(block, 0, out, offset, copyLen)
            CryptoPrimitives.zero(block)
            offset += copyLen
            blockIndex++
        }
        return out
    }

    private fun bytesToLittleEndianInts(src: ByteArray, dst: IntArray) {
        for (i in dst.indices) {
            val base = i shl 2
            dst[i] = (src[base].toInt() and 0xFF) or
                    ((src[base + 1].toInt() and 0xFF) shl 8) or
                    ((src[base + 2].toInt() and 0xFF) shl 16) or
                    ((src[base + 3].toInt() and 0xFF) shl 24)
        }
    }

    private fun littleEndianIntsToBytes(src: IntArray, dst: ByteArray) {
        for (i in src.indices) {
            val v = src[i]
            val base = i shl 2
            dst[base] = v.toByte()
            dst[base + 1] = (v ushr 8).toByte()
            dst[base + 2] = (v ushr 16).toByte()
            dst[base + 3] = (v ushr 24).toByte()
        }
    }

    private fun decodeUtf8Chars(utf8: ByteArray): CharArray {
        val charBuffer: CharBuffer = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(utf8))
        val chars = CharArray(charBuffer.remaining())
        charBuffer.get(chars)
        return chars
    }
}
