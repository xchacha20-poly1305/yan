package io.github.xchacha20_poly1305.yan.internal

import kotlin.io.encoding.Base64

internal object Base64Strict {
    private val RAW_CODEC: Base64 = Base64.withPadding(Base64.PaddingOption.ABSENT)
    private val PADDED_CODEC: Base64 = Base64.withPadding(Base64.PaddingOption.PRESENT)

    fun encodeRaw(data: ByteArray): String = RAW_CODEC.encode(data)

    fun encodeRawBytes(data: ByteArray): ByteArray = RAW_CODEC.encodeToByteArray(data)

    fun decodeRaw(input: String): ByteArray = RAW_CODEC.decode(input)

    fun encodePaddedInto(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int,
    ): Int = PADDED_CODEC.encodeIntoByteArray(source, destination, destinationOffset, startIndex, endIndex)

    fun decodePaddedInto(source: ByteArray, destination: ByteArray, endIndex: Int): Int =
        PADDED_CODEC.decodeIntoByteArray(source, destination, endIndex = endIndex)
}
