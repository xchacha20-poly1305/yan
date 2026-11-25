package io.github.xchacha20_poly1305.yan.internal

import kotlin.io.encoding.Base64

internal object Base64Strict {
    private val RAW_CODEC: Base64 = Base64.withPadding(Base64.PaddingOption.ABSENT)
    private val PADDED_CODEC: Base64 = Base64.withPadding(Base64.PaddingOption.PRESENT)

    fun encodeRaw(data: ByteArray): String = RAW_CODEC.encode(data)

    fun decodeRaw(input: String): ByteArray = RAW_CODEC.decode(input)

    fun encodePadded(data: ByteArray): String = PADDED_CODEC.encode(data)

    fun decodePadded(input: String): ByteArray = PADDED_CODEC.decode(input)
}
