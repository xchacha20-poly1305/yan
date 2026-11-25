package io.github.xchacha20_poly1305.yan

import java.util.Collections

/**
 * A single recipient stanza in an `age` file header.
 *
 * Custom [Recipient] and [Identity] implementations can use this class to construct or inspect
 * recipient stanzas without using external plugins.
 */
public class Stanza(
    public val type: String,
    args: List<String>,
    body: ByteArray,
) {
    /**
     * Space-separated stanza arguments following [type].
     */
    public val args: List<String> = Collections.unmodifiableList(args.toList())

    internal val rawBody: ByteArray = body.copyOf()

    /**
     * Returns a defensive copy of the stanza body bytes.
     */
    public val body: ByteArray
        get() = rawBody.copyOf()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Stanza) return false
        return type == other.type && args == other.args && rawBody.contentEquals(other.rawBody)
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + args.hashCode()
        result = 31 * result + rawBody.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "Stanza(type=$type, argsCount=${args.size}, bodySize=${rawBody.size})"
    }
}
