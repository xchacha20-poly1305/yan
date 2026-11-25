package io.github.xchacha20_poly1305.yan

/**
 * Unwraps the 16-byte symmetric file key from the header [Stanza] list during decryption.
 */
public interface Identity {
    /**
     * Inspects all [stanzas] in the header and returns the unwrapped 16-byte file key, or `null`
     * if none of the stanzas match this identity.
     *
     * Implementations MUST ignore unrecognized stanza types and reject malformed stanzas of their
     * own type by throwing [HeaderFormatException].
     */
    @Throws(AgeException::class)
    public fun unwrap(stanzas: List<Stanza>): ByteArray?
}
