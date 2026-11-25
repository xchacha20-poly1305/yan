package io.github.xchacha20_poly1305.yan

/**
 * Wraps the 16-byte symmetric file key into one or more header [Stanza] entries during encryption.
 */
public interface Recipient {
    /**
     * Wraps [fileKey] (16 bytes) and returns one or more recipient stanzas.
     */
    @Throws(AgeException::class)
    public fun wrap(fileKey: ByteArray): List<Stanza>
}
