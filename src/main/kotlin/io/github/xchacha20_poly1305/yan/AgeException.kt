package io.github.xchacha20_poly1305.yan

import java.io.IOException

/**
 * Base exception for errors encountered during `age` key parsing, encryption, or decryption.
 *
 * Extends [IOException] so streaming [java.io.InputStream] and [java.io.OutputStream] operations
 * can throw specific `age` protocol errors directly without losing failure classification.
 */
public open class AgeException(
    message: String,
    cause: Throwable? = null,
) : IOException(message, cause)

/**
 * Thrown when ASCII-armored PEM input violates the `age` strict RFC 7468 armor specification.
 */
public class ArmorFormatException(
    message: String,
    cause: Throwable? = null,
) : AgeException(message, cause)

/**
 * Thrown when an `age` file header or native recipient stanza is syntactically or structurally invalid.
 */
public class HeaderFormatException(
    message: String,
    cause: Throwable? = null,
) : AgeException(message, cause)

/**
 * Thrown when the `age` header MAC fails verification against the unwrapped file key.
 */
public class HeaderMacException(
    message: String,
    cause: Throwable? = null,
) : AgeException(message, cause)

/**
 * Thrown when none of the provided identities can unwrap any stanza in the `age` header.
 */
public class NoMatchingIdentityException(
    message: String,
    cause: Throwable? = null,
) : AgeException(message, cause)

/**
 * Thrown when the STREAM-encrypted payload fails authentication, is truncated, or has trailing data.
 */
public class PayloadDecryptionException(
    message: String,
    cause: Throwable? = null,
) : AgeException(message, cause)

/**
 * Thrown when a Bech32-encoded `age` recipient or identity string cannot be parsed.
 */
public class KeyFormatException(
    message: String,
    cause: Throwable? = null,
) : AgeException(message, cause)
