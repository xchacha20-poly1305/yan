package io.github.xchacha20_poly1305.yan

import io.github.xchacha20_poly1305.yan.internal.Base64Strict
import io.github.xchacha20_poly1305.yan.internal.CryptoPrimitives
import io.github.xchacha20_poly1305.yan.internal.ScryptKdf
import java.io.Closeable
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException

/**
 * Passphrase-based `age` recipient implementing the `scrypt` stanza type.
 *
 * Instances hold sensitive passphrase material and should be closed via [close] when no longer
 * needed. Per the `age` specification, an `scrypt` recipient MUST NOT be mixed with any other
 * recipient when encrypting a file.
 */
public class ScryptRecipient : Recipient, Closeable {
    public companion object {
        /**
         * Default scrypt work factor (`N = 2^18 = 262144`, ~256 MiB memory).
         */
        public const val DEFAULT_WORK_FACTOR: Int = 18

        /**
         * Minimum supported scrypt work factor.
         */
        public const val MIN_WORK_FACTOR: Int = 1

        /**
         * Maximum supported scrypt work factor (`2^30`).
         */
        public const val MAX_WORK_FACTOR: Int = 30

        internal val SALT_PREFIX: ByteArray =
            "age-encryption.org/v1/scrypt".toByteArray(StandardCharsets.US_ASCII)
    }

    private var passphraseUtf8: ByteArray?
    private val workFactor: Int
    private var closed: Boolean = false

    /**
     * Creates an [ScryptRecipient] from a [CharArray] passphrase.
     */
    @JvmOverloads
    public constructor(
        passphrase: CharArray,
        workFactor: Int = DEFAULT_WORK_FACTOR,
    ) {
        validateWorkFactor(workFactor)
        this.passphraseUtf8 = encodeUtf8(passphrase)
        this.workFactor = workFactor
    }

    /**
     * Creates an [ScryptRecipient] from a [String] passphrase.
     */
    @JvmOverloads
    public constructor(
        passphrase: String,
        workFactor: Int = DEFAULT_WORK_FACTOR,
    ) : this(passphrase.toCharArray(), workFactor)

    override fun wrap(fileKey: ByteArray): List<Stanza> {
        checkNotClosed()
        require(fileKey.size == 16) { "File key must be 16 bytes" }
        val salt = CryptoPrimitives.randomBytes(16)
        val combinedSalt = ByteArray(SALT_PREFIX.size + salt.size)
        System.arraycopy(SALT_PREFIX, 0, combinedSalt, 0, SALT_PREFIX.size)
        System.arraycopy(salt, 0, combinedSalt, SALT_PREFIX.size, salt.size)

        val wrapKey = ScryptKdf.derive(
            passphraseUtf8 = passphraseUtf8!!,
            salt = combinedSalt,
            workFactor = workFactor,
        )
        try {
            val body = CryptoPrimitives.chacha20Poly1305Seal(
                key = wrapKey,
                nonce = ByteArray(12),
                plaintext = fileKey,
            )
            return listOf(
                Stanza(
                    type = "scrypt",
                    args = listOf(Base64Strict.encodeRaw(salt), workFactor.toString()),
                    body = body,
                ),
            )
        } finally {
            CryptoPrimitives.zero(wrapKey)
            CryptoPrimitives.zero(combinedSalt)
        }
    }

    /**
     * Returns the configured log2 scrypt cost parameter (`workFactor`).
     */
    public fun workFactor(): Int = workFactor

    override fun close() {
        if (closed) return
        closed = true
        CryptoPrimitives.zero(passphraseUtf8)
        passphraseUtf8 = null
    }

    override fun toString(): String = "ScryptRecipient(workFactor=$workFactor, [REDACTED])"

    private fun checkNotClosed() {
        if (closed) {
            throw IllegalStateException("ScryptRecipient has been closed")
        }
    }

    private fun validateWorkFactor(wf: Int) {
        require(wf in MIN_WORK_FACTOR..MAX_WORK_FACTOR) {
            "scrypt workFactor must be in $MIN_WORK_FACTOR..$MAX_WORK_FACTOR, got $wf"
        }
    }
}

/**
 * Passphrase-based `age` identity implementing the `scrypt` stanza type.
 *
 * Instances hold sensitive passphrase material and should be closed via [close] when no longer
 * needed.
 */
public class ScryptIdentity : Identity, Closeable {
    public companion object {
        /**
         * Default upper limit for accepted scrypt work factors during decryption (`2^22`).
         */
        public const val DEFAULT_MAX_WORK_FACTOR: Int = 22
    }

    private var passphraseUtf8: ByteArray?
    private val maxWorkFactor: Int
    private var closed: Boolean = false

    /**
     * Creates an [ScryptIdentity] from a [CharArray] passphrase.
     */
    @JvmOverloads
    public constructor(
        passphrase: CharArray,
        maxWorkFactor: Int = DEFAULT_MAX_WORK_FACTOR,
    ) {
        require(maxWorkFactor in ScryptRecipient.MIN_WORK_FACTOR..ScryptRecipient.MAX_WORK_FACTOR) {
            "maxWorkFactor must be in ${ScryptRecipient.MIN_WORK_FACTOR}..${ScryptRecipient.MAX_WORK_FACTOR}, got $maxWorkFactor"
        }
        this.passphraseUtf8 = encodeUtf8(passphrase)
        this.maxWorkFactor = maxWorkFactor
    }

    /**
     * Creates an [ScryptIdentity] from a [String] passphrase.
     */
    @JvmOverloads
    public constructor(
        passphrase: String,
        maxWorkFactor: Int = DEFAULT_MAX_WORK_FACTOR,
    ) : this(passphrase.toCharArray(), maxWorkFactor)

    override fun unwrap(stanzas: List<Stanza>): ByteArray? {
        checkNotClosed()
        var matchedStanza: Stanza? = null
        for (stanza in stanzas) {
            if (stanza.type == "scrypt") {
                if (stanzas.size != 1) {
                    throw HeaderFormatException("scrypt stanza must be the only stanza in the header")
                }
                matchedStanza = stanza
            }
        }
        val stanza = matchedStanza ?: return null

        if (stanza.args.size != 2) {
            throw HeaderFormatException("Invalid scrypt stanza argument count: ${stanza.args.size}")
        }
        val salt = try {
            Base64Strict.decodeRaw(stanza.args[0])
        } catch (e: IllegalArgumentException) {
            throw HeaderFormatException("Invalid scrypt salt encoding", e)
        }
        if (salt.size != 16) {
            throw HeaderFormatException("Invalid scrypt salt length: ${salt.size}")
        }

        val workFactor = parseWorkFactorStrict(stanza.args[1])
        if (workFactor > maxWorkFactor) {
            throw HeaderFormatException(
                "scrypt work factor $workFactor exceeds configured maximum ($maxWorkFactor)",
            )
        }

        // Check body length (16-byte file key + 16-byte Poly1305 tag = 32 bytes) before KDF.
        if (stanza.rawBody.size != 32) {
            throw HeaderFormatException("Invalid scrypt stanza body length: ${stanza.rawBody.size}")
        }

        val combinedSalt = ByteArray(ScryptRecipient.SALT_PREFIX.size + salt.size)
        System.arraycopy(ScryptRecipient.SALT_PREFIX, 0, combinedSalt, 0, ScryptRecipient.SALT_PREFIX.size)
        System.arraycopy(salt, 0, combinedSalt, ScryptRecipient.SALT_PREFIX.size, salt.size)

        val wrapKey = ScryptKdf.derive(
            passphraseUtf8 = passphraseUtf8!!,
            salt = combinedSalt,
            workFactor = workFactor,
        )
        return try {
            val fileKey = CryptoPrimitives.chacha20Poly1305Open(
                key = wrapKey,
                nonce = ByteArray(12),
                ciphertext = stanza.rawBody,
            )
            if (fileKey.size != 16) {
                CryptoPrimitives.zero(fileKey)
                throw HeaderFormatException("Unwrapped file key has invalid length: ${fileKey.size}")
            }
            fileKey
        } catch (_: GeneralSecurityException) {
            null
        } finally {
            CryptoPrimitives.zero(wrapKey)
            CryptoPrimitives.zero(combinedSalt)
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        CryptoPrimitives.zero(passphraseUtf8)
        passphraseUtf8 = null
    }

    override fun toString(): String = "ScryptIdentity(maxWorkFactor=$maxWorkFactor, [REDACTED])"

    private fun checkNotClosed() {
        if (closed) {
            throw IllegalStateException("ScryptIdentity has been closed")
        }
    }

    private fun parseWorkFactorStrict(raw: String): Int {
        if (raw.isEmpty()) {
            throw HeaderFormatException("Empty scrypt work factor")
        }
        // RFC/ABNF: %x31-39 *DIGIT (no leading zero, no sign, ASCII digits only).
        val first = raw[0]
        if (first !in '1'..'9') {
            throw HeaderFormatException("Invalid scrypt work factor: '$raw'")
        }
        var value = first - '0'
        for (i in 1 until raw.length) {
            val char = raw[i]
            if (char !in '0'..'9') {
                throw HeaderFormatException("Invalid scrypt work factor: '$raw'")
            }
            val digit = char - '0'
            if (value > (Int.MAX_VALUE - digit) / 10) {
                throw HeaderFormatException("scrypt work factor overflow: '$raw'")
            }
            value = value * 10 + digit
        }
        return value
    }
}

private fun encodeUtf8(chars: CharArray): ByteArray {
    val buffer: ByteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars))
    val out = ByteArray(buffer.remaining())
    buffer.get(out)
    if (buffer.hasArray()) {
        CryptoPrimitives.zero(buffer.array())
    }
    return out
}
