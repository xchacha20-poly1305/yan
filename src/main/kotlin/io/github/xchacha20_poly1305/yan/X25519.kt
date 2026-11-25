package io.github.xchacha20_poly1305.yan

import io.github.xchacha20_poly1305.yan.internal.Base64Strict
import io.github.xchacha20_poly1305.yan.internal.Bech32
import io.github.xchacha20_poly1305.yan.internal.CryptoPrimitives
import org.bouncycastle.math.ec.rfc7748.X25519
import java.io.Closeable
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException

/**
 * An `age` X25519 public key recipient (`age1...`).
 */
public class X25519Recipient internal constructor(
    publicKeyBytes: ByteArray,
) : Recipient {
    public companion object {
        private const val HRP = "age"
        private const val KEY_SIZE = 32
        internal val INFO_BYTES: ByteArray =
            "age-encryption.org/v1/X25519".toByteArray(StandardCharsets.US_ASCII)

        /**
         * Parses a lowercase Bech32-encoded X25519 recipient string (`age1...`).
         */
        @JvmStatic
        @Throws(KeyFormatException::class)
        public fun parse(
            encoded: String,
        ): X25519Recipient {
            val decoded = try {
                Bech32.decode(encoded)
            } catch (e: IllegalArgumentException) {
                throw KeyFormatException("Malformed X25519 recipient", e)
            }
            if (decoded.hrp != HRP || decoded.isUppercase) {
                throw KeyFormatException("Invalid X25519 recipient prefix: '${decoded.hrp}'")
            }
            if (decoded.data.size != KEY_SIZE) {
                throw KeyFormatException("Invalid X25519 recipient key size: ${decoded.data.size}")
            }
            return X25519Recipient(decoded.data)
        }
    }

    private val rawPublicKey: ByteArray = publicKeyBytes.copyOf()

    init {
        require(rawPublicKey.size == KEY_SIZE) { "X25519 public key must be $KEY_SIZE bytes" }
    }

    /**
     * Returns the lowercase Bech32 encoding (`age1...`) of this recipient.
     */
    public fun encode(): String = Bech32.encode(HRP, rawPublicKey, uppercase = false)

    /**
     * Returns a defensive copy of the 32-byte X25519 public key.
     */
    public fun publicKeyBytes(): ByteArray = rawPublicKey.copyOf()

    override fun wrap(fileKey: ByteArray): List<Stanza> {
        require(fileKey.size == 16) { "File key must be 16 bytes" }
        val ephemeral = CryptoPrimitives.randomBytes(KEY_SIZE)
        val ephPubBytes = ByteArray(KEY_SIZE)
        val sharedSecret = ByteArray(KEY_SIZE)
        try {
            X25519.generatePublicKey(ephemeral, 0, ephPubBytes, 0)
            if (!X25519.calculateAgreement(ephemeral, 0, rawPublicKey, 0, sharedSecret, 0)) {
                CryptoPrimitives.zero(sharedSecret)
                throw KeyFormatException("Invalid X25519 recipient public key")
            }
        } finally {
            CryptoPrimitives.zero(ephemeral)
        }

        val salt = ByteArray(KEY_SIZE * 2)
        System.arraycopy(ephPubBytes, 0, salt, 0, KEY_SIZE)
        System.arraycopy(rawPublicKey, 0, salt, KEY_SIZE, KEY_SIZE)

        var wrapKey: ByteArray? = null
        return try {
            wrapKey = CryptoPrimitives.hkdfSha256(
                ikm = sharedSecret,
                salt = salt,
                info = INFO_BYTES,
                length = 32,
            )
            val body = CryptoPrimitives.chacha20Poly1305Seal(
                key = wrapKey,
                nonce = ByteArray(12),
                plaintext = fileKey,
            )
            listOf(
                Stanza(
                    type = "X25519",
                    args = listOf(Base64Strict.encodeRaw(ephPubBytes)),
                    body = body,
                ),
            )
        } finally {
            CryptoPrimitives.zero(sharedSecret)
            CryptoPrimitives.zero(wrapKey)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X25519Recipient) return false
        return rawPublicKey.contentEquals(other.rawPublicKey)
    }

    override fun hashCode(): Int = rawPublicKey.contentHashCode()

    override fun toString(): String = encode()
}

/**
 * An `age` X25519 secret key identity (`AGE-SECRET-KEY-1...`).
 *
 * Call [close] when finished to zero sensitive private key material from memory.
 */
public class X25519Identity private constructor(
    secretBytes: ByteArray,
) : Identity, Closeable {
    public companion object {
        private const val HRP = "AGE-SECRET-KEY-"
        private const val KEY_SIZE = 32
        /**
         * Generates a new random [X25519Identity].
         */
        @JvmStatic
        public fun generate(): X25519Identity =
            X25519Identity(CryptoPrimitives.randomBytes(KEY_SIZE))

        /**
         * Parses an uppercase Bech32-encoded X25519 secret key (`AGE-SECRET-KEY-1...`).
         */
        @JvmStatic
        @Throws(KeyFormatException::class)
        public fun parse(
            encoded: String,
        ): X25519Identity {
            val decoded = try {
                Bech32.decode(encoded)
            } catch (e: IllegalArgumentException) {
                throw KeyFormatException("Malformed X25519 secret key", e)
            }
            if (decoded.hrp != HRP || !decoded.isUppercase) {
                CryptoPrimitives.zero(decoded.data)
                throw KeyFormatException("Invalid X25519 secret key prefix")
            }
            if (decoded.data.size != KEY_SIZE) {
                CryptoPrimitives.zero(decoded.data)
                throw KeyFormatException("Invalid X25519 secret key size: ${decoded.data.size}")
            }

            return X25519Identity(decoded.data)
        }
    }

    private var rawSecretKey: ByteArray? = secretBytes
    private val rawPublicKey = ByteArray(KEY_SIZE).also { X25519.generatePublicKey(secretBytes, 0, it, 0) }
    private val recipientInstance = X25519Recipient(rawPublicKey)
    private var closed: Boolean = false

    /**
     * Returns the corresponding public [X25519Recipient].
     */
    public val recipient: X25519Recipient
        get() {
            checkNotClosed()
            return recipientInstance
        }

    /**
     * Returns the uppercase Bech32 encoding (`AGE-SECRET-KEY-1...`) of this secret key.
     */
    public fun encode(): String {
        checkNotClosed()
        return Bech32.encode(HRP, rawSecretKey!!, uppercase = true)
    }

    override fun unwrap(stanzas: List<Stanza>): ByteArray? {
        checkNotClosed()
        for (stanza in stanzas) {
            if (stanza.type != "X25519") continue
            if (stanza.args.size != 1) {
                throw HeaderFormatException("Invalid X25519 stanza argument count: ${stanza.args.size}")
            }
            val ephShare = try {
                Base64Strict.decodeRaw(stanza.args[0])
            } catch (e: IllegalArgumentException) {
                throw HeaderFormatException("Invalid X25519 ephemeral share encoding", e)
            }
            if (ephShare.size != KEY_SIZE) {
                throw HeaderFormatException("Invalid X25519 ephemeral share size: ${ephShare.size}")
            }
            // Check body length (16-byte file key + 16-byte tag = 32 bytes) before decrypting.
            if (stanza.rawBody.size != 32) {
                throw HeaderFormatException("Invalid X25519 stanza body length: ${stanza.rawBody.size}")
            }

            val sharedSecret = ByteArray(KEY_SIZE)
            if (!X25519.calculateAgreement(rawSecretKey!!, 0, ephShare, 0, sharedSecret, 0)) {
                CryptoPrimitives.zero(sharedSecret)
                throw HeaderFormatException("Invalid X25519 ephemeral share (low-order or identity point)")
            }

            val salt = ByteArray(KEY_SIZE * 2)
            System.arraycopy(ephShare, 0, salt, 0, KEY_SIZE)
            System.arraycopy(rawPublicKey, 0, salt, KEY_SIZE, KEY_SIZE)

            var wrapKey: ByteArray? = null
            try {
                wrapKey = CryptoPrimitives.hkdfSha256(
                    ikm = sharedSecret,
                    salt = salt,
                    info = X25519Recipient.INFO_BYTES,
                    length = 32,
                )
                val fileKey = CryptoPrimitives.chacha20Poly1305Open(
                    key = wrapKey,
                    nonce = ByteArray(12),
                    ciphertext = stanza.rawBody,
                )
                if (fileKey.size != 16) {
                    CryptoPrimitives.zero(fileKey)
                    throw HeaderFormatException("Unwrapped file key has invalid length: ${fileKey.size}")
                }
                return fileKey
            } catch (_: GeneralSecurityException) {
                // Tag verification failed; stanza was encrypted to a different recipient.
            } finally {
                CryptoPrimitives.zero(sharedSecret)
                CryptoPrimitives.zero(wrapKey)
            }
        }
        return null
    }

    override fun close() {
        if (closed) return
        closed = true
        CryptoPrimitives.zero(rawSecretKey)
        rawSecretKey = null
    }

    override fun toString(): String = "X25519Identity(recipient=${recipientInstance.encode()}, [REDACTED])"

    private fun checkNotClosed() {
        if (closed) {
            throw IllegalStateException("X25519Identity has been closed")
        }
    }
}
