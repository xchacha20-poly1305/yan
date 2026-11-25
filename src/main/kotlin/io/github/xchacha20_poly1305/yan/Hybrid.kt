package io.github.xchacha20_poly1305.yan

import io.github.xchacha20_poly1305.yan.internal.Base64Strict
import io.github.xchacha20_poly1305.yan.internal.Bech32
import io.github.xchacha20_poly1305.yan.internal.CryptoPrimitives
import io.github.xchacha20_poly1305.yan.internal.RawKeySpec
import org.conscrypt.HpkeContextRecipient
import org.conscrypt.HpkeContextSender
import org.conscrypt.NativeCrypto
import org.conscrypt.OpenSslXwingPrivateKey
import java.io.Closeable
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey

/**
 * Post-quantum hybrid `age` recipient (`age1pq1...`) using MLKEM768-X25519 (X-Wing) HPKE.
 *
 * Per the `age` specification, files encrypted to this recipient SHOULD NOT also be encrypted
 * to non-quantum-resistant recipients, because compromise of a classical recipient key would
 * expose the symmetric file key.
 */
public class HybridRecipient internal constructor(
    publicKeyBytes: ByteArray,
    private val provider: Provider,
) : Recipient {
    public companion object {
        private const val HRP = "age1pq"
        internal const val PUBLIC_KEY_SIZE = 1216
        internal const val HPKE_SUITE = "XWING/HKDF_SHA256/CHACHA20POLY1305"
        internal val INFO_BYTES: ByteArray =
            "age-encryption.org/mlkem768x25519".toByteArray(StandardCharsets.US_ASCII)

        /**
         * Parses a lowercase Bech32-encoded MLKEM768-X25519 recipient string (`age1pq1...`).
         */
        @JvmStatic
        @JvmOverloads
        @Throws(KeyFormatException::class)
        public fun parse(
            encoded: String,
            provider: Provider = AgeProvider.defaultProvider(),
        ): HybridRecipient {
            AgeProvider.requireConscrypt(provider)
            val decoded = try {
                Bech32.decode(encoded)
            } catch (e: IllegalArgumentException) {
                throw KeyFormatException("Malformed hybrid recipient", e)
            }
            if (decoded.hrp != HRP || decoded.isUppercase) {
                throw KeyFormatException("Invalid hybrid recipient prefix: '${decoded.hrp}'")
            }
            if (decoded.data.size != PUBLIC_KEY_SIZE) {
                throw KeyFormatException("Invalid hybrid recipient key size: ${decoded.data.size}")
            }
            return HybridRecipient(decoded.data, provider)
        }
    }

    private val rawPublicKey: ByteArray = publicKeyBytes.copyOf()
    private val publicKey: PublicKey

    init {
        require(rawPublicKey.size == PUBLIC_KEY_SIZE) {
            "X-Wing public key must be $PUBLIC_KEY_SIZE bytes"
        }
        AgeProvider.requireConscrypt(provider)
        val factory = KeyFactory.getInstance("XWING", provider)
        publicKey = factory.generatePublic(RawKeySpec(rawPublicKey))
    }

    /**
     * Returns the lowercase Bech32 encoding (`age1pq1...`) of this recipient.
     */
    public fun encode(): String = Bech32.encode(HRP, rawPublicKey, uppercase = false)

    /**
     * Returns a defensive copy of the 1216-byte MLKEM768-X25519 public key.
     */
    public fun publicKeyBytes(): ByteArray = rawPublicKey.copyOf()

    override fun wrap(fileKey: ByteArray): List<Stanza> {
        require(fileKey.size == 16) { "File key must be 16 bytes" }
        val sender = HpkeContextSender.getInstance(HPKE_SUITE, provider)
        sender.init(publicKey, INFO_BYTES)
        val encapsulated = sender.encapsulated
        val body = sender.seal(fileKey, CryptoPrimitives.EMPTY_BYTES)
        return listOf(
            Stanza(
                type = "mlkem768x25519",
                args = listOf(Base64Strict.encodeRaw(encapsulated)),
                body = body,
            ),
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HybridRecipient) return false
        return rawPublicKey.contentEquals(other.rawPublicKey)
    }

    override fun hashCode(): Int = rawPublicKey.contentHashCode()

    override fun toString(): String = encode()
}

/**
 * Post-quantum hybrid `age` secret key identity (`AGE-SECRET-KEY-PQ-1...`) using MLKEM768-X25519
 * (X-Wing).
 *
 * Call [close] when finished to zero sensitive private key material from memory.
 */
public class HybridIdentity private constructor(
    seedBytes: ByteArray,
    publicKeyBytes: ByteArray,
    private val provider: Provider,
) : Identity, Closeable {
    public companion object {
        private const val HRP = "AGE-SECRET-KEY-PQ-"
        private const val SEED_SIZE = 32
        private const val ENC_SIZE = 1120

        /**
         * Generates a new random [HybridIdentity] using Conscrypt's X-Wing key generator.
         */
        @JvmStatic
        @JvmOverloads
        public fun generate(provider: Provider = AgeProvider.defaultProvider()): HybridIdentity {
            AgeProvider.requireConscrypt(provider)
            val keyPairGenerator = KeyPairGenerator.getInstance("XWING", provider)
            val keyPair = keyPairGenerator.generateKeyPair()
            val keyFactory = KeyFactory.getInstance("XWING", provider)
            val seed = keyFactory.getKeySpec(keyPair.private, RawKeySpec::class.java).encoded
            val publicKey = keyFactory.getKeySpec(keyPair.public, RawKeySpec::class.java).encoded
            destroyXwingPrivateKey(keyPair.private)
            return HybridIdentity(seed, publicKey, provider)
        }

        /**
         * Parses an uppercase Bech32-encoded MLKEM768-X25519 secret key (`AGE-SECRET-KEY-PQ-1...`).
         */
        @JvmStatic
        @JvmOverloads
        @Throws(KeyFormatException::class)
        public fun parse(
            encoded: String,
            provider: Provider = AgeProvider.defaultProvider(),
        ): HybridIdentity {
            AgeProvider.requireConscrypt(provider)
            val decoded = try {
                Bech32.decode(encoded)
            } catch (e: IllegalArgumentException) {
                throw KeyFormatException("Malformed hybrid secret key", e)
            }
            if (decoded.hrp != HRP || !decoded.isUppercase) {
                CryptoPrimitives.zero(decoded.data)
                throw KeyFormatException("Invalid hybrid secret key prefix")
            }
            if (decoded.data.size != SEED_SIZE) {
                CryptoPrimitives.zero(decoded.data)
                throw KeyFormatException("Invalid hybrid secret key size: ${decoded.data.size}")
            }
            // Ensure Conscrypt native library is initialized before calling NativeCrypto.
            KeyFactory.getInstance("XWING", provider)
            val pubBytes = NativeCrypto.XWING_public_key_from_seed(decoded.data)
            return HybridIdentity(decoded.data, pubBytes, provider)
        }
    }

    private var rawSeed: ByteArray? = seedBytes.copyOf()
    private val privateKey: PrivateKey
    private val recipientInstance: HybridRecipient
    private var closed: Boolean = false

    init {
        CryptoPrimitives.zero(seedBytes)
        val factory = KeyFactory.getInstance("XWING", provider)
        privateKey = factory.generatePrivate(RawKeySpec(rawSeed!!))
        recipientInstance = HybridRecipient(publicKeyBytes, provider)
    }

    /**
     * Returns the corresponding public [HybridRecipient].
     */
    public val recipient: HybridRecipient
        get() {
            checkNotClosed()
            return recipientInstance
        }

    /**
     * Returns the uppercase Bech32 encoding (`AGE-SECRET-KEY-PQ-1...`) of this secret key.
     */
    public fun encode(): String {
        checkNotClosed()
        return Bech32.encode(HRP, rawSeed!!, uppercase = true)
    }

    override fun unwrap(stanzas: List<Stanza>): ByteArray? {
        checkNotClosed()
        for (stanza in stanzas) {
            if (stanza.type != "mlkem768x25519") continue
            if (stanza.args.size != 1) {
                throw HeaderFormatException("Invalid mlkem768x25519 stanza argument count: ${stanza.args.size}")
            }
            val enc = try {
                Base64Strict.decodeRaw(stanza.args[0])
            } catch (e: IllegalArgumentException) {
                throw HeaderFormatException("Invalid mlkem768x25519 enc encoding", e)
            }
            if (enc.size != ENC_SIZE) {
                throw HeaderFormatException("Invalid mlkem768x25519 enc length: ${enc.size}")
            }
            // Check body length (16-byte file key + 16-byte tag = 32 bytes) before decrypting.
            if (stanza.rawBody.size != 32) {
                throw HeaderFormatException("Invalid mlkem768x25519 stanza body length: ${stanza.rawBody.size}")
            }

            val recipientCtx = HpkeContextRecipient.getInstance(HybridRecipient.HPKE_SUITE, provider)
            try {
                recipientCtx.init(enc, privateKey, HybridRecipient.INFO_BYTES)
            } catch (e: GeneralSecurityException) {
                throw HeaderFormatException("Invalid mlkem768x25519 encapsulated key", e)
            } catch (e: RuntimeException) {
                throw HeaderFormatException("Invalid mlkem768x25519 encapsulated key", e)
            }

            try {
                val fileKey = recipientCtx.open(stanza.rawBody, CryptoPrimitives.EMPTY_BYTES)
                if (fileKey.size != 16) {
                    CryptoPrimitives.zero(fileKey)
                    throw HeaderFormatException("Unwrapped file key has invalid length: ${fileKey.size}")
                }
                return fileKey
            } catch (_: GeneralSecurityException) {
                // Decryption failed; stanza was encrypted to a different recipient or corrupted.
            }
        }
        return null
    }

    override fun close() {
        if (closed) return
        closed = true
        CryptoPrimitives.zero(rawSeed)
        rawSeed = null
        destroyXwingPrivateKey(privateKey)
    }

    override fun toString(): String = "HybridIdentity(recipient=${recipientInstance.encode()}, [REDACTED])"

    private fun checkNotClosed() {
        if (closed) {
            throw IllegalStateException("HybridIdentity has been closed")
        }
    }
}

private fun destroyXwingPrivateKey(key: PrivateKey) {
    if (key is OpenSslXwingPrivateKey) {
        key.destroy()
    }
}
