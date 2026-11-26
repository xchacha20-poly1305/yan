package io.github.xchacha20_poly1305.yan

import io.github.xchacha20_poly1305.yan.internal.CryptoPrimitives
import io.github.xchacha20_poly1305.yan.internal.HeaderFormat
import io.github.xchacha20_poly1305.yan.internal.StreamCipher
import io.github.xchacha20_poly1305.yan.internal.StreamDecryptInputStream
import io.github.xchacha20_poly1305.yan.internal.StreamEncryptOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.Reader
import java.io.StringReader
import java.nio.charset.MalformedInputException
import java.nio.charset.StandardCharsets

/**
 * Primary entry point for `age` encryption, decryption, and key/recipient parsing.
 */
public object Age {
    private const val FILE_KEY_SIZE = 16
    private const val PAYLOAD_NONCE_SIZE = 16
    private const val KEY_FILE_LIMIT_BYTES = 1 shl 24 // 16 MiB
    private val PAYLOAD_INFO = "payload".toByteArray(StandardCharsets.US_ASCII)

    /**
     * Encrypts plaintext written to the returned [OutputStream] and writes the `age` ciphertext
     * (optionally ASCII-armored when [armor] is `true`) to [output].
     *
     * Callers MUST close the returned [OutputStream] so the final STREAM chunk (and optional PEM
     * footer) is authenticated and flushed.
     *
     * Security note: per the `age` specification, mixing post-quantum ([HybridRecipient]) and
     * classical ([X25519Recipient]) recipients in the same file SHOULD NOT be done, because
     * compromise of any non-PQ identity exposes the file key. Mixing [ScryptRecipient] with any
     * other recipient is strictly forbidden and throws [IllegalArgumentException].
     */
    @JvmStatic
    @JvmOverloads
    @Throws(AgeException::class, IOException::class)
    public fun encrypt(
        output: OutputStream,
        recipients: List<Recipient>,
        armor: Boolean = false,
    ): OutputStream {
        require(recipients.isNotEmpty()) { "At least one recipient is required" }
        if (recipients.size > 1 && recipients.any { it is ScryptRecipient }) {
            throw IllegalArgumentException("ScryptRecipient cannot be mixed with other recipients")
        }

        val fileKey = CryptoPrimitives.randomBytes(FILE_KEY_SIZE)
        try {
            val stanzas = ArrayList<Stanza>(recipients.size)
            for (recipient in recipients) {
                val wrapped = recipient.wrap(fileKey)
                if (wrapped.isEmpty()) {
                    throw HeaderFormatException("Recipient ${recipient.javaClass.name} produced no stanzas")
                }
                stanzas.addAll(wrapped)
            }
            if (stanzas.any { it.type == "scrypt" } && stanzas.size != 1) {
                throw HeaderFormatException("scrypt stanza cannot be mixed with other stanzas")
            }

            val targetOut = if (armor) {
                Armor.wrap(output)
            } else {
                output
            }
            HeaderFormat.writeAuthenticated(stanzas, fileKey, targetOut)
            return StreamEncryptOutputStream(targetOut, fileKey)
        } finally {
            CryptoPrimitives.zero(fileKey)
        }
    }

    /**
     * Convenience vararg overload for binary encryption.
     */
    @JvmStatic
    @Throws(AgeException::class, IOException::class)
    public fun encrypt(output: OutputStream, vararg recipients: Recipient): OutputStream {
        return encrypt(output, recipients.toList())
    }

    /**
     * Encrypts [plaintext] in memory and returns binary or ASCII-armored `age` bytes.
     */
    @JvmStatic
    @JvmOverloads
    @Throws(AgeException::class, IOException::class)
    public fun encryptBytes(
        plaintext: ByteArray,
        recipients: List<Recipient>,
        armor: Boolean = false,
    ): ByteArray = encryptInMemory(plaintext, recipients, armor).toByteArray()

    /**
     * Encrypts [plaintext] in memory and returns an ASCII-armored `age` PEM string.
     */
    @JvmStatic
    @Throws(AgeException::class, IOException::class)
    public fun encryptToArmoredString(
        plaintext: ByteArray,
        recipients: List<Recipient>,
    ): String = encryptInMemory(plaintext, recipients, armor = true).toString(StandardCharsets.US_ASCII.name())

    private fun encryptInMemory(
        plaintext: ByteArray,
        recipients: List<Recipient>,
        armor: Boolean,
    ): ByteArrayOutputStream {
        val chunks = maxOf(1L, (plaintext.size.toLong() + StreamCipher.CHUNK_SIZE - 1) / StreamCipher.CHUNK_SIZE)
        // Custom recipients can produce larger headers. The output grows if this estimate is too small.
        val binarySize = plaintext.size + chunks * StreamCipher.TAG_SIZE + PAYLOAD_NONCE_SIZE + 256
        val capacity = if (armor) {
            Armor.encodedSize(binarySize)
        } else {
            binarySize
        }
        val out = CryptoPrimitives.memoryOutput(capacity)
        encrypt(out, recipients, armor).use {
            it.write(plaintext)
        }
        return out
    }

    /**
     * Decrypts an `age` stream read from [input] using [identities] and returns a streaming
     * [InputStream] yielding authenticated plaintext.
     *
     * When [armor] is `true`, [input] is unwrapped with [Armor.unwrap] before header parsing.
     */
    @JvmStatic
    @JvmOverloads
    @Throws(AgeException::class, IOException::class)
    public fun decrypt(
        input: InputStream,
        identities: List<Identity>,
        armor: Boolean = false,
    ): InputStream {
        val sourceStream = if (armor) {
            Armor.unwrap(input)
        } else {
            input
        }
        val parsed = HeaderFormat.parse(sourceStream)
        val stanzas = parsed.header.stanzas

        if (stanzas.any { it.type == "scrypt" } && stanzas.size != 1) {
            throw HeaderFormatException("scrypt stanza must be the only stanza in the header")
        }
        require(identities.isNotEmpty()) { "At least one identity is required" }

        val orderedIdentities = orderNativeIdentitiesFirst(identities)
        var unwrappedKey: ByteArray? = null
        for (identity in orderedIdentities) {
            val candidate = identity.unwrap(stanzas)
            if (candidate != null) {
                if (candidate.size != FILE_KEY_SIZE) {
                    CryptoPrimitives.zero(candidate)
                    throw HeaderFormatException("Unwrapped file key has invalid size: ${candidate.size}")
                }
                unwrappedKey = candidate
                break
            }
        }

        val fileKey = unwrappedKey ?: throw NoMatchingIdentityException(
            "No identity matched any recipient stanza in the age header",
        )

        var payloadKey: ByteArray? = null
        try {
            val expectedMac = HeaderFormat.computeMac(stanzas, fileKey)
            if (!CryptoPrimitives.constantTimeEquals(expectedMac, parsed.header.mac)) {
                throw HeaderMacException("Invalid age header MAC")
            }

            val payloadNonce = ByteArray(PAYLOAD_NONCE_SIZE)
            val nonceRead = try {
                CryptoPrimitives.readFullyCompat(parsed.remaining, payloadNonce)
            } catch (e: ArmorFormatException) {
                throw e
            } catch (e: IOException) {
                throw HeaderFormatException("Failed to read payload nonce", e)
            }
            if (nonceRead < PAYLOAD_NONCE_SIZE) {
                throw HeaderFormatException("Truncated payload nonce")
            }

            payloadKey = CryptoPrimitives.hkdfSha256(
                ikm = fileKey,
                salt = payloadNonce,
                info = PAYLOAD_INFO,
                length = 32,
            )
            return StreamDecryptInputStream(
                src = parsed.remaining,
                fileKey = CryptoPrimitives.EMPTY_BYTES,
                preDerivedPayloadKey = payloadKey,
            )
        } finally {
            CryptoPrimitives.zero(fileKey)
            CryptoPrimitives.zero(payloadKey)
        }
    }

    /**
     * Convenience vararg overload for binary decryption.
     */
    @JvmStatic
    @Throws(AgeException::class, IOException::class)
    public fun decrypt(input: InputStream, vararg identities: Identity): InputStream {
        return decrypt(input, identities.toList())
    }

    /**
     * Convenience entry point for decrypting ASCII-armored `age` input streams.
     */
    @JvmStatic
    @Throws(AgeException::class, IOException::class)
    public fun decryptArmored(
        input: InputStream,
        identities: List<Identity>,
    ): InputStream = decrypt(input, identities, armor = true)

    /**
     * Decrypts [ciphertext] in memory using [identities].
     */
    @JvmStatic
    @JvmOverloads
    @Throws(AgeException::class, IOException::class)
    public fun decryptBytes(
        ciphertext: ByteArray,
        identities: List<Identity>,
        armor: Boolean = false,
    ): ByteArray {
        decrypt(ByteArrayInputStream(ciphertext), identities, armor).use { stream ->
            val capacity = if (armor) {
                Armor.decodedSizeBound(ciphertext.size)
            } else {
                ciphertext.size
            }
            return CryptoPrimitives.readAllCompat(stream, capacity)
        }
    }

    /**
     * Decrypts an ASCII-armored `age` string in memory using [identities].
     */
    @JvmStatic
    @Throws(AgeException::class, IOException::class)
    public fun decryptArmoredString(
        armoredCiphertext: String,
        identities: List<Identity>,
    ): ByteArray {
        return decryptBytes(
            ciphertext = armoredCiphertext.toByteArray(StandardCharsets.UTF_8),
            identities = identities,
            armor = true,
        )
    }

    /**
     * Parses a single Bech32-encoded native recipient string (`age1...` or `age1pq1...`).
     */
    @JvmStatic
    @Throws(KeyFormatException::class)
    public fun parseRecipient(
        encoded: String,
    ): Recipient {
        return when {
            encoded.startsWith("age1pq1") -> HybridRecipient.parse(encoded)
            encoded.startsWith("age1") -> X25519Recipient.parse(encoded)
            else -> throw KeyFormatException("Unknown age recipient type")
        }
    }

    /**
     * Parses a single Bech32-encoded native identity string (`AGE-SECRET-KEY-1...` or
     * `AGE-SECRET-KEY-PQ-1...`).
     */
    @JvmStatic
    @Throws(KeyFormatException::class)
    public fun parseIdentity(
        encoded: String,
    ): Identity {
        return when {
            encoded.startsWith("AGE-SECRET-KEY-PQ-1") -> HybridIdentity.parse(encoded)
            encoded.startsWith("AGE-SECRET-KEY-1") -> X25519Identity.parse(encoded)
            else -> throw KeyFormatException("Unknown age identity type")
        }
    }

    /**
     * Parses a recipient file containing one recipient per line, ignoring empty lines and `#`
     * comment lines.
     */
    @JvmStatic
    @Throws(KeyFormatException::class, IOException::class)
    public fun parseRecipients(
        reader: Reader,
    ): List<Recipient> {
        val lines = readKeyFileLines(reader, "recipients")
        val recipients = ArrayList<Recipient>()
        for ((lineNumber, line) in lines) {
            try {
                recipients.add(parseRecipient(line))
            } catch (e: KeyFormatException) {
                throw KeyFormatException("Invalid recipient at line $lineNumber: ${e.message}", e)
            }
        }
        if (recipients.isEmpty()) {
            throw KeyFormatException("No recipients found")
        }
        return recipients
    }

    /**
     * Parses a multi-line recipients string, ignoring empty lines and `#` comment lines.
     */
    @JvmStatic
    @Throws(KeyFormatException::class)
    public fun parseRecipients(
        text: String,
    ): List<Recipient> {
        return parseRecipients(StringReader(text))
    }

    /**
     * Parses an identity file containing one secret key per line, ignoring empty lines and `#`
     * comment lines (compatible with `age-keygen` output).
     *
     * If any line fails to parse, all previously parsed identities are closed before throwing.
     */
    @JvmStatic
    @Throws(KeyFormatException::class, IOException::class)
    public fun parseIdentities(
        reader: Reader,
    ): List<Identity> {
        val lines = readKeyFileLines(reader, "identities")
        val identities = ArrayList<Identity>()
        try {
            for ((lineNumber, line) in lines) {
                try {
                    identities.add(parseIdentity(line))
                } catch (e: KeyFormatException) {
                    throw KeyFormatException("Invalid identity at line $lineNumber", e)
                }
            }
            if (identities.isEmpty()) {
                throw KeyFormatException("No identities found")
            }
            return identities
        } catch (t: Throwable) {
            for (id in identities) {
                if (id is Closeable) {
                    try {
                        id.close()
                    } catch (_: Throwable) {
                        // Best-effort cleanup of sensitive key material.
                    }
                }
            }
            throw t
        }
    }

    /**
     * Parses a multi-line identities string, ignoring empty lines and `#` comment lines.
     */
    @JvmStatic
    @Throws(KeyFormatException::class)
    public fun parseIdentities(
        text: String,
    ): List<Identity> {
        return parseIdentities(StringReader(text))
    }

    private fun orderNativeIdentitiesFirst(identities: List<Identity>): List<Identity> {
        val native = ArrayList<Identity>(identities.size)
        val custom = ArrayList<Identity>()
        for (id in identities) {
            if (id is X25519Identity || id is HybridIdentity || id is ScryptIdentity) {
                native.add(id)
            } else {
                custom.add(id)
            }
        }
        if (custom.isEmpty() || native.isEmpty()) {
            return identities
        }
        native.addAll(custom)
        return native
    }

    private fun readKeyFileLines(reader: Reader, label: String): List<Pair<Int, String>> {
        val entries = ArrayList<Pair<Int, String>>()
        val line = StringBuilder()
        val buf = CharArray(4096)
        var lineNumber = 1
        var isComment = false
        var totalChars = 0
        var totalBytes = 0
        var pendingSurrogate = false
        var malformed = false

        fun finishLine() {
            val end = if (line.lastOrNull() == '\r') {
                line.length - 1
            } else {
                line.length
            }
            if (end != 0) {
                entries.add(lineNumber to line.substring(0, end))
            }
            line.setLength(0)
            lineNumber++
            isComment = false
        }

        while (true) {
            val n = reader.read(buf)
            if (n < 0) break
            totalChars += n
            if (totalChars > KEY_FILE_LIMIT_BYTES) {
                throw KeyFormatException("$label file exceeds maximum allowed size")
            }

            // Validate all input, including comments. A surrogate pair may straddle reads.
            totalBytes += n
            for (i in 0 until n) {
                val char = buf[i]
                if (pendingSurrogate) {
                    if (char.isLowSurrogate()) {
                        totalBytes += 2
                        pendingSurrogate = false
                        continue
                    }
                    malformed = true
                    pendingSurrogate = false
                }
                when {
                    char <= '\u007f' -> Unit
                    char <= '\u07ff' -> totalBytes++
                    char.isHighSurrogate() -> pendingSurrogate = true
                    char.isLowSurrogate() -> malformed = true
                    else -> totalBytes += 2
                }
            }

            var start = 0
            for (i in 0 until n) {
                if (buf[i] == '\n') {
                    if (!isComment && start < i && (line.isNotEmpty() || buf[start] != '#')) {
                        line.appendRange(buf, start, i)
                    }
                    finishLine()
                    start = i + 1
                }
            }
            if (start < n && !isComment) {
                if (line.isEmpty() && buf[start] == '#') {
                    isComment = true
                } else {
                    line.appendRange(buf, start, n)
                }
            }
        }

        if (malformed || pendingSurrogate) {
            throw KeyFormatException(
                "$label file contains invalid UTF-16/UTF-8 characters",
                MalformedInputException(1),
            )
        }
        if (totalBytes > KEY_FILE_LIMIT_BYTES) {
            throw KeyFormatException("$label file exceeds maximum allowed size")
        }
        finishLine()
        return entries
    }
}
