package io.github.xchacha20_poly1305.yan

import io.github.xchacha20_poly1305.yan.internal.CryptoPrimitives
import io.github.xchacha20_poly1305.yan.internal.HeaderFormat
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
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.Provider

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
        provider: Provider = AgeProvider.defaultProvider(),
    ): OutputStream {
        AgeProvider.requireConscrypt(provider)
        require(recipients.isNotEmpty()) { "At least one recipient is required" }
        if (recipients.size > 1 && recipients.any { it is ScryptRecipient }) {
            throw IllegalArgumentException("ScryptRecipient cannot be mixed with other recipients")
        }

        val fileKey = CryptoPrimitives.randomBytes(FILE_KEY_SIZE, provider)
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

            val mac = HeaderFormat.computeMac(stanzas, fileKey, provider)
            val header = HeaderFormat.Header(stanzas, mac)
            val targetOut = if (armor) {
                Armor.wrap(output)
            } else {
                output
            }
            HeaderFormat.marshal(header, targetOut)
            return StreamEncryptOutputStream(targetOut, fileKey, provider)
        } finally {
            CryptoPrimitives.zero(fileKey)
        }
    }

    /**
     * Convenience vararg overload for binary encryption using the default Conscrypt provider.
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
        provider: Provider = AgeProvider.defaultProvider(),
    ): ByteArray {
        val out = ByteArrayOutputStream()
        encrypt(out, recipients, armor, provider).use {
            it.write(plaintext)
        }
        return out.toByteArray()
    }

    /**
     * Encrypts [plaintext] in memory and returns an ASCII-armored `age` PEM string.
     */
    @JvmStatic
    @JvmOverloads
    @Throws(AgeException::class, IOException::class)
    public fun encryptToArmoredString(
        plaintext: ByteArray,
        recipients: List<Recipient>,
        provider: Provider = AgeProvider.defaultProvider(),
    ): String {
        val armoredBytes = encryptBytes(
            plaintext = plaintext,
            recipients = recipients,
            armor = true,
            provider = provider
        )
        return String(armoredBytes, StandardCharsets.US_ASCII)
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
        provider: Provider = AgeProvider.defaultProvider(),
    ): InputStream {
        AgeProvider.requireConscrypt(provider)

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
            val expectedMac = HeaderFormat.computeMac(stanzas, fileKey, provider)
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
                provider = provider,
            )
            return StreamDecryptInputStream(
                src = parsed.remaining,
                fileKey = CryptoPrimitives.EMPTY_BYTES,
                provider = provider,
                preDerivedPayloadKey = payloadKey,
            )
        } finally {
            CryptoPrimitives.zero(fileKey)
            CryptoPrimitives.zero(payloadKey)
        }
    }

    /**
     * Convenience vararg overload for binary decryption using the default Conscrypt provider.
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
    @JvmOverloads
    @Throws(AgeException::class, IOException::class)
    public fun decryptArmored(
        input: InputStream,
        identities: List<Identity>,
        provider: Provider = AgeProvider.defaultProvider(),
    ): InputStream {
        return decrypt(input, identities, armor = true, provider = provider)
    }

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
        provider: Provider = AgeProvider.defaultProvider(),
    ): ByteArray {
        decrypt(ByteArrayInputStream(ciphertext), identities, armor, provider).use { stream ->
            return CryptoPrimitives.readAllCompat(stream)
        }
    }

    /**
     * Decrypts an ASCII-armored `age` string in memory using [identities].
     */
    @JvmStatic
    @JvmOverloads
    @Throws(AgeException::class, IOException::class)
    public fun decryptArmoredString(
        armoredCiphertext: String,
        identities: List<Identity>,
        provider: Provider = AgeProvider.defaultProvider(),
    ): ByteArray {
        return decryptBytes(
            ciphertext = armoredCiphertext.toByteArray(StandardCharsets.UTF_8),
            identities = identities,
            armor = true,
            provider = provider,
        )
    }

    /**
     * Parses a single Bech32-encoded native recipient string (`age1...` or `age1pq1...`).
     */
    @JvmStatic
    @JvmOverloads
    @Throws(KeyFormatException::class)
    public fun parseRecipient(
        encoded: String,
        provider: Provider = AgeProvider.defaultProvider(),
    ): Recipient {
        AgeProvider.requireConscrypt(provider)
        return when {
            encoded.startsWith("age1pq1") -> HybridRecipient.parse(encoded, provider)
            encoded.startsWith("age1") -> X25519Recipient.parse(encoded, provider)
            else -> throw KeyFormatException("Unknown age recipient type")
        }
    }

    /**
     * Parses a single Bech32-encoded native identity string (`AGE-SECRET-KEY-1...` or
     * `AGE-SECRET-KEY-PQ-1...`).
     */
    @JvmStatic
    @JvmOverloads
    @Throws(KeyFormatException::class)
    public fun parseIdentity(
        encoded: String,
        provider: Provider = AgeProvider.defaultProvider(),
    ): Identity {
        AgeProvider.requireConscrypt(provider)
        return when {
            encoded.startsWith("AGE-SECRET-KEY-PQ-1") -> HybridIdentity.parse(encoded, provider)
            encoded.startsWith("AGE-SECRET-KEY-1") -> X25519Identity.parse(encoded, provider)
            else -> throw KeyFormatException("Unknown age identity type")
        }
    }

    /**
     * Parses a recipient file containing one recipient per line, ignoring empty lines and `#`
     * comment lines.
     */
    @JvmStatic
    @JvmOverloads
    @Throws(KeyFormatException::class, IOException::class)
    public fun parseRecipients(
        reader: Reader,
        provider: Provider = AgeProvider.defaultProvider(),
    ): List<Recipient> {
        AgeProvider.requireConscrypt(provider)
        val lines = readKeyFileLines(reader, "recipients")
        val recipients = ArrayList<Recipient>()
        for ((lineNumber, line) in lines) {
            try {
                recipients.add(parseRecipient(line, provider))
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
    @JvmOverloads
    @Throws(KeyFormatException::class)
    public fun parseRecipients(
        text: String,
        provider: Provider = AgeProvider.defaultProvider(),
    ): List<Recipient> {
        return parseRecipients(StringReader(text), provider)
    }

    /**
     * Parses an identity file containing one secret key per line, ignoring empty lines and `#`
     * comment lines (compatible with `age-keygen` output).
     *
     * If any line fails to parse, all previously parsed identities are closed before throwing.
     */
    @JvmStatic
    @JvmOverloads
    @Throws(KeyFormatException::class, IOException::class)
    public fun parseIdentities(
        reader: Reader,
        provider: Provider = AgeProvider.defaultProvider(),
    ): List<Identity> {
        AgeProvider.requireConscrypt(provider)
        val lines = readKeyFileLines(reader, "identities")
        val identities = ArrayList<Identity>()
        try {
            for ((lineNumber, line) in lines) {
                try {
                    identities.add(parseIdentity(line, provider))
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
    @JvmOverloads
    @Throws(KeyFormatException::class)
    public fun parseIdentities(
        text: String,
        provider: Provider = AgeProvider.defaultProvider(),
    ): List<Identity> {
        return parseIdentities(StringReader(text), provider)
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
        val sb = StringBuilder()
        val buf = CharArray(4096)
        var totalChars = 0
        while (true) {
            val n = reader.read(buf)
            if (n < 0) break
            totalChars += n
            if (totalChars > KEY_FILE_LIMIT_BYTES) {
                throw KeyFormatException("$label file exceeds maximum allowed size")
            }
            sb.appendRange(buf, 0, n)
        }
        val content = sb.toString()
        validateUtf8Encodable(content, label)

        val entries = ArrayList<Pair<Int, String>>()
        var lineNumber = 1
        var lineStart = 0
        var i = 0
        while (i <= content.length) {
            val atEnd = i == content.length
            if (atEnd || content[i] == '\n') {
                var lineEnd = i
                if (lineEnd > lineStart && content[lineEnd - 1] == '\r') {
                    lineEnd--
                }
                if (lineEnd > lineStart) {
                    val line = content.substring(lineStart, lineEnd)
                    if (!line.startsWith("#")) {
                        entries.add(lineNumber to line)
                    }
                }
                lineStart = i + 1
                lineNumber++
            }
            i++
        }
        return entries
    }

    private fun validateUtf8Encodable(text: String, label: String) {
        val encoder = StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        try {
            encoder.encode(CharBuffer.wrap(text))
        } catch (e: CharacterCodingException) {
            throw KeyFormatException("$label file contains invalid UTF-16/UTF-8 characters", e)
        }
        val byteLen = text.toByteArray(StandardCharsets.UTF_8).size
        if (byteLen > KEY_FILE_LIMIT_BYTES) {
            throw KeyFormatException("$label file exceeds maximum allowed size")
        }
    }
}
