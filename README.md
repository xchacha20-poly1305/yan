# Module yan

A young and naive Kotlin implementation of the [C2SP age](https://c2sp.org/age) (`age-encryption.org/v1`) encryption specification for JVM 8+ and Android API 21+, backed by Bouncy Castle.

## Supported Features

- **Post-quantum hybrid (`mlkem768x25519` / X-Wing)**: `HybridIdentity` / `HybridRecipient` (`AGE-SECRET-KEY-PQ-1...` / `age1pq1...`) via Bouncy Castle X-Wing HPKE.
- **X25519**: `X25519Identity` / `X25519Recipient` (`AGE-SECRET-KEY-1...` / `age1...`).
- **Passphrase (`scrypt`)**: `ScryptIdentity` / `ScryptRecipient`, using the RFC 7914 scrypt implementation in Bouncy Castle.
- **Streaming encryption & decryption**: 64 KiB ChaCha20-Poly1305 STREAM chunks via `java.io.InputStream` / `OutputStream` and `ByteArray` convenience APIs.
- **Strict ASCII armor**: RFC 7468 PEM encoding/decoding (`AGE ENCRYPTED FILE`) via `Armor` or `armor = true`.
- **Extensible recipient/identity interfaces**: Open `Recipient`, `Identity`, and `Stanza` types (external `age-plugin` subprocess protocol is not included).

## Gradle Setup

The same artifact works on JVM and Android. It brings in the Bouncy Castle lightweight implementation as a runtime dependency.

Use `mavenCentral()` in your Gradle repositories and choose either dependency declaration below.

### Version catalog

Add these entries to `gradle/libs.versions.toml`.

```toml
[versions]
yan = "0.1.1"

[libraries]
yan = { module = "io.github.xchacha20-poly1305:yan", version.ref = "yan" }
```

Then add the library in your module's `build.gradle.kts`.

```kotlin
dependencies {
    implementation(libs.yan)
}
```

### Direct dependency

In your module's `build.gradle.kts`, specify the version with the dependency.

```kotlin
dependencies {
    implementation("io.github.xchacha20-poly1305:yan:0.1.1")
}
```

## Quick Example

```kotlin
import io.github.xchacha20_poly1305.yan.Age
import io.github.xchacha20_poly1305.yan.HybridIdentity
import io.github.xchacha20_poly1305.yan.ScryptIdentity
import io.github.xchacha20_poly1305.yan.ScryptRecipient

HybridIdentity.generate().use { identity ->
    val ciphertext = Age.encryptToArmoredString(
        plaintext = "hello post-quantum age".toByteArray(),
        recipients = listOf(identity.recipient),
    )
    val plaintext = Age.decryptArmoredString(ciphertext, listOf(identity))
}

ScryptRecipient("correct horse battery staple").use { recipient ->
    val encrypted = Age.encryptBytes("secret".toByteArray(), listOf(recipient))
    ScryptIdentity("correct horse battery staple").use { id ->
        val decrypted = Age.decryptBytes(encrypted, listOf(id))
    }
}
```
