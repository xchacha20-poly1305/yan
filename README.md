# yan

A Kotlin implementation of the [C2SP age](https://c2sp.org/age) (`age-encryption.org/v1`) encryption specification for JVM 8+ and Android API 21+, backed by Conscrypt 2.10.0.

## Supported Features

- **Post-quantum hybrid (`mlkem768x25519` / X-Wing)**: `HybridIdentity` / `HybridRecipient` (`AGE-SECRET-KEY-PQ-1...` / `age1pq1...`) via Conscrypt 2.10.0 `XWING` HPKE.
- **X25519**: `X25519Identity` / `X25519Recipient` (`AGE-SECRET-KEY-1...` / `age1...`).
- **Passphrase (`scrypt`)**: `ScryptIdentity` / `ScryptRecipient`, using Conscrypt native `SCRYPT` for `workFactor <= 18` and an RFC 7914 Kotlin fallback for `19..maxWorkFactor` (default `22`).
- **Streaming encryption & decryption**: 64 KiB ChaCha20-Poly1305 STREAM chunks via `java.io.InputStream` / `OutputStream` and `ByteArray` convenience APIs.
- **Strict ASCII armor**: RFC 7468 PEM encoding/decoding (`AGE ENCRYPTED FILE`) via `Armor` or `armor = true`.
- **Extensible recipient/identity interfaces**: Open `Recipient`, `Identity`, and `Stanza` types (external `age-plugin` subprocess protocol is not included).

## Gradle Setup

`yan` declares Conscrypt as `compileOnly` so both JVM and Android consumers can supply the matching Conscrypt artifact without dependency conflicts.

### JVM

```kotlin
dependencies {
    implementation("io.github.xchacha20-poly1305:yan:0.1.0-SNAPSHOT")
    implementation("org.conscrypt:conscrypt-openjdk-uber:2.10.0")
}
```

### Android (minSdk 21+)

```kotlin
dependencies {
    implementation("io.github.xchacha20-poly1305:yan:0.1.0-SNAPSHOT")
    implementation("org.conscrypt:conscrypt-android:2.10.0")
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
