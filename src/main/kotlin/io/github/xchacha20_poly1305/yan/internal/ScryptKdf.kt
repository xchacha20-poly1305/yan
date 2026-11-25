package io.github.xchacha20_poly1305.yan.internal

import org.bouncycastle.crypto.generators.SCrypt

internal object ScryptKdf {
    fun derive(passphraseUtf8: ByteArray, salt: ByteArray, workFactor: Int): ByteArray {
        require(workFactor in 1..30) { "Unsupported scrypt work factor: $workFactor" }
        return SCrypt.generate(passphraseUtf8, salt, 1 shl workFactor, 8, 1, 32)
    }
}
