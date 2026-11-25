package io.github.xchacha20_poly1305.yan

import org.conscrypt.Conscrypt
import java.security.Provider

/**
 * Manages the Conscrypt [Provider] instance used by `yan` without mutating the global
 * `java.security.Security` provider list.
 */
public object AgeProvider {
    private val defaultInstance: Provider by lazy {
        Conscrypt.checkAvailability()
        Conscrypt.newProviderBuilder()
            .provideTrustManager(false)
            .build()
    }

    /**
     * Returns the shared, lazily initialized Conscrypt [Provider] instance.
     */
    @JvmStatic
    public fun defaultProvider(): Provider = defaultInstance

    internal fun requireConscrypt(provider: Provider): Provider {
        if (!Conscrypt.isConscrypt(provider)) {
            throw IllegalArgumentException(
                "Expected a Conscrypt security Provider, got ${provider.javaClass.name} (${provider.name})",
            )
        }
        return provider
    }
}
