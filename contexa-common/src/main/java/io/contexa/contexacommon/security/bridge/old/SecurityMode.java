package io.contexa.contexacommon.security.bridge.old;

/**
 * Determines how Contexa integrates with the host application's security.
 */
public enum SecurityMode {

    /**
     * Contexa manages the entire authentication and authorization lifecycle.
     * Suitable for new projects where Contexa is the primary security provider.
     */
    FULL,

    /**
     * Contexa operates as a sandbox alongside existing legacy security.
     * Legacy authentication is bridged via {@link AuthBridge}.
     * Only {@code @Protectable} resources are protected by Contexa.
     * Legacy security remains completely untouched.
     */
    SANDBOX
}
