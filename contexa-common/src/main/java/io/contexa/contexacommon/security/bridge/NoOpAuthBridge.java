package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Default no-op bridge used in FULL mode. Always returns null (no bridging needed).
 * In FULL mode, Contexa manages authentication directly.
 */
public class NoOpAuthBridge implements AuthBridge {

    @Override
    public BridgedUser extractUser(HttpServletRequest request) {
        return null;
    }
}
