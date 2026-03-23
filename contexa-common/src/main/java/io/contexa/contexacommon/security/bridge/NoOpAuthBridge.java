package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;

public class NoOpAuthBridge implements AuthBridge {

    @Override
    public BridgedUser extractUser(HttpServletRequest request) {
        return null;
    }
}
