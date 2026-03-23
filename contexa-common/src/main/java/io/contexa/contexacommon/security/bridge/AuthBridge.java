package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;

public interface AuthBridge {

    BridgedUser extractUser(HttpServletRequest request);
}
