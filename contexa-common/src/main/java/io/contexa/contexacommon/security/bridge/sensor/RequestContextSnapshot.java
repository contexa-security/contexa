package io.contexa.contexacommon.security.bridge.sensor;

import java.time.Instant;

public record RequestContextSnapshot(
        String requestUri,
        String method,
        String clientIp,
        String userAgent,
        String sessionId,
        String requestId,
        String servletPath,
        String queryString,
        boolean secure,
        Instant collectedAt
) {
}
