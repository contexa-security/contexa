package io.contexa.contexacommon.security.bridge.sensor;

import io.contexa.contexacommon.security.network.ClientIpResolutionPolicy;
import io.contexa.contexacommon.security.network.ClientIpResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public class RequestContextCollector {

    private final ClientIpResolutionPolicy clientIpResolutionPolicy;

    public RequestContextCollector() {
        this(ClientIpResolutionPolicy.trustedProxy(List.of()));
    }

    public RequestContextCollector(ClientIpResolutionPolicy clientIpResolutionPolicy) {
        this.clientIpResolutionPolicy = clientIpResolutionPolicy != null
                ? clientIpResolutionPolicy
                : ClientIpResolutionPolicy.trustedProxy(List.of());
    }

    public RequestContextSnapshot collect(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return new RequestContextSnapshot(
                request.getRequestURI(),
                request.getMethod(),
                extractClientIp(request),
                extractUserAgent(request),
                session != null ? session.getId() : request.getRequestedSessionId(),
                extractRequestId(request),
                request.getServletPath(),
                request.getQueryString(),
                request.isSecure(),
                Instant.now()
        );
    }

    private String extractClientIp(HttpServletRequest request) {
        return ClientIpResolver.resolve(request, clientIpResolutionPolicy);
    }

    private String extractUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "unknown";
    }

    private String extractRequestId(HttpServletRequest request) {
        String requestId = request.getHeader("X-Request-ID");
        return (requestId != null && !requestId.isBlank()) ? requestId : UUID.randomUUID().toString();
    }
}
