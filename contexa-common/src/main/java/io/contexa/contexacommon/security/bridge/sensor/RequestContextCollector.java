package io.contexa.contexacommon.security.bridge.sensor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.time.Instant;
import java.util.UUID;

public class RequestContextCollector {

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
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return request.getRemoteAddr();
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
