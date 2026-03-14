package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacore.properties.TieredStrategyProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.net.InetAddress;
import java.util.List;
import java.util.UUID;

@Slf4j
public final class RequestInfoExtractor {

    private RequestInfoExtractor() {

    }

    public static RequestInfo extract(HttpServletRequest request, TieredStrategyProperties.Security security) {
        if (request == null) {
            return null;
        }

        return RequestInfo.builder()
                .requestUri(request.getRequestURI())
                .method(request.getMethod())
                .clientIp(extractClientIp(request, security))
                .userAgent(extractUserAgent(request))
                .sessionId(request.getRequestedSessionId())
                .requestId(extractRequestId(request))
                .servletPath(request.getServletPath())
                .queryString(request.getQueryString())
                .remoteHost(request.getRemoteHost())
                .protocol(request.getProtocol())
                .secure(request.isSecure())
                .isNewSession((Boolean) request.getAttribute("hcad.is_new_session"))
                .isNewUser((Boolean) request.getAttribute("hcad.is_new_user"))
                .isNewDevice((Boolean) request.getAttribute("hcad.is_new_device"))
                .recentRequestCount((Integer) request.getAttribute("hcad.recent_request_count"))
                .failedLoginAttempts(castToInteger(request.getAttribute("hcad.failed_login_attempts")))
                .baselineConfidence(castToDouble(request.getAttribute("hcad.baseline_confidence")))
                .isSensitiveResource((Boolean) request.getAttribute("hcad.is_sensitive_resource"))
                .mfaVerified(castToBoolean(request.getAttribute("hcad.mfa_verified")))
                .userRoles((String) request.getAttribute("hcad.user_roles"))
                .geoCountry((String) request.getAttribute("hcad.country"))
                .geoCity((String) request.getAttribute("hcad.city"))
                .geoLatitude(castToDouble(request.getAttribute("hcad.latitude")))
                .geoLongitude(castToDouble(request.getAttribute("hcad.longitude")))
                .impossibleTravel(castToBoolean(request.getAttribute("hcad.impossibleTravel")))
                .travelDistanceKm(castToInteger(request.getAttribute("hcad.travelDistanceKm")))
                .travelElapsedMinutes(castToInteger(request.getAttribute("hcad.travelElapsedMinutes")))
                .previousLocation((String) request.getAttribute("hcad.previousLocation"))
                .build();
    }

    public static String extractClientIp(HttpServletRequest request, TieredStrategyProperties.Security security) {
        String remoteAddr = request.getRemoteAddr();

        if (security == null || !security.isTrustedProxyValidationEnabled()) {
            return extractClientIpLegacy(request);
        }

        List<String> trustedProxies = security.getTrustedProxies();

        if (trustedProxies == null || trustedProxies.isEmpty()) {
            return remoteAddr;
        }

        if (isTrustedProxy(remoteAddr, trustedProxies)) {

            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                String clientIp = xForwardedFor.split(",")[0].trim();
                return clientIp;
            }

            String xRealIp = request.getHeader("X-Real-IP");
            if (xRealIp != null && !xRealIp.isEmpty()) {
                return xRealIp;
            }
        }

        return remoteAddr;
    }

    public static String extractUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "unknown";
    }

    public static String extractRequestId(HttpServletRequest request) {
        String requestId = request.getHeader("X-Request-ID");
        return (requestId != null && !requestId.isEmpty()) ?
                requestId : UUID.randomUUID().toString();
    }

    private static String extractClientIpLegacy(HttpServletRequest request) {
        return SessionFingerprintUtil.extractClientIp(request);
    }

    private static boolean isTrustedProxy(String ip, List<String> trustedProxies) {
        if (ip == null || trustedProxies == null) {
            return false;
        }

        for (String trusted : trustedProxies) {
            if (trusted == null || trusted.isEmpty()) {
                continue;
            }

            try {
                if (trusted.contains("/")) {
                    if (isIpInCidr(ip, trusted)) {
                        return true;
                    }
                } else {
                    if (trusted.equals(ip)) {
                        return true;
                    }
                }
            } catch (Exception e) {
                log.error("[RequestInfoExtractor] Invalid trusted proxy format: {}", trusted, e);
            }
        }

        return false;
    }

    private static boolean isIpInCidr(String ip, String cidr) {
        try {
            String[] parts = cidr.split("/");
            if (parts.length != 2) {
                return false;
            }

            String networkAddress = parts[0];
            int prefixLength = Integer.parseInt(parts[1]);

            InetAddress inetIp = InetAddress.getByName(ip);
            InetAddress inetNetwork = InetAddress.getByName(networkAddress);

            byte[] ipBytes = inetIp.getAddress();
            byte[] networkBytes = inetNetwork.getAddress();

            if (ipBytes.length != networkBytes.length) {
                return false;
            }

            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;

            for (int i = 0; i < fullBytes; i++) {
                if (ipBytes[i] != networkBytes[i]) {
                    return false;
                }
            }

            if (remainingBits > 0 && fullBytes < ipBytes.length) {
                int mask = (0xFF << (8 - remainingBits)) & 0xFF;
                return (ipBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Builder
    @Getter
    public static class RequestInfo {
        private final String requestUri;
        private final String method;
        private final String clientIp;
        private final String userAgent;
        private final String sessionId;
        private final String requestId;
        private final String servletPath;
        private final String queryString;
        private final String remoteHost;
        private final String protocol;
        private final boolean secure;

        private final Boolean isNewSession;
        private final Boolean isNewUser;
        private final Boolean isNewDevice;
        private final Integer recentRequestCount;
        private final Integer failedLoginAttempts;
        private final Double baselineConfidence;
        private final Boolean isSensitiveResource;
        private final Boolean mfaVerified;
        private final String userRoles;

        private final String geoCountry;
        private final String geoCity;
        private final Double geoLatitude;
        private final Double geoLongitude;

        private final Boolean impossibleTravel;
        private final Integer travelDistanceKm;
        private final Integer travelElapsedMinutes;
        private final String previousLocation;
    }

    private static Integer castToInteger(Object value) {
        if (value instanceof Integer) return (Integer) value;
        if (value instanceof Number) return ((Number) value).intValue();
        return null;
    }

    private static Double castToDouble(Object value) {
        if (value instanceof Double) return (Double) value;
        if (value instanceof Number) return ((Number) value).doubleValue();
        return null;
    }

    private static Boolean castToBoolean(Object value) {
        if (value instanceof Boolean) return (Boolean) value;
        return null;
    }
}
