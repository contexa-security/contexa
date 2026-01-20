package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.net.InetAddress;
import java.util.List;
import java.util.UUID;

/**
 * HTTP 요청 정보 추출 유틸리티
 *
 * AI Native v13.0: AuthorizationEventPublisher.RequestInfo를 독립 클래스로 분리
 *
 * 기능:
 * - HTTP 요청에서 보안 관련 정보 추출
 * - Trusted Proxy 검증을 통한 X-Forwarded-For 스푸핑 방지
 * - Zero Trust 분석에 필요한 컨텍스트 정보 제공
 *
 * @author contexa
 * @since 4.0.0
 */
@Slf4j
public final class RequestInfoExtractor {

    private RequestInfoExtractor() {
        // 유틸리티 클래스 - 인스턴스화 방지
    }

    /**
     * HttpServletRequest에서 RequestInfo 추출
     *
     * @param request HTTP 요청
     * @param security 보안 설정 (Trusted Proxy 목록 등)
     * @return RequestInfo 객체
     */
    public static RequestInfo extract(HttpServletRequest request, TieredStrategyProperties.Security security) {
        if (request == null) {
            return null;
        }

        return RequestInfo.builder()
                .requestUri(request.getRequestURI())
                .method(request.getMethod())
                .clientIp(extractClientIp(request, security))
                .userAgent(extractUserAgent(request))
                .sessionId(request.getSession(false) != null ?
                        request.getSession(false).getId() : null)
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
                .build();
    }

    /**
     * 클라이언트 IP 추출 (Trusted Proxy 검증 포함)
     *
     * Zero Trust 원칙:
     * - 신뢰할 수 있는 프록시에서만 X-Forwarded-For 헤더 사용
     * - 비신뢰 소스의 X-Forwarded-For는 무시 (스푸핑 방지)
     */
    public static String extractClientIp(HttpServletRequest request, TieredStrategyProperties.Security security) {
        String remoteAddr = request.getRemoteAddr();

        if (security == null || !security.isTrustedProxyValidationEnabled()) {
            return extractClientIpLegacy(request);
        }

        List<String> trustedProxies = security.getTrustedProxies();

        // 신뢰 프록시 목록이 비어있으면 X-Forwarded-For 사용 안 함 (가장 안전)
        if (trustedProxies == null || trustedProxies.isEmpty()) {
            log.debug("[RequestInfoExtractor] No trusted proxies configured, using remoteAddr: {}", remoteAddr);
            return remoteAddr;
        }

        // remoteAddr이 신뢰 프록시 목록에 있는지 확인
        if (isTrustedProxy(remoteAddr, trustedProxies)) {
            // 신뢰 프록시에서 온 요청 -> X-Forwarded-For 사용
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                String clientIp = xForwardedFor.split(",")[0].trim();
                log.debug("[RequestInfoExtractor] Trusted proxy {}, using X-Forwarded-For: {}", remoteAddr, clientIp);
                return clientIp;
            }

            String xRealIp = request.getHeader("X-Real-IP");
            if (xRealIp != null && !xRealIp.isEmpty()) {
                log.debug("[RequestInfoExtractor] Trusted proxy {}, using X-Real-IP: {}", remoteAddr, xRealIp);
                return xRealIp;
            }
        } else {
            // 신뢰 프록시가 아닌 곳에서 온 요청 -> remoteAddr 사용
            // X-Forwarded-For가 있어도 무시 (스푸핑 방지)
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                log.warn("[RequestInfoExtractor] Untrusted source {} sent X-Forwarded-For header (ignored): {}",
                        remoteAddr, xForwardedFor);
            }
        }

        return remoteAddr;
    }

    /**
     * User-Agent 추출
     */
    public static String extractUserAgent(HttpServletRequest request) {
        // 시뮬레이션용 헤더 우선 확인
        String userAgent = request.getHeader("X-Simulated-User-Agent");
        if (userAgent != null && !userAgent.isEmpty()) {
            return userAgent;
        }
        userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "unknown";
    }

    /**
     * 요청 ID 추출 (없으면 생성)
     */
    public static String extractRequestId(HttpServletRequest request) {
        String requestId = request.getHeader("X-Request-ID");
        return (requestId != null && !requestId.isEmpty()) ?
                requestId : UUID.randomUUID().toString();
    }

    // ========== Private 메서드 ==========

    private static String extractClientIpLegacy(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
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
                log.warn("[RequestInfoExtractor] Invalid trusted proxy format: {}", trusted, e);
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

            // IPv4와 IPv6 호환성 확인
            if (ipBytes.length != networkBytes.length) {
                return false;
            }

            // 네트워크 마스크 생성 및 비교
            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;

            // 전체 바이트 비교
            for (int i = 0; i < fullBytes; i++) {
                if (ipBytes[i] != networkBytes[i]) {
                    return false;
                }
            }

            // 남은 비트 비교
            if (remainingBits > 0 && fullBytes < ipBytes.length) {
                int mask = (0xFF << (8 - remainingBits)) & 0xFF;
                return (ipBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
            }

            return true;
        } catch (Exception e) {
            log.debug("[RequestInfoExtractor] CIDR check failed for ip={}, cidr={}: {}", ip, cidr, e.getMessage());
            return false;
        }
    }

    // ========== RequestInfo 데이터 클래스 ==========

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

        // Zero Trust 신호
        private final Boolean isNewSession;
        private final Boolean isNewUser;
        private final Boolean isNewDevice;
        private final Integer recentRequestCount;
    }
}
