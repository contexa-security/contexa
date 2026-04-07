package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageReport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.net.InetAddress;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Slf4j
public final class RequestInfoExtractor {
    private static final String REQUEST_ID_ATTRIBUTE = "contexa.requestId";
    private RequestInfoExtractor() {
    }
    public static RequestInfo extract(HttpServletRequest request, TieredStrategyProperties.Security security) {
        if (request == null) {
            return null;
        }

        String requestId = extractRequestId(request);
        String requestedModelId = firstNonBlankText(
                extractHeaderOrAttribute(request, "X-Contexa-Model-Id", "requestedModelId"),
                extractHeaderOrAttribute(request, "X-Contexa-Preferred-Model", "preferredModel"),
                extractHeaderOrAttribute(request, "X-Contexa-Runtime-Model-Id", "runtimeModelId"));
        Double runtimeTemperature = extractDoubleHeaderOrAttribute(request, "X-Contexa-Temperature", "temperature", "runtimeTemperature");
        Double runtimeTopP = extractDoubleHeaderOrAttribute(request, "X-Contexa-Top-P", "topP", "runtimeTopP");
        Integer runtimeSeed = extractIntegerHeaderOrAttribute(request, "X-Contexa-Seed", "seed", "runtimeSeed");
        Integer runtimeMaxTokens = extractIntegerHeaderOrAttribute(request, "X-Contexa-Max-Tokens", "maxTokens", "runtimeMaxTokens");
        Boolean runtimeDisableRetries = extractBooleanHeaderOrAttribute(request, "X-Contexa-Disable-Retries", "disableRetries");
        Boolean runtimeDisableOllamaThinking = extractBooleanHeaderOrAttribute(request, "X-Contexa-Disable-Ollama-Thinking", "disableOllamaThinking");
        String decisionBoundaryMode = deriveDecisionBoundaryMode(
                request,
                requestedModelId,
                runtimeTemperature,
                runtimeTopP,
                runtimeSeed,
                runtimeMaxTokens,
                runtimeDisableRetries,
                runtimeDisableOllamaThinking);

        return RequestInfo.builder()
                .requestUri(request.getRequestURI())
                .method(request.getMethod())
                .clientIp(extractClientIp(request, security))
                .userAgent(extractUserAgent(request))
                .sessionId(OfficialVerificationRequestContext.resolveSessionId(request))
                .requestId(requestId)
                .requestedModelId(requestedModelId)
                .observedAt(extractObservedAt(request))
                .servletPath(request.getServletPath())
                .queryString(request.getQueryString())
                .remoteHost(request.getRemoteHost())
                .protocol(request.getProtocol())
                .scenario(extractScenario(request))
                .demoRunId(extractHeader(request, "X-Contexa-Demo-Run-Id"))
                .demoPhase(extractHeader(request, "X-Contexa-Demo-Phase"))
                .roundKey(extractHeader(request, "X-Contexa-Round-Key"))
                .behaviorPhase(extractHeader(request, "X-Contexa-Behavior-Phase"))
                .anomalySignal(extractHeader(request, "X-Contexa-Anomaly-Signal"))
                .promptBudgetProfile(extractHeader(request, "X-Contexa-Prompt-Budget-Profile"))
                .decisionBoundaryMode(decisionBoundaryMode)
                .runtimeTemperature(runtimeTemperature)
                .runtimeTopP(runtimeTopP)
                .runtimeSeed(runtimeSeed)
                .runtimeMaxTokens(runtimeMaxTokens)
                .runtimeDisableRetries(runtimeDisableRetries)
                .runtimeDisableOllamaThinking(runtimeDisableOllamaThinking)
                .simulatedUserAgentLabel(extractHeader(request, "X-Simulated-User-Agent-Label"))
                .secure(request.isSecure())
                .isNewSession((Boolean) request.getAttribute("hcad.is_new_session"))
                .isNewUser((Boolean) request.getAttribute("hcad.is_new_user"))
                .isNewDevice((Boolean) request.getAttribute("hcad.is_new_device"))
                .recentRequestCount((Integer) request.getAttribute("hcad.recent_request_count"))
                .failedLoginAttempts(castToInteger(request.getAttribute("hcad.failed_login_attempts")))
                .baselineConfidence(castToDouble(request.getAttribute("hcad.baseline_confidence")))
                .isSensitiveResource((Boolean) request.getAttribute("hcad.is_sensitive_resource"))
                .authMethod(extractAttributeText(request,
                        "hcad.auth_method",
                        "hcad.authMethod",
                        "authMethod"))
                .resourceSensitivity(extractAttributeText(request,
                        "hcad.resource_sensitivity",
                        "hcad.resourceSensitivity",
                        "resourceSensitivity",
                        "sensitivity"))
                .resourceBusinessLabel(extractAttributeText(request,
                        "hcad.resource_business_label",
                        "hcad.resourceBusinessLabel",
                        "resourceLabel",
                        "businessLabel"))
                .resourceId(extractAttributeText(request,
                        "hcad.resource_id",
                        "hcad.resourceId",
                        "resourceId",
                        "requestedResourceId",
                        "protectedResourceId"))
                .mfaVerified(castToBoolean(request.getAttribute("hcad.mfa_verified")))
                .previousPath(extractAttributeText(request,
                        "hcad.previous_path",
                        "hcad.previousPath",
                        "previousPath"))
                .lastRequestIntervalMs(castToLong(
                        firstNonNullAttribute(request,
                                "hcad.last_request_interval_ms",
                                "hcad.lastRequestIntervalMs",
                                "lastRequestIntervalMs")))
                .userRoles((String) request.getAttribute("hcad.user_roles"))
                .geoCountry((String) request.getAttribute("hcad.country"))
                .geoCity((String) request.getAttribute("hcad.city"))
                .geoLatitude(castToDouble(request.getAttribute("hcad.latitude")))
                .geoLongitude(castToDouble(request.getAttribute("hcad.longitude")))
                .impossibleTravel(castToBoolean(request.getAttribute("hcad.impossibleTravel")))
                .travelDistanceKm(castToInteger(request.getAttribute("hcad.travelDistanceKm")))
                .travelElapsedMinutes(castToInteger(request.getAttribute("hcad.travelElapsedMinutes")))
                .previousLocation((String) request.getAttribute("hcad.previousLocation"))
                .bridgeResolutionResult(extractBridgeResolutionResult(request, security, requestId))
                .build();
    }

    private static BridgeResolutionResult extractBridgeResolutionResult(
            HttpServletRequest request,
            TieredStrategyProperties.Security security,
            String requestId) {
        Object rawResolutionResult = request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        if (rawResolutionResult instanceof BridgeResolutionResult bridgeResolutionResult) {
            return bridgeResolutionResult;
        }

        AuthenticationStamp authenticationStamp = request.getAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP) instanceof AuthenticationStamp stamp
                ? stamp
                : null;
        AuthorizationStamp authorizationStamp = request.getAttribute(BridgeRequestAttributes.AUTHORIZATION_STAMP) instanceof AuthorizationStamp stamp
                ? stamp
                : null;
        DelegationStamp delegationStamp = request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP) instanceof DelegationStamp stamp
                ? stamp
                : null;
        BridgeCoverageReport coverageReport = request.getAttribute(BridgeRequestAttributes.COVERAGE_REPORT) instanceof BridgeCoverageReport report
                ? report
                : null;

        if (authenticationStamp == null && authorizationStamp == null && delegationStamp == null && coverageReport == null) {
            return null;
        }

        RequestContextSnapshot requestContext = new RequestContextSnapshot(
                request.getRequestURI(),
                request.getMethod(),
                extractClientIp(request, security),
                extractUserAgent(request),
                OfficialVerificationRequestContext.resolveSessionId(request),
                requestId,
                request.getServletPath(),
                request.getQueryString(),
                request.isSecure(),
                extractObservedAt(request));
        return new BridgeResolutionResult(
                requestContext,
                authenticationStamp,
                authorizationStamp,
                delegationStamp,
                coverageReport);
    }

    public static Instant extractObservedAt(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        Instant fromAttribute = parseObservedAt(request.getAttribute("hcad.observed_at"));
        if (fromAttribute != null) {
            return fromAttribute;
        }

        Instant fromPrimaryHeader = parseObservedAt(request.getHeader("X-Contexa-Observed-At"));
        if (fromPrimaryHeader != null) {
            return fromPrimaryHeader;
        }

        return parseObservedAt(request.getHeader("X-Simulated-Observed-At"));
    }

    public static String extractClientIp(HttpServletRequest request, TieredStrategyProperties.Security security) {
        String remoteAddr = request.getRemoteAddr();

        if (isOfficialVerificationRequest(request)) {
            return extractClientIpLegacy(request);
        }

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

    private static boolean isOfficialVerificationRequest(HttpServletRequest request) {
        if (request == null) {
            return false;
        }
        String scenario = extractScenario(request);
        if (scenario != null && scenario.trim().toUpperCase(Locale.ROOT).startsWith("OFFICIAL_VERIFICATION")) {
            return true;
        }
        String path = request.getRequestURI();
        return path != null && path.contains("/admin/api/enterprise/verification/runtime/probe/");
    }

    public static String extractUserAgent(HttpServletRequest request) {
        // Test simulation header takes priority
        String simulated = request.getHeader("X-Simulated-User-Agent");
        if (simulated != null && !simulated.isEmpty()) {
            return simulated;
        }
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "unknown";
    }

    public static String extractRequestId(HttpServletRequest request) {
        Object existing = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        if (existing instanceof String text && !text.isBlank()) {
            return text;
        }
        String requestId = request.getHeader("X-Request-ID");
        String resolved = (requestId != null && !requestId.isEmpty())
                ? requestId
                : UUID.randomUUID().toString();
        request.setAttribute(REQUEST_ID_ATTRIBUTE, resolved);
        return resolved;
    }

    public static String extractScenario(HttpServletRequest request) {
        String scenario = request.getHeader("X-Contexa-Scenario");
        return (scenario != null && !scenario.isBlank()) ? scenario.trim() : null;
    }

    private static Instant parseObservedAt(Object rawValue) {
        if (rawValue == null) {
            return null;
        }
        if (rawValue instanceof Instant instant) {
            return instant;
        }
        if (rawValue instanceof OffsetDateTime offsetDateTime) {
            return offsetDateTime.toInstant();
        }
        if (rawValue instanceof LocalDateTime localDateTime) {
            return localDateTime.atZone(ZoneId.systemDefault()).toInstant();
        }

        String text = rawValue.toString();
        if (text == null || text.isBlank()) {
            return null;
        }

        try {
            return Instant.parse(text.trim());
        } catch (Exception ignored) {
        }

        try {
            return OffsetDateTime.parse(text.trim()).toInstant();
        } catch (Exception ignored) {
        }

        try {
            return LocalDateTime.parse(text.trim()).atZone(ZoneId.systemDefault()).toInstant();
        } catch (Exception ignored) {
        }

        if (text.trim().matches("-?\\d+")) {
            try {
                long epochValue = Long.parseLong(text.trim());
                return text.trim().length() > 10
                        ? Instant.ofEpochMilli(epochValue)
                        : Instant.ofEpochSecond(epochValue);
            } catch (Exception ignored) {
            }
        }

        return null;
    }

    private static String extractHeader(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        return (value != null && !value.isBlank()) ? value.trim() : null;
    }


    private static String extractHeaderOrAttribute(HttpServletRequest request, String headerName, String... attributeNames) {
        String value = extractHeader(request, headerName);
        if (value != null) {
            return value;
        }
        if (attributeNames == null) {
            return null;
        }
        for (String attributeName : attributeNames) {
            String attributeValue = extractAttributeText(request, attributeName);
            if (attributeValue != null) {
                return attributeValue;
            }
        }
        return null;
    }

    private static Double extractDoubleHeaderOrAttribute(HttpServletRequest request, String headerName, String... attributeNames) {
        String value = extractHeaderOrAttribute(request, headerName, attributeNames);
        if (value == null) {
            return null;
        }
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static String deriveDecisionBoundaryMode(
            HttpServletRequest request,
            String requestedModelId,
            Double runtimeTemperature,
            Double runtimeTopP,
            Integer runtimeSeed,
            Integer runtimeMaxTokens,
            Boolean runtimeDisableRetries,
            Boolean runtimeDisableOllamaThinking) {
        String explicitBoundaryMode = extractHeaderOrAttribute(
                request,
                "X-Contexa-Decision-Boundary-Mode",
                "decisionBoundaryMode");
        if (explicitBoundaryMode != null && !explicitBoundaryMode.isBlank()) {
            return explicitBoundaryMode;
        }
        if (requestedModelId != null
                || runtimeTemperature != null
                || runtimeTopP != null
                || runtimeSeed != null
                || runtimeMaxTokens != null
                || runtimeDisableRetries != null
                || runtimeDisableOllamaThinking != null) {
            return "RUNTIME_MODEL_SELECTION";
        }
        return null;
    }

    private static Integer extractIntegerHeaderOrAttribute(HttpServletRequest request, String headerName, String... attributeNames) {
        String value = extractHeaderOrAttribute(request, headerName, attributeNames);
        if (value == null) {
            return null;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static Double extractDoubleHeader(HttpServletRequest request, String name) {
        String value = extractHeader(request, name);
        if (value == null) {
            return null;
        }
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static Boolean extractBooleanHeaderOrAttribute(HttpServletRequest request, String headerName, String attributeName) {
        String value = extractHeaderOrAttribute(request, headerName, attributeName);
        if (value == null) {
            return null;
        }
        return Boolean.parseBoolean(value);
    }
    private static Integer extractIntegerHeader(HttpServletRequest request, String name) {
        String value = extractHeader(request, name);
        if (value == null) {
            return null;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static Boolean extractBooleanHeader(HttpServletRequest request, String name) {
        String value = extractHeader(request, name);
        if (value == null) {
            return null;
        }
        return Boolean.parseBoolean(value);
    }

    private static String firstNonBlankText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private static String extractAttributeText(HttpServletRequest request, String... names) {
        if (request == null || names == null) {
            return null;
        }
        for (String name : names) {
            Object value = request.getAttribute(name);
            if (value == null) {
                continue;
            }
            if (value instanceof String text) {
                if (!text.isBlank()) {
                    return text.trim();
                }
                continue;
            }
            String text = String.valueOf(value);
            if (!text.isBlank()) {
                return text.trim();
            }
        }
        return null;
    }

    private static Object firstNonNullAttribute(HttpServletRequest request, String... names) {
        if (request == null || names == null) {
            return null;
        }
        for (String name : names) {
            Object value = request.getAttribute(name);
            if (value != null) {
                return value;
            }
        }
        return null;
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
        private final String requestedModelId;
        private final Instant observedAt;
        private final String servletPath;
        private final String queryString;
        private final String remoteHost;
        private final String protocol;
        private final String scenario;
        private final String demoRunId;
        private final String demoPhase;
        private final String roundKey;
        private final String behaviorPhase;
        private final String anomalySignal;
        private final String promptBudgetProfile;
        private final String decisionBoundaryMode;
        private final Double runtimeTemperature;
        private final Double runtimeTopP;
        private final Integer runtimeSeed;
        private final Integer runtimeMaxTokens;
        private final Boolean runtimeDisableRetries;
        private final Boolean runtimeDisableOllamaThinking;
        private final String simulatedUserAgentLabel;
        private final boolean secure;

        private final Boolean isNewSession;
        private final Boolean isNewUser;
        private final Boolean isNewDevice;
        private final Integer recentRequestCount;
        private final Integer failedLoginAttempts;
        private final Double baselineConfidence;
        private final Boolean isSensitiveResource;
        private final String authMethod;
        private final String resourceSensitivity;
        private final String resourceBusinessLabel;
        private final String resourceId;
        private final Boolean mfaVerified;
        private final String previousPath;
        private final Long lastRequestIntervalMs;
        private final String userRoles;
        private final BridgeResolutionResult bridgeResolutionResult;

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

    private static Long castToLong(Object value) {
        if (value instanceof Long) return (Long) value;
        if (value instanceof Number) return ((Number) value).longValue();
        if (value instanceof String text && text.matches("-?\\d+")) {
            return Long.parseLong(text);
        }
        return null;
    }
}













