/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacommon.security.context.OfficialContextRequestAttributes;
import io.contexa.contexacommon.security.context.RequestSecurityContextAttributes;
import io.contexa.contexacommon.security.context.RequestSecurityContextAttributes.Field;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageReport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import io.contexa.contexacommon.security.network.ClientIpResolutionPolicy;
import io.contexa.contexacommon.security.network.ClientIpResolver;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

public final class RequestInfoExtractor {
    private static final String REQUEST_ID_ATTRIBUTE = "contexa.requestId";
    private RequestInfoExtractor() {
    }
    public static RequestInfo extract(HttpServletRequest request, TieredStrategyProperties.Security security) {
        if (request == null) {
            return null;
        }

        String requestId = extractRequestId(request);
        boolean runtimeOverrideHeadersAllowed = isOfficialVerificationRequest(request);
        String requestedModelId = firstNonBlankText(
                extractRuntimeHeaderOrAttribute(request, runtimeOverrideHeadersAllowed, "X-Contexa-Model-Id", "requestedModelId"),
                extractRuntimeHeaderOrAttribute(request, runtimeOverrideHeadersAllowed, "X-Contexa-Preferred-Model", "preferredModel"),
                extractRuntimeHeaderOrAttribute(request, runtimeOverrideHeadersAllowed, "X-Contexa-Runtime-Model-Id", "runtimeModelId"));
        Double runtimeTemperature = extractDoubleRuntimeHeaderOrAttribute(request, runtimeOverrideHeadersAllowed, "X-Contexa-Temperature", "temperature", "runtimeTemperature");
        Double runtimeTopP = extractDoubleRuntimeHeaderOrAttribute(request, runtimeOverrideHeadersAllowed, "X-Contexa-Top-P", "topP", "runtimeTopP");
        Integer runtimeSeed = extractIntegerRuntimeHeaderOrAttribute(request, runtimeOverrideHeadersAllowed, "X-Contexa-Seed", "seed", "runtimeSeed");
        Integer runtimeMaxTokens = extractIntegerRuntimeHeaderOrAttribute(request, runtimeOverrideHeadersAllowed, "X-Contexa-Max-Tokens", "maxTokens", "runtimeMaxTokens");
        Boolean runtimeDisableRetries = extractBooleanRuntimeHeaderOrAttribute(request, runtimeOverrideHeadersAllowed, "X-Contexa-Disable-Retries", "disableRetries");
        Boolean runtimeDisableOllamaThinking = extractBooleanRuntimeHeaderOrAttribute(request, runtimeOverrideHeadersAllowed, "X-Contexa-Disable-Ollama-Thinking", "disableOllamaThinking");
        Map<String, Object> officialContextFields = OfficialContextRequestAttributes.extractSnapshot(request);
        String authenticationType = castToText(officialContextFields.get("authenticationType"));
        String tenantId = firstNonBlankText(
                castToText(officialContextFields.get("tenantId")),
                authenticationStampAttribute(request, "tenantId", "tenant_id"));
        String organizationId = firstNonBlankText(
                castToText(officialContextFields.get("organizationId")),
                castToText(officialContextFields.get("orgId")),
                authenticationStampAttribute(request, "organizationId", "orgId"));
        String decisionBoundaryMode = deriveDecisionBoundaryMode(
                request,
                runtimeOverrideHeadersAllowed,
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
                .pqaPromptFaultScenario(extractAttributeText(request, "pqaPromptFaultScenario"))
                .pqaPromptFaultRejected(Boolean.TRUE.equals(request.getAttribute("pqaPromptFaultRejected"))
                        || extractHeader(request, "X-PQA-Prompt-Fault") != null)
                .pqaPromptFaultRejectedSource(extractAttributeText(request, "pqaPromptFaultRejectedSource") != null
                        ? extractAttributeText(request, "pqaPromptFaultRejectedSource")
                        : extractHeader(request, "X-PQA-Prompt-Fault") != null
                                ? "UNTRUSTED_REQUEST_HEADER"
                                : null)
                .decisionBoundaryMode(decisionBoundaryMode)
                .runtimeTemperature(runtimeTemperature)
                .runtimeTopP(runtimeTopP)
                .runtimeSeed(runtimeSeed)
                .runtimeMaxTokens(runtimeMaxTokens)
                .runtimeDisableRetries(runtimeDisableRetries)
                .runtimeDisableOllamaThinking(runtimeDisableOllamaThinking)
                .simulatedUserAgentLabel(extractHeader(request, "X-Simulated-User-Agent-Label"))
                .secure(request.isSecure())
                .isNewSession(castToBoolean(RequestSecurityContextAttributes.read(request, Field.NEW_SESSION)))
                .isNewUser(castToBoolean(RequestSecurityContextAttributes.read(request, Field.NEW_USER)))
                .isNewDevice(castToBoolean(RequestSecurityContextAttributes.read(request, Field.NEW_DEVICE)))
                .recentRequestCount(castToInteger(officialContextFields.get("recentRequestCount")))
                .failedLoginAttempts(castToInteger(officialContextFields.get("failedLoginAttempts")))
                .baselineConfidence(castToDouble(RequestSecurityContextAttributes.read(request, Field.BASELINE_CONFIDENCE)))
                .isSensitiveResource(castToBoolean(RequestSecurityContextAttributes.read(request, Field.SENSITIVE_RESOURCE)))
                .resourceSensitivity(castToText(RequestSecurityContextAttributes.read(request, Field.RESOURCE_SENSITIVITY)))
                .resourceBusinessLabel(castToText(RequestSecurityContextAttributes.read(request, Field.RESOURCE_BUSINESS_LABEL)))
                .resourceId(castToText(RequestSecurityContextAttributes.read(request, Field.RESOURCE_ID)))
                .currentResourceFamily(extractAttributeText(request,
                        "currentResourceFamily",
                        "current_resource_family"))
                .currentActionFamily(extractAttributeText(request,
                        "currentActionFamily",
                        "current_action_family"))
                .expectedResourceFamilies(extractAttributeStrings(request,
                        "expectedResourceFamilies",
                        "allowedResourceFamilies"))
                .expectedActionFamilies(extractAttributeStrings(request,
                        "expectedActionFamilies",
                        "allowedActionFamilies"))
                .recentPermissionChanges(extractAttributeStrings(request,
                        "recentPermissionChanges",
                        "permissionChangeEvents"))
                .approvalRequired(castToBoolean(firstNonNullAttribute(request,
                        "approvalRequired",
                        "approval_required")))
                .approvalGranted(castToBoolean(firstNonNullAttribute(request,
                        "approvalGranted",
                        "approval_granted")))
                .approvalMissing(castToBoolean(firstNonNullAttribute(request,
                        "approvalMissing",
                        "approval_missing")))
                .approvalStatus(extractAttributeText(request,
                        "approvalStatus",
                        "approval_status"))
                .delegated(castToBoolean(firstNonNullAttribute(request,
                        "delegated",
                        "isDelegated",
                        "agentDelegated")))
                .objectiveDrift(castToBoolean(firstNonNullAttribute(request,
                        "objectiveDrift",
                        "objective_drift",
                        "delegationObjectiveDrift")))
                .objectiveDriftSummary(extractAttributeText(request,
                        "objectiveDriftSummary",
                        "objective_drift_summary",
                        "delegationObjectiveDriftSummary"))
                .tenantId(tenantId)
                .organizationId(organizationId)
                .mfaVerified(castToBoolean(officialContextFields.get("mfaVerified")))
                .previousPath(castToText(RequestSecurityContextAttributes.read(request, Field.PREVIOUS_PATH)))
                .lastRequestIntervalMs(castToLong(RequestSecurityContextAttributes.read(request, Field.LAST_REQUEST_INTERVAL_MS)))
                .userRoles(castToText(RequestSecurityContextAttributes.read(request, Field.USER_ROLES)))
                .geoCountry(castToText(officialContextFields.get("country")))
                .geoCity(castToText(officialContextFields.get("city")))
                .geoLatitude(castToDouble(RequestSecurityContextAttributes.read(request, Field.GEO_LATITUDE)))
                .geoLongitude(castToDouble(RequestSecurityContextAttributes.read(request, Field.GEO_LONGITUDE)))
                .impossibleTravel(castToBoolean(officialContextFields.get("impossibleTravel")))
                .travelDistanceKm(castToInteger(RequestSecurityContextAttributes.read(request, Field.TRAVEL_DISTANCE_KM)))
                .travelElapsedMinutes(castToInteger(RequestSecurityContextAttributes.read(request, Field.TRAVEL_ELAPSED_MINUTES)))
                .previousLocation(castToText(RequestSecurityContextAttributes.read(request, Field.PREVIOUS_LOCATION)))
                .ipBand(castToText(officialContextFields.get("ipBand")))
                .asn(castToText(officialContextFields.get("asn")))
                .deviceOs(castToText(officialContextFields.get("deviceOs")))
                .deviceOsVersion(castToText(officialContextFields.get("deviceOsVersion")))
                .deviceBrowser(castToText(officialContextFields.get("deviceBrowser")))
                .deviceBrowserVersion(castToText(officialContextFields.get("deviceBrowserVersion")))
                .deviceScreenResolution(castToText(officialContextFields.get("deviceScreenResolution")))
                .deviceLanguage(castToText(officialContextFields.get("deviceLanguage")))
                .deviceFingerprintMatch(castToBoolean(officialContextFields.get("deviceFingerprintMatch")))
                .intentBotUserAgent(castToBoolean(officialContextFields.get("intentBotUserAgent")))
                .intentMissingReferer(castToBoolean(officialContextFields.get("intentMissingReferer")))
                .intentLanguageMismatch(castToBoolean(officialContextFields.get("intentLanguageMismatch")))
                .intentTlsFingerprintAltered(castToBoolean(officialContextFields.get("intentTlsFingerprintAltered")))
                .intentAbnormalHeaderOrder(castToBoolean(officialContextFields.get("intentAbnormalHeaderOrder")))
                .authenticationType(authenticationType)
                .currentAccessHour(castToInteger(officialContextFields.get("currentAccessHour")))
                .concurrentSessions(castToInteger(officialContextFields.get("concurrentSessions")))
                .passwordAgeDays(castToInteger(officialContextFields.get("passwordAgeDays")))
                .sessionAgeMinutes(castToInteger(officialContextFields.get("sessionAgeMinutes")))
                .authMethod(firstNonBlankText(
                        authenticationType,
                        extractAttributeText(request, "authMethod")))
                .officialContextFields(Map.copyOf(officialContextFields))
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

        Instant fromAttribute = parseObservedAt(
                RequestSecurityContextAttributes.read(request, Field.OBSERVED_AT));
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
        if (isOfficialVerificationRequest(request)) {
            return ClientIpResolver.resolveLegacy(request);
        }

        if (security == null) {
            return ClientIpResolver.resolveLegacy(request);
        }

        return ClientIpResolver.resolve(request, ClientIpResolutionPolicy.of(
                security.isTrustedProxyValidationEnabled(),
                security.getTrustedProxies()
        ));
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

    private static String authenticationStampAttribute(HttpServletRequest request, String... keys) {
        if (request == null) {
            return null;
        }
        Object rawStamp = request.getAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP);
        if (rawStamp instanceof AuthenticationStamp stamp && stamp.attributes() != null) {
            if (keys == null) {
                return null;
            }
            for (String key : keys) {
                String value = castToText(stamp.attributes().get(key));
                if (value != null) {
                    return value;
                }
            }
        }
        return null;
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
            boolean runtimeOverrideHeadersAllowed,
            String requestedModelId,
            Double runtimeTemperature,
            Double runtimeTopP,
            Integer runtimeSeed,
            Integer runtimeMaxTokens,
            Boolean runtimeDisableRetries,
            Boolean runtimeDisableOllamaThinking) {
        String explicitBoundaryMode = extractRuntimeHeaderOrAttribute(
                request,
                runtimeOverrideHeadersAllowed,
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


    private static String extractRuntimeHeaderOrAttribute(
            HttpServletRequest request,
            boolean runtimeOverrideHeadersAllowed,
            String headerName,
            String... attributeNames) {
        if (runtimeOverrideHeadersAllowed) {
            return extractHeaderOrAttribute(request, headerName, attributeNames);
        }
        return extractAttributeText(request, attributeNames);
    }

    private static Double extractDoubleRuntimeHeaderOrAttribute(
            HttpServletRequest request,
            boolean runtimeOverrideHeadersAllowed,
            String headerName,
            String... attributeNames) {
        String value = extractRuntimeHeaderOrAttribute(request, runtimeOverrideHeadersAllowed, headerName, attributeNames);
        if (value == null) {
            return null;
        }
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static Integer extractIntegerRuntimeHeaderOrAttribute(
            HttpServletRequest request,
            boolean runtimeOverrideHeadersAllowed,
            String headerName,
            String... attributeNames) {
        String value = extractRuntimeHeaderOrAttribute(request, runtimeOverrideHeadersAllowed, headerName, attributeNames);
        if (value == null) {
            return null;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static Boolean extractBooleanRuntimeHeaderOrAttribute(
            HttpServletRequest request,
            boolean runtimeOverrideHeadersAllowed,
            String headerName,
            String... attributeNames) {
        String value = extractRuntimeHeaderOrAttribute(request, runtimeOverrideHeadersAllowed, headerName, attributeNames);
        if (value == null) {
            return null;
        }
        return Boolean.parseBoolean(value);
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

    private static List<String> extractAttributeStrings(HttpServletRequest request, String... names) {
        Object value = firstNonNullAttribute(request, names);
        if (value == null) {
            return List.of();
        }
        List<String> values = new ArrayList<>();
        if (value instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                addText(values, item);
            }
        } else if (value instanceof Object[] array) {
            for (Object item : array) {
                addText(values, item);
            }
        } else {
            String text = String.valueOf(value);
            for (String token : text.split(",")) {
                addText(values, token);
            }
        }
        return List.copyOf(values);
    }

    private static void addText(List<String> values, Object value) {
        if (values == null || value == null) {
            return;
        }
        String text = String.valueOf(value).trim();
        if (!text.isBlank()) {
            values.add(text);
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
        private final String pqaPromptFaultScenario;
        private final Boolean pqaPromptFaultRejected;
        private final String pqaPromptFaultRejectedSource;
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
        private final String currentResourceFamily;
        private final String currentActionFamily;
        private final List<String> expectedResourceFamilies;
        private final List<String> expectedActionFamilies;
        private final List<String> recentPermissionChanges;
        private final Boolean approvalRequired;
        private final Boolean approvalGranted;
        private final Boolean approvalMissing;
        private final String approvalStatus;
        private final Boolean delegated;
        private final Boolean objectiveDrift;
        private final String objectiveDriftSummary;
        private final String tenantId;
        private final String organizationId;
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

        private final String ipBand;
        private final String asn;

        private final String deviceOs;
        private final String deviceOsVersion;
        private final String deviceBrowser;
        private final String deviceBrowserVersion;
        private final String deviceScreenResolution;
        private final String deviceLanguage;
        private final Boolean deviceFingerprintMatch;

        private final Boolean intentBotUserAgent;
        private final Boolean intentMissingReferer;
        private final Boolean intentLanguageMismatch;
        private final Boolean intentTlsFingerprintAltered;
        private final Boolean intentAbnormalHeaderOrder;

        private final String authenticationType;
        private final Integer currentAccessHour;
        private final Integer concurrentSessions;
        private final Integer passwordAgeDays;
        private final Integer sessionAgeMinutes;
        private final Map<String, Object> officialContextFields;
    }

    private static Integer castToInteger(Object value) {
        if (value instanceof Integer) return (Integer) value;
        if (value instanceof Number) return ((Number) value).intValue();
        return null;
    }

    private static String castToText(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
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













