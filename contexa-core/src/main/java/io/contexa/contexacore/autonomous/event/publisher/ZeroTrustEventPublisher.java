package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.coverage.MissingBridgeContext;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor.RequestInfo;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class ZeroTrustEventPublisher {

    private final ApplicationEventPublisher eventPublisher;
    private final TieredStrategyProperties properties;

    @Autowired(required = false)
    private ZeroTrustActionRepository actionRedisRepository;

    public ZeroTrustEventPublisher(
            ApplicationEventPublisher eventPublisher,
            TieredStrategyProperties properties) {
        this.eventPublisher = eventPublisher;
        this.properties = properties;
    }

    public void publishAuthenticationSuccess(
            String userId,
            String sessionId,
            String clientIp,
            String userAgent,
            Map<String, Object> payload) {

        publish(
                ZeroTrustEventCategory.AUTHENTICATION,
                ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS,
                userId,
                sessionId,
                clientIp,
                userAgent,
                null,
                payload
        );

    }

    public void publishAuthenticationFailure(
            String userId,
            String sessionId,
            String clientIp,
            String userAgent,
            Map<String, Object> payload) {

        publish(
                ZeroTrustEventCategory.AUTHENTICATION,
                ZeroTrustSpringEvent.TYPE_AUTHENTICATION_FAILURE,
                userId,
                sessionId,
                clientIp,
                userAgent,
                null,
                payload
        );

    }

    public void publishMethodAuthorization(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason) {
        ZeroTrustSpringEvent event = buildMethodAuthorizationEvent(
                methodInvocation,
                authentication,
                granted,
                denialReason
        );
        eventPublisher.publishEvent(event);
    }

    public ZeroTrustSpringEvent buildMethodAuthorizationEvent(
            MethodInvocation methodInvocation,
            Authentication authentication,
            boolean granted,
            String denialReason) {

        RequestInfo requestInfo = extractRequestInfoFromContext();
        String methodResource = methodInvocation.getMethod().getDeclaringClass().getSimpleName()
                + "." + methodInvocation.getMethod().getName();
        String resource = (requestInfo != null && requestInfo.getRequestUri() != null)
                ? requestInfo.getRequestUri()
                : methodResource;

        Map<String, Object> payload = new HashMap<>();
        payload.put("granted", granted);
        payload.put("denialReason", denialReason != null ? denialReason : "");
        payload.put("methodName", methodInvocation.getMethod().getName());
        payload.put("className", methodInvocation.getMethod().getDeclaringClass().getName());

        Protectable protectable = resolveProtectable(methodInvocation);
        if (protectable != null) {
            payload.put("protectableSync", protectable.sync());
        }

        if (requestInfo != null) {
            payload.put("httpUri", requestInfo.getRequestUri());
            payload.put("requestPath", requestInfo.getRequestUri());
            payload.put("requestUri", requestInfo.getRequestUri());
            payload.put("httpMethod", requestInfo.getMethod());
            payload.put("requestId", requestInfo.getRequestId());
            payload.put("correlationId", requestInfo.getRequestId());
            payload.put("clientIp", requestInfo.getClientIp());
            payload.put("userAgent", requestInfo.getUserAgent());
            payload.put("scenario", requestInfo.getScenario());
            payload.put("demoRunId", requestInfo.getDemoRunId());
            payload.put("demoPhase", requestInfo.getDemoPhase());
            if (requestInfo.getRoundKey() != null) {
                payload.put("roundKey", requestInfo.getRoundKey());
            }
            if (requestInfo.getBehaviorPhase() != null) {
                payload.put("behaviorPhase", requestInfo.getBehaviorPhase());
            }
            if (requestInfo.getAnomalySignal() != null) {
                payload.put("anomalySignal", requestInfo.getAnomalySignal());
            }
            if (requestInfo.getPromptBudgetProfile() != null) {
                payload.put("promptBudgetProfile", requestInfo.getPromptBudgetProfile());
            }
            if (requestInfo.getSimulatedUserAgentLabel() != null) {
                payload.put("simulatedUserAgentLabel", requestInfo.getSimulatedUserAgentLabel());
            }
            payload.put("isNewSession", requestInfo.getIsNewSession());
            payload.put("isNewUser", requestInfo.getIsNewUser());
            payload.put("isNewDevice", requestInfo.getIsNewDevice());
            payload.put("recentRequestCount", requestInfo.getRecentRequestCount());
            payload.put("failedLoginAttempts", requestInfo.getFailedLoginAttempts());
            payload.put("baselineConfidence", requestInfo.getBaselineConfidence());
            payload.put("isSensitiveResource", requestInfo.getIsSensitiveResource());
            if (requestInfo.getAuthMethod() != null) {
                payload.put("authMethod", requestInfo.getAuthMethod());
            }
            if (requestInfo.getResourceSensitivity() != null) {
                payload.put("resourceSensitivity", requestInfo.getResourceSensitivity());
            }
            if (requestInfo.getResourceBusinessLabel() != null) {
                payload.put("resourceLabel", requestInfo.getResourceBusinessLabel());
            }
            payload.put("mfaVerified", requestInfo.getMfaVerified());
            if (requestInfo.getPreviousPath() != null) {
                payload.put("previousPath", requestInfo.getPreviousPath());
            }
            if (requestInfo.getLastRequestIntervalMs() != null) {
                payload.put("lastRequestIntervalMs", requestInfo.getLastRequestIntervalMs());
            }
            payload.put("userRoles", requestInfo.getUserRoles());
            if (requestInfo.getServletPath() != null) {
                payload.put("servletPath", requestInfo.getServletPath());
            }
            if (requestInfo.getQueryString() != null) {
                payload.put("queryString", requestInfo.getQueryString());
            }
            populateBridgePayload(requestInfo, payload);

            if (requestInfo.getGeoCountry() != null) {
                payload.put("geoCountry", requestInfo.getGeoCountry());
            }
            if (requestInfo.getGeoCity() != null) {
                payload.put("geoCity", requestInfo.getGeoCity());
            }
            if (requestInfo.getGeoLatitude() != null) {
                payload.put("geoLatitude", requestInfo.getGeoLatitude());
            }
            if (requestInfo.getGeoLongitude() != null) {
                payload.put("geoLongitude", requestInfo.getGeoLongitude());
            }
            if (Boolean.TRUE.equals(requestInfo.getImpossibleTravel())) {
                payload.put("impossibleTravel", true);
                payload.put("travelDistanceKm", requestInfo.getTravelDistanceKm());
                payload.put("travelElapsedMinutes", requestInfo.getTravelElapsedMinutes());
                payload.put("previousLocation", requestInfo.getPreviousLocation());
            }
        }

        populateAuthenticationFallback(authentication, payload);
        reconcileAuthorizationDecision(granted, payload);

        if (actionRedisRepository != null && authentication != null) {
            ZeroTrustAction currentAction = actionRedisRepository.getCurrentAction(authentication.getName());
            if (currentAction != null) {
                payload.put("action", currentAction.name());
            }
        }

        return build(
                ZeroTrustEventCategory.AUTHORIZATION,
                ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD,
                authentication != null ? authentication.getName() : null,
                requestInfo != null ? requestInfo.getSessionId() : null,
                requestInfo != null ? requestInfo.getClientIp() : null,
                requestInfo != null ? requestInfo.getUserAgent() : null,
                resource,
                payload,
                requestInfo != null ? requestInfo.getObservedAt() : null
        );
    }

    public void publish(
            ZeroTrustEventCategory category,
            String eventType,
            String userId,
            Map<String, Object> payload) {

        publish(category, eventType, userId, null, null, null, null, payload);
    }

    public void publish(
            ZeroTrustEventCategory category,
            String eventType,
            String userId,
            String sessionId,
            String clientIp,
            String userAgent,
            String resource,
            Map<String, Object> payload) {
        ZeroTrustSpringEvent event = build(
                category,
                eventType,
                userId,
                sessionId,
                clientIp,
                userAgent,
                resource,
                payload,
                null
        );
        eventPublisher.publishEvent(event);
    }

    private ZeroTrustSpringEvent build(
            ZeroTrustEventCategory category,
            String eventType,
            String userId,
            String sessionId,
            String clientIp,
            String userAgent,
            String resource,
            Map<String, Object> payload,
            Instant eventTimestamp) {

        return ZeroTrustSpringEvent.builder(this)
                .category(category)
                .eventType(eventType)
                .userId(userId)
                .sessionId(sessionId)
                .clientIp(clientIp)
                .userAgent(userAgent)
                .resource(resource)
                .eventTimestamp(eventTimestamp != null ? eventTimestamp : Instant.now())
                .payload(payload != null ? payload : Map.of())
                .build();
    }

    private TieredStrategyProperties.Security getSecurity() {
        return properties != null ? properties.getSecurity() : null;
    }

    private RequestInfo extractRequestInfoFromContext() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                HttpServletRequest request = attrs.getRequest();
                return RequestInfoExtractor.extract(request, getSecurity());
            }
        } catch (Exception e) {
            log.error("Failed to extract request info from context", e);
        }
        return null;
    }

    private void populateBridgePayload(RequestInfo requestInfo, Map<String, Object> payload) {
        BridgeResolutionResult bridgeResolutionResult = requestInfo.getBridgeResolutionResult();
        if (bridgeResolutionResult == null) {
            return;
        }

        payload.put("bridgeCoverageLevel", bridgeResolutionResult.coverageReport().level().name());
        payload.put("bridgeCoverageScore", bridgeResolutionResult.coverageReport().score());
        putIfPresent(payload, "bridgeCoverageSummary", bridgeResolutionResult.coverageReport().summary());
        payload.put("bridgeMissingContexts", bridgeResolutionResult.coverageReport().missingContexts().stream()
                .map(MissingBridgeContext::name)
                .collect(Collectors.toList()));
        if (!bridgeResolutionResult.coverageReport().remediationHints().isEmpty()) {
            payload.put("bridgeRemediationHints", bridgeResolutionResult.coverageReport().remediationHints());
        }
        AuthenticationStamp authenticationStamp = bridgeResolutionResult.authenticationStamp();
        if (authenticationStamp != null) {
            putIfPresent(payload, "bridgeAuthenticationSource", authenticationStamp.authenticationSource());
            putIfPresent(payload, "principalType", authenticationStamp.principalType());
            putIfPresent(payload, "authenticationType", authenticationStamp.authenticationType());
            putIfPresent(payload, "authenticationAssurance", authenticationStamp.authenticationAssurance());
            putIfPresent(payload, "mfaVerified", authenticationStamp.mfaCompleted());
            if (!authenticationStamp.authorities().isEmpty()) {
                payload.put("authorities", authenticationStamp.authorities());
            }
            putIfPresent(payload, "organizationId", authenticationStamp.attributes().get("organizationId"));
            putIfPresent(payload, "orgId", authenticationStamp.attributes().get("orgId"));
            putIfPresent(payload, "department", authenticationStamp.attributes().get("department"));
        }

        AuthorizationStamp authorizationStamp = bridgeResolutionResult.authorizationStamp();
        if (authorizationStamp != null) {
            putIfPresent(payload, "bridgeAuthorizationSource", authorizationStamp.decisionSource());
            payload.put("authorizationEffect", authorizationStamp.effect().name());
            putIfPresent(payload, "privileged", authorizationStamp.privileged());
            putIfPresent(payload, "policyId", authorizationStamp.policyId());
            if (!authorizationStamp.scopeTags().isEmpty()) {
                payload.put("scopeTags", authorizationStamp.scopeTags());
            }
            List<String> effectiveRoles = sanitizeRoleTokens(authorizationStamp.effectiveRoles());
            if (!effectiveRoles.isEmpty()) {
                payload.put("effectiveRoles", effectiveRoles);
            }
            List<String> effectivePermissions = sanitizePermissionTokens(authorizationStamp.effectiveAuthorities());
            if (!effectivePermissions.isEmpty()) {
                payload.put("effectivePermissions", effectivePermissions);
            }
            List<String> authorityEvidence = sanitizeAuthorityTokens(authorizationStamp.effectiveAuthorities());
            if (!authorityEvidence.isEmpty()) {
                payload.put("authorities", mergeDistinctStringLists(payload.get("authorities"), authorityEvidence));
            }
        }

        DelegationStamp delegationStamp = bridgeResolutionResult.delegationStamp();
        if (delegationStamp != null && delegationStamp.delegated()) {
            putIfPresent(payload, "bridgeDelegationSource", delegationStamp.attributes().get("delegationResolver"));
            payload.put("delegated", true);
            putIfPresent(payload, "agentId", delegationStamp.agentId());
            putIfPresent(payload, "objectiveId", delegationStamp.objectiveId());
            putIfPresent(payload, "objectiveFamily", delegationStamp.objectiveFamily());
            putIfPresent(payload, "objectiveSummary", delegationStamp.objectiveSummary());
            putIfPresent(payload, "approvalRequired", delegationStamp.approvalRequired());
            putIfPresent(payload, "privilegedExportAllowed", delegationStamp.privilegedExportAllowed());
            putIfPresent(payload, "containmentOnly", delegationStamp.containmentOnly());
            if (!delegationStamp.allowedOperations().isEmpty()) {
                payload.put("allowedOperations", delegationStamp.allowedOperations());
            }
            if (!delegationStamp.allowedResources().isEmpty()) {
                payload.put("allowedResources", delegationStamp.allowedResources());
            }
        }
    }

    private void populateAuthenticationFallback(Authentication authentication, Map<String, Object> payload) {
        if (authentication == null) {
            return;
        }
        List<String> authorities = authentication.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority != null ? grantedAuthority.getAuthority() : null)
                .filter(authority -> authority != null && !authority.isBlank())
                .distinct()
                .toList();
        if (authorities.isEmpty()) {
            return;
        }

        if (!hasNonNullPayload(payload, "authMethod")) {
            boolean hasMfaAuthority = authorities.stream()
                    .anyMatch(authority -> authority.toUpperCase().contains("MFA"));
            payload.put("authMethod", hasMfaAuthority ? "mfa" : "password");
        }

        if (!hasNonNullPayload(payload, "mfaVerified")) {
            boolean hasMfaAuthority = authorities.stream()
                    .anyMatch(authority -> authority.toUpperCase().contains("MFA"));
            if (hasMfaAuthority) {
                payload.put("mfaVerified", true);
            }
        }

        if (!hasNonNullPayload(payload, "effectiveRoles")) {
            List<String> effectiveRoles = authorities.stream()
                    .filter(authority -> authority.startsWith("ROLE_"))
                    .map(authority -> authority.substring("ROLE_".length()))
                    .distinct()
                    .toList();
            if (!effectiveRoles.isEmpty()) {
                payload.put("effectiveRoles", effectiveRoles);
            }
        }

        if (!hasNonNullPayload(payload, "effectivePermissions")) {
            List<String> effectivePermissions = new ArrayList<>(authorities.stream()
                    .filter(authority -> !authority.toUpperCase().contains("MFA"))
                    .filter(authority -> !authority.startsWith("ROLE_"))
                    .distinct()
                    .toList());
            if (effectivePermissions.isEmpty()) {
                effectivePermissions.addAll(authorities.stream()
                        .filter(authority -> !authority.toUpperCase().contains("MFA"))
                        .distinct()
                        .toList());
            }
            if (!effectivePermissions.isEmpty()) {
                payload.put("effectivePermissions", effectivePermissions);
            }
        }

        if (!hasNonNullPayload(payload, "authorities")) {
            payload.put("authorities", authorities);
        }
    }

    private void reconcileAuthorizationDecision(boolean granted, Map<String, Object> payload) {
        String existingEffect = textValue(payload.get("authorizationEffect"));
        boolean synthesizedAuthorizationEffect = !StringUtils.hasText(existingEffect)
                || "UNKNOWN".equalsIgnoreCase(existingEffect);
        if (synthesizedAuthorizationEffect) {
            payload.put("authorizationEffect", granted ? "ALLOW" : "DENY");
        }

        if (!payload.containsKey("bridgeCoverageLevel")) {
            return;
        }

        List<String> missingContexts = new ArrayList<>(extractStringList(payload.get("bridgeMissingContexts")));
        if (synthesizedAuthorizationEffect) {
            missingContexts.remove(MissingBridgeContext.AUTHORIZATION_EFFECT.name());
        }
        if (missingContexts.isEmpty()) {
            payload.remove("bridgeMissingContexts");
        } else {
            payload.put("bridgeMissingContexts", List.copyOf(missingContexts));
        }

        List<String> remediationHints = new ArrayList<>(extractStringList(payload.get("bridgeRemediationHints")));
        if (synthesizedAuthorizationEffect) {
            remediationHints.removeIf(hint -> hint != null
                    && hint.toLowerCase(Locale.ROOT).contains("authorization effect"));
        }
        if (remediationHints.isEmpty()) {
            payload.remove("bridgeRemediationHints");
        } else {
            payload.put("bridgeRemediationHints", List.copyOf(remediationHints));
        }

        if (synthesizedAuthorizationEffect && payload.get("bridgeCoverageScore") instanceof Number number) {
            int adjustedScore = Math.min(100, number.intValue() + 10);
            payload.put("bridgeCoverageScore", adjustedScore);
        }

        String coverageLevel = textValue(payload.get("bridgeCoverageLevel"));
        if (StringUtils.hasText(coverageLevel)) {
            payload.put("bridgeCoverageSummary", resolveBridgeCoverageSummary(coverageLevel, missingContexts));
        }
    }

    private String resolveBridgeCoverageSummary(String coverageLevel, List<String> missingContexts) {
        boolean missingAuthorizationAuthorities = missingContexts.contains(MissingBridgeContext.AUTHORIZATION_AUTHORITIES.name());
        boolean missingDelegation = missingContexts.contains(MissingBridgeContext.DELEGATION.name());
        return switch (coverageLevel.trim().toUpperCase(Locale.ROOT)) {
            case "AUTHORIZATION_CONTEXT" -> {
                if (missingAuthorizationAuthorities) {
                    yield "Bridge completeness reached authentication and partial authorization context for the current request.";
                }
                if (missingDelegation) {
                    yield "Bridge completeness reached authentication and authorization context, but delegated execution metadata is incomplete for this request.";
                }
                yield "Bridge completeness reached authentication and authorization context for the current request.";
            }
            case "DELEGATION_CONTEXT" ->
                    "Bridge completeness reached authentication, authorization, and delegated execution context for the current request.";
            case "AUTHENTICATION_ONLY" ->
                    "Bridge completeness reached authentication, but request-level authorization context is still incomplete.";
            default -> "Bridge completeness did not reach an authenticated principal for the current request.";
        };
    }

    private boolean hasNonNullPayload(Map<String, Object> payload, String key) {
        return payload.containsKey(key) && payload.get(key) != null;
    }

    private List<String> sanitizeRoleTokens(List<String> rawValues) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        for (String rawValue : rawValues) {
            String normalized = normalizeAuthorityValue(rawValue);
            if (!StringUtils.hasText(normalized)) {
                continue;
            }
            if (isPermissionAuthorityArtifact(rawValue)) {
                continue;
            }
            if (normalized.startsWith("ROLE_")) {
                normalized = normalized.substring("ROLE_".length());
            }
            if (normalized.contains("/")
                    || normalized.contains(".")
                    || normalized.contains(":")
                    || normalized.contains("=")
                    || normalized.contains(" ")) {
                continue;
            }
            values.add(normalized.toUpperCase(Locale.ROOT));
        }
        return List.copyOf(values);
    }

    private List<String> sanitizePermissionTokens(List<String> rawValues) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        for (String rawValue : rawValues) {
            String normalized = normalizePermissionValue(rawValue);
            if (!StringUtils.hasText(normalized)) {
                continue;
            }
            if (normalized.startsWith("ROLE_")
                    || normalized.startsWith("/")
                    || normalized.contains("=")
                    || normalized.contains(" ")) {
                continue;
            }
            if (isRoleAuthorityArtifact(rawValue)) {
                continue;
            }
            values.add(normalized);
        }
        return List.copyOf(values);
    }

    private List<String> sanitizeAuthorityTokens(List<String> rawValues) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        for (String rawValue : rawValues) {
            String normalized = normalizeAuthorityValue(rawValue);
            if (!StringUtils.hasText(normalized)) {
                continue;
            }
            if (normalized.startsWith("ROLE_")
                    || normalized.startsWith("/")
                    || normalized.contains("=")
                    || normalized.contains(" ")) {
                continue;
            }
            values.add(normalized);
        }
        return List.copyOf(values);
    }

    private List<String> mergeDistinctStringLists(Object existing, List<String> additions) {
        LinkedHashSet<String> merged = new LinkedHashSet<>(extractStringList(existing));
        merged.addAll(additions);
        return List.copyOf(merged);
    }

    private List<String> extractStringList(Object rawValue) {
        if (rawValue == null) {
            return List.of();
        }
        LinkedHashSet<String> values = new LinkedHashSet<>();
        if (rawValue instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                String normalized = normalizeAuthorityValue(item != null ? item.toString() : null);
                if (StringUtils.hasText(normalized)) {
                    values.add(normalized);
                }
            }
            return List.copyOf(values);
        }
        String text = rawValue.toString();
        if (text.contains(",")) {
            for (String token : text.split(",")) {
                String normalized = normalizeAuthorityValue(token);
                if (StringUtils.hasText(normalized)) {
                    values.add(normalized);
                }
            }
            return List.copyOf(values);
        }
        String normalized = normalizeAuthorityValue(text);
        if (StringUtils.hasText(normalized)) {
            values.add(normalized);
        }
        return List.copyOf(values);
    }

    private String normalizeAuthorityValue(String rawValue) {
        if (!StringUtils.hasText(rawValue)) {
            return null;
        }
        String value = extractAuthorityLiteral(rawValue);
        value = value != null ? value : rawValue.trim();
        while (!value.isEmpty() && isWrapperChar(value.charAt(0))) {
            value = value.substring(1).trim();
        }
        while (!value.isEmpty() && isWrapperChar(value.charAt(value.length() - 1))) {
            value = value.substring(0, value.length() - 1).trim();
        }
        if (value.isBlank()
                || "null".equalsIgnoreCase(value)
                || value.startsWith("roleId=")
                || value.startsWith("permissionId=")
                || value.startsWith("targetType=")
                || value.startsWith("actionType=")) {
            return null;
        }
        return value;
    }

    private String normalizePermissionValue(String rawValue) {
        String normalized = normalizeAuthorityValue(rawValue);
        if (!StringUtils.hasText(normalized)) {
            return null;
        }
        // Permission authority artifacts often arrive as REPORT_READ style identifiers.
        // For prompt quality and cross-round comparison we normalize them to the same
        // dotted lowercase vocabulary used by scope tags and prompt sections.
        if (normalized.indexOf('.') < 0
                && normalized.indexOf('/') < 0
                && normalized.indexOf(':') < 0
                && normalized.indexOf('=') < 0
                && normalized.equals(normalized.toUpperCase(Locale.ROOT))
                && normalized.contains("_")) {
            return normalized.toLowerCase(Locale.ROOT).replace('_', '.');
        }
        return normalized;
    }

    private String extractAuthorityLiteral(String rawValue) {
        Matcher quotedMatcher = Pattern.compile("authority='([^']+)'").matcher(rawValue);
        if (quotedMatcher.find()) {
            return quotedMatcher.group(1);
        }
        Matcher plainMatcher = Pattern.compile("authority=([^,}\\]]+)").matcher(rawValue);
        if (plainMatcher.find()) {
            return plainMatcher.group(1).trim();
        }
        return null;
    }

    private boolean isWrapperChar(char value) {
        return value == '[' || value == ']' || value == '{' || value == '}'
                || value == '(' || value == ')' || value == '"' || value == '\'';
    }

    private boolean isPermissionAuthorityArtifact(String rawValue) {
        return rawValue != null && rawValue.contains("PermissionAuthority{");
    }

    private boolean isRoleAuthorityArtifact(String rawValue) {
        return rawValue != null && rawValue.contains("RoleAuthority{");
    }

    private String textValue(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }

    private void putIfPresent(Map<String, Object> payload, String key, Object value) {
        if (value != null) {
            payload.put(key, value);
        }
    }

    private Protectable resolveProtectable(MethodInvocation methodInvocation) {
        Protectable protectable = AnnotationUtils.findAnnotation(methodInvocation.getMethod(), Protectable.class);
        if (protectable != null) {
            return protectable;
        }

        Object target = methodInvocation.getThis();
        if (target != null) {
            Class<?> targetClass = AopProxyUtils.ultimateTargetClass(target);
            protectable = AnnotationUtils.findAnnotation(
                    AopUtils.getMostSpecificMethod(methodInvocation.getMethod(), targetClass),
                    Protectable.class);
            if (protectable != null) {
                return protectable;
            }
            protectable = AnnotationUtils.findAnnotation(targetClass, Protectable.class);
            if (protectable != null) {
                return protectable;
            }
        }

        return AnnotationUtils.findAnnotation(methodInvocation.getMethod().getDeclaringClass(), Protectable.class);
    }
}
