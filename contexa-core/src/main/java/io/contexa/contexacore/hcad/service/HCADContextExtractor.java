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
package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import io.contexa.contexacommon.security.network.ClientIpResolver;
import io.contexa.contexacore.autonomous.context.policy.PromptRelevantRequestPathPolicy;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.utils.OfficialVerificationRequestContext;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.hcad.trigger.HcadRequestPathUtils;
import jakarta.servlet.http.HttpServletRequest;
import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;
import org.springframework.util.AntPathMatcher;

import java.lang.reflect.Method;
import java.lang.reflect.Array;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class HCADContextExtractor {

    private final HCADDataStore hcadDataStore;
    private final SecurityContextDataStore securityContextDataStore;
    private final HcadProperties hcadProperties;

    @Setter
    private BlockMfaStateStore blockMfaStateStore;

    @Setter
    private BaselineLearningService baselineLearningService;

    @Setter
    private GeoIpService geoIpService;

    @Setter
    private TieredStrategyProperties.Security trustedProxySecurity;

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public HCADContext extractContext(HttpServletRequest request, Authentication authentication) {
        long startTime = System.nanoTime();

        try {

            String clientIp = extractClientIp(request);

            String userId = extractUserId(request, authentication);
            String username = extractUsername(request, authentication);
            String sessionId = OfficialVerificationRequestContext.resolveSessionId(request);
            String requestPath = HcadRequestPathUtils.normalizedPath(request);

            if (userId.startsWith("anonymous:")) {
                userId = "anonymous:" + clientIp;
                username = "anonymous:" + clientIp;
            }

            HCADContext context = new HCADContext();
            context.setUserId(userId);
            context.setSessionId(sessionId != null ? sessionId : "unknown");
            context.setUsername(username);
            context.setRequestPath(requestPath);
            context.setHttpMethod(request.getMethod());
            context.setRemoteIp(clientIp);

            String simulatedUA = request.getHeader("X-Simulated-User-Agent");
            String userAgent = (simulatedUA != null && !simulatedUA.isEmpty())
                    ? simulatedUA : request.getHeader("User-Agent");
            context.setUserAgent(userAgent != null ? userAgent : "unknown");
            context.setReferer(request.getHeader("Referer"));
            Instant observedAt = resolveObservedAt(request);
            context.setTimestamp(observedAt);
            context.setIpBand(deriveIpBand(clientIp));
            context.setCurrentAccessHour(LocalDateTime.ofInstant(observedAt, ZoneId.systemDefault()).getHour());
            enrichWithSecurityScope(context, request);
            enrichWithDeviceContext(context, request);
            enrichWithIntentSignals(context, request);

            boolean promptRelevantPath = PromptRelevantRequestPathPolicy.isPromptRelevantPath(context.getRequestPath());

            enrichWithSessionInfo(context, userId, sessionId, promptRelevantPath, observedAt);

            enrichWithRequestPattern(context, userId, request, promptRelevantPath, observedAt);

            enrichWithSecurityInfo(context, userId, request, authentication, promptRelevantPath, observedAt);

            enrichAuthorizationContext(context, request, userId);

            enrichWithResourceInfo(context, request);

            enrichWithGeoLocation(context, clientIp);

            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);

            return context;

        } catch (Exception e) {
            log.error("[HCAD] Context extraction failed", e);
            Map<String, Object> failureAttributes = new HashMap<>();
            failureAttributes.put("contextExtractionFailed", true);
            failureAttributes.put("contextExtractionFailureType", e.getClass().getSimpleName());

            return HCADContext.builder()
                    .userId(authentication != null ? extractUserId(request, authentication) : "unknown")
                    .sessionId(OfficialVerificationRequestContext.resolveSessionId(request))
                    .requestPath(HcadRequestPathUtils.normalizedPath(request))
                    .httpMethod(request.getMethod())
                    .remoteIp(request.getRemoteAddr())
                    .timestamp(resolveObservedAt(request))
                    .isNewSession(false)
                    .isNewUser(false)
                    .isNewDevice(false)
                    .additionalAttributes(failureAttributes)
                    .build();
        }
    }

    private String extractUserId(HttpServletRequest request, Authentication authentication) {
        String requestedUserId = OfficialVerificationRequestContext.resolveUserId(request);
        if (requestedUserId != null) {
            return requestedUserId;
        }

        if (authentication == null) {
            return "anonymous:unknown";
        }

        Object principal = authentication.getPrincipal();

        if ("anonymousUser".equals(principal)) {
            return "anonymous:" + System.currentTimeMillis();
        }

        if (principal != null && principal.getClass().getSimpleName().contains("UserDto")) {
            try {

                Method getUsernameMethod = principal.getClass().getMethod("getUsername");
                Object username = getUsernameMethod.invoke(principal);
                return username != null ? username.toString() : authentication.getName();
            } catch (Exception e) {
                return authentication.getName();
            }
        }

        String name = authentication.getName();

        if ("anonymousUser".equals(name)) {
            return "anonymous:" + System.currentTimeMillis();
        }

        return name;
    }

    private String extractUsername(HttpServletRequest request, Authentication authentication) {
        return extractUserId(request, authentication);
    }

    private String extractClientIp(HttpServletRequest request) {
        if (trustedProxySecurity != null) {
            return RequestInfoExtractor.extractClientIp(request, trustedProxySecurity);
        }

        return ClientIpResolver.resolveLegacy(request);
    }

    private void enrichWithSessionInfo(HCADContext context,
                                       String userId,
                                       String sessionId,
                                       boolean promptRelevantPath,
                                       Instant observedAt) {
        try {

            Map<Object, Object> sessionInfo = hcadDataStore.getSessionMetadata(sessionId);

            boolean isNewSession = sessionInfo.isEmpty();
            context.setIsNewSession(isNewSession);

            String currentDevice = context.getUserAgent();
            boolean isNewDevice = checkAndRegisterDevice(userId, currentDevice, promptRelevantPath);
            context.setIsNewDevice(isNewDevice);

            if (promptRelevantPath && isNewSession && userId != null && !userId.startsWith("anonymous:")) {
                Map<String, Object> newSessionInfo = new HashMap<>();
                newSessionInfo.put("userId", userId);
                newSessionInfo.put("device", currentDevice);
                newSessionInfo.put("createdAt", observedAt.toString());
                hcadDataStore.saveSessionMetadata(sessionId, newSessionInfo);
            }

            Integer sessionAgeMinutes = calculateSessionAgeMinutes(sessionInfo, observedAt);
            if (sessionAgeMinutes != null) {
                context.setSessionAgeMinutes(sessionAgeMinutes);
            }

        } catch (Exception e) {
            context.setIsNewSession(false);
            context.setIsNewDevice(false);
            context.setSessionAgeMinutes(0);
            putAdditionalAttribute(context, "sessionInfoUnavailable", true);
            putAdditionalAttribute(context, "sessionInfoFailureType", e.getClass().getSimpleName());
        }
    }

    private boolean checkAndRegisterDevice(String userId, String currentDevice, boolean promptRelevantPath) {
        if (userId == null || userId.startsWith("anonymous:") || currentDevice == null || currentDevice.isEmpty()) {
            return true;
        }

        try {
            if (hcadDataStore.isDeviceRegistered(userId, currentDevice)) {
                return false;
            } else {
                if (promptRelevantPath) {
                    hcadDataStore.registerDevice(userId, currentDevice);
                }
                return true;
            }
        } catch (Exception e) {
            return false;
        }
    }

    private void enrichWithRequestPattern(HCADContext context,
                                          String userId,
                                          HttpServletRequest request,
                                          boolean promptRelevantPath,
                                          Instant observedAt) {
        try {
            long currentTime = observedAt.toEpochMilli();
            long fiveMinutesAgo = currentTime - (5 * 60 * 1000);
            String requestPath = HcadRequestPathUtils.normalizedPath(request);

            if (userId != null && userId.startsWith("anonymous:")) {
                context.setRecentRequestCount(0);
                context.setLastRequestInterval(0L);
                return;
            }

            if (promptRelevantPath) {
                hcadDataStore.recordRequest(userId, currentTime);
                int recentCount = hcadDataStore.getRecentRequestCount(userId, fiveMinutesAgo, currentTime);
                context.setRecentRequestCount(recentCount > 0 ? recentCount : 1);

                Long lastReqTime = securityContextDataStore.getLastRequestTime(userId);
                if (lastReqTime != null) {
                    long interval = currentTime - lastReqTime;
                    context.setLastRequestInterval(interval);
                } else {
                    context.setLastRequestInterval(0L);
                }
                securityContextDataStore.setLastRequestTime(userId, currentTime);

                String previousPath = securityContextDataStore.getPreviousPath(userId);
                context.setPreviousPath(previousPath);
                securityContextDataStore.setPreviousPath(userId, requestPath);

                String sessionId = context.getSessionId();
                if (sessionId != null && securityContextDataStore != null) {
                    LocalDateTime observedDateTime = LocalDateTime.ofInstant(observedAt, ZoneId.systemDefault());
                    String actionEntry = String.format("%02d:%02d | %s %s | %s",
                            observedDateTime.getHour(),
                            observedDateTime.getMinute(),
                            request.getMethod(),
                            requestPath,
                            context.getRemoteIp() != null ? context.getRemoteIp() : "unknown");
                    securityContextDataStore.addSessionAction(sessionId, actionEntry);
                }
            } else {
                int recentCount = hcadDataStore.getRecentRequestCount(userId, fiveMinutesAgo, currentTime);
                context.setRecentRequestCount(recentCount);
            }

        } catch (Exception e) {
            context.setRecentRequestCount(0);
            context.setLastRequestInterval(0L);
        }
    }

    private void enrichWithSecurityInfo(HCADContext context,
                                        String userId,
                                        HttpServletRequest request,
                                        Authentication authentication,
                                        boolean promptRelevantPath,
                                        Instant observedAt) {
        try {
            if (userId != null && userId.startsWith("anonymous:")) {
                context.setNewUser(false);
                context.setCurrentTrustScore(Double.NaN);
                context.setBaselineConfidence(Double.NaN);
                context.setFailedLoginAttempts(0);
                context.setHasValidMFA(false);
                return;
            }

            boolean isRegistered = hcadDataStore.isUserRegistered(userId);

            if (!isRegistered) {
                if (promptRelevantPath) {
                    hcadDataStore.registerUser(userId);
                }
                context.setNewUser(true);
            } else {
                context.setNewUser(false);
            }

            context.setCurrentTrustScore(Double.NaN);

            context.setBaselineConfidence(calculateBaselineConfidence(userId));

            context.setFailedLoginAttempts(resolveFailedLoginAttempts(userId));

            AuthenticationStamp authenticationStamp = resolveAuthenticationStamp(request);
            boolean hasMfa = resolveMfaVerified(userId);
            if (authenticationStamp != null && Boolean.TRUE.equals(authenticationStamp.mfaCompleted())) {
                hasMfa = true;
            }

            String authMethod = resolveAuthenticationMethod(authentication, authenticationStamp, hasMfa);
            context.setAuthenticationMethod(authMethod);
            context.setAuthenticationType(authMethod);

            context.setHasValidMFA(hasMfa);

            Set<String> authorities = authentication == null
                    ? Set.of()
                    : authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            Set<String> roles = authorities.stream()
                    .filter(authority -> authority != null && authority.startsWith("ROLE_"))
                    .map(authority -> authority.substring("ROLE_".length()))
                    .collect(Collectors.toSet());

            Map<String, Object> additionalAttrs = context.getAdditionalAttributes();
            if (additionalAttrs == null) {
                additionalAttrs = new HashMap<>();
                context.setAdditionalAttributes(additionalAttrs);
            }
            additionalAttrs.put("userRoles", roles);
            additionalAttrs.put("authorities", authorities);
            additionalAttrs.put("mfaVerified", hasMfa);
            enrichAuthenticationStamp(additionalAttrs, authenticationStamp, observedAt);
            enrichMfaFreshness(additionalAttrs, userId, hasMfa, observedAt);

        } catch (Exception e) {

            context.setCurrentTrustScore(Double.NaN);
            context.setBaselineConfidence(Double.NaN);
            context.setFailedLoginAttempts(0);
            context.setHasValidMFA(false);
            context.setNewUser(false);
            putAdditionalAttribute(context, "securityInfoUnavailable", true);
            putAdditionalAttribute(context, "securityInfoFailureType", e.getClass().getSimpleName());
        }
    }

    private int resolveFailedLoginAttempts(String userId) {
        if (blockMfaStateStore == null) {
            return 0;
        }
        try {
            return blockMfaStateStore.getFailCount(userId);
        } catch (Exception e) {
            return 0;
        }
    }

    private boolean resolveMfaVerified(String userId) {
        if (blockMfaStateStore != null) {
            try {
                if (blockMfaStateStore.isVerified(userId)) {
                    return true;
                }
            } catch (Exception e) {
            }
        }
        return hcadDataStore.isMfaVerified(userId);
    }

    private String resolveAuthenticationMethod(
            Authentication authentication,
            AuthenticationStamp authenticationStamp,
            boolean hasMfa) {
        String stampedMethod = authenticationStamp == null ? null : firstNonBlank(
                authenticationStamp.authenticationType(),
                authenticationStamp.authenticationSource());
        if (StringUtils.hasText(stampedMethod)) {
            return stampedMethod.trim().toLowerCase();
        }
        if (hasMfa) {
            return "mfa";
        }
        if (authentication == null || authentication.getAuthorities() == null) {
            return "password";
        }
        return authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority() != null && auth.getAuthority().contains("MFA"))
                ? "mfa"
                : "password";
    }

    private void enrichAuthenticationStamp(
            Map<String, Object> attrs,
            AuthenticationStamp authenticationStamp,
            Instant observedAt) {
        if (attrs == null || authenticationStamp == null) {
            return;
        }
        putIfText(attrs, "authenticationAssurance", authenticationStamp.authenticationAssurance());
        putIfText(attrs, "authenticationType", authenticationStamp.authenticationType());
        putIfText(attrs, "authenticationSource", authenticationStamp.authenticationSource());
        if (authenticationStamp.mfaCompleted() != null) {
            attrs.put("mfaCompleted", authenticationStamp.mfaCompleted());
        }
        if (authenticationStamp.authenticationTime() != null) {
            attrs.put("authenticationTime", authenticationStamp.authenticationTime().toString());
            if (observedAt != null) {
                attrs.put("authenticationAgeSeconds",
                        Math.max(0L, Duration.between(authenticationStamp.authenticationTime(), observedAt).toSeconds()));
            }
        }
        if (!authenticationStamp.authorities().isEmpty()) {
            attrs.put("bridgeAuthorities", authenticationStamp.authorities());
        }
    }

    private void enrichMfaFreshness(
            Map<String, Object> attrs,
            String userId,
            boolean hasMfa,
            Instant observedAt) {
        if (attrs == null) {
            return;
        }
        if (!hasMfa || blockMfaStateStore == null || observedAt == null) {
            attrs.put("mfaFresh", false);
            return;
        }
        try {
            Instant verifiedAt = blockMfaStateStore.getVerifiedAt(userId);
            Instant expiresAt = blockMfaStateStore.getVerifiedExpiresAt(userId);
            if (verifiedAt != null) {
                long freshnessSeconds = Math.max(0L, Duration.between(verifiedAt, observedAt).toSeconds());
                attrs.put("mfaVerifiedAt", verifiedAt.toString());
                attrs.put("mfaFreshnessSeconds", freshnessSeconds);
                attrs.put("mfaFresh", freshnessSeconds <= hcadProperties.getPreTrigger().getFreshMfaMaxAgeSeconds());
            } else {
                attrs.put("mfaFresh", false);
            }
            if (expiresAt != null) {
                attrs.put("mfaVerifiedExpiresAt", expiresAt.toString());
            }
        } catch (Exception e) {
            attrs.put("mfaFresh", false);
            attrs.put("mfaFreshnessUnavailable", true);
        }
    }

    private void enrichAuthorizationContext(HCADContext context, HttpServletRequest request, String userId) {
        if (context == null || request == null) {
            return;
        }

        AuthorizationStamp authorizationStamp = resolveAuthorizationStamp(request);
        if (authorizationStamp != null) {
            putAdditionalAttribute(context, "authorizationPrivileged", authorizationStamp.privileged());
            putAdditionalAttribute(context, "authorizationResourceId", authorizationStamp.resourceId());
            putAdditionalAttribute(context, "authorizationAction", authorizationStamp.action());
            putAdditionalAttribute(context, "authorizationEffect", authorizationStamp.effect().name());
            putAdditionalAttribute(context, "authorizationPolicyId", authorizationStamp.policyId());
            putAdditionalAttribute(context, "authorizationPolicyVersion", authorizationStamp.policyVersion());
            putAdditionalAttribute(context, "authorizationDecisionSource", authorizationStamp.decisionSource());
            if (!authorizationStamp.effectiveRoles().isEmpty()) {
                putAdditionalAttribute(context, "effectiveRoles", authorizationStamp.effectiveRoles());
            }
            if (!authorizationStamp.effectiveAuthorities().isEmpty()) {
                putAdditionalAttribute(context, "effectiveAuthorities", authorizationStamp.effectiveAuthorities());
            }
        }

        List<String> permissionChanges = new ArrayList<>();
        permissionChanges.addAll(normalizeStringList(firstNonNullAttribute(request,
                "hcad.recent_permission_changes",
                "hcad.recentPermissionChanges",
                "recentPermissionChanges",
                "permissionChangeEvents")));
        permissionChanges.addAll(normalizeStringList(firstHeader(request,
                "X-Contexa-Recent-Permission-Changes",
                "X-Contexa-Permission-Changes")));
        String tenantId = firstNonBlank(
                attrText(context, "tenantId"),
                attrText(context, "organizationId"),
                attrText(context, "orgId"));
        if (StringUtils.hasText(tenantId) && StringUtils.hasText(userId) && !userId.startsWith("anonymous:")) {
            try {
                permissionChanges.addAll(securityContextDataStore.getRecentPermissionChangeObservations(
                        tenantId,
                        userId,
                        hcadProperties.getPreTrigger().getPermissionChangeObservationLimit()));
            } catch (Exception e) {
                putAdditionalAttribute(context, "permissionChangeObservationUnavailable", true);
            }
        }
        if (!permissionChanges.isEmpty()) {
            putAdditionalAttribute(context, "recentPermissionChanges", List.copyOf(permissionChanges));
        }
    }

    private AuthenticationStamp resolveAuthenticationStamp(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        Object rawStamp = request.getAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP);
        if (rawStamp instanceof AuthenticationStamp stamp) {
            return stamp;
        }
        Object rawResult = request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        if (rawResult instanceof BridgeResolutionResult result) {
            return result.authenticationStamp();
        }
        return null;
    }

    private AuthorizationStamp resolveAuthorizationStamp(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        Object rawStamp = request.getAttribute(BridgeRequestAttributes.AUTHORIZATION_STAMP);
        if (rawStamp instanceof AuthorizationStamp stamp) {
            return stamp;
        }
        Object rawResult = request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        if (rawResult instanceof BridgeResolutionResult result) {
            return result.authorizationStamp();
        }
        return null;
    }

    private double calculateBaselineConfidence(String userId) {
        if (baselineLearningService == null) {
            return Double.NaN;
        }
        try {
            BaselineVector baseline = baselineLearningService.getBaseline(userId);
            if (baseline == null || baseline.getUpdateCount() == null) {
                return 0.0;
            }
            long updateCount = baseline.getUpdateCount();
            if (updateCount < 10) {
                return 0.0;
            } else if (updateCount < 30) {
                return 0.3;
            } else if (updateCount < 100) {
                return 0.7;
            } else {
                return 1.0;
            }
        } catch (Exception e) {
            return Double.NaN;
        }
    }

    private void enrichWithResourceInfo(HCADContext context,
                                        HttpServletRequest request) {
        try {
            String path = HcadRequestPathUtils.normalizedPath(request);
            String explicitResourceId = firstNonBlankAttribute(request,
                    "hcad.resource_id",
                    "hcad.resourceId",
                    "resourceId",
                    "requestedResourceId",
                    "protectedResourceId");
            String explicitResourceType = firstNonBlankAttribute(request,
                    "hcad.resource_type",
                    "hcad.resourceType",
                    "resourceType",
                    "resourceCategory",
                    "endpointKey");
            String explicitBusinessLabel = firstNonBlankAttribute(request,
                    "hcad.resource_business_label",
                    "hcad.resourceBusinessLabel",
                    "resourceBusinessLabel",
                    "resourceLabel",
                    "businessLabel");

            context.setResourceType(StringUtils.hasText(explicitResourceType)
                    ? explicitResourceType
                    : resolveResourceTypeFromPath(path));

            Boolean sensitiveResource = matchesSensitiveResource(path);
            context.setIsSensitiveResource(Boolean.TRUE.equals(sensitiveResource));

            Map<String, Object> additionalAttrs = context.getAdditionalAttributes();
            if (additionalAttrs == null) {
                additionalAttrs = new HashMap<>();
            }
            if (StringUtils.hasText(explicitResourceId)) {
                additionalAttrs.put("resourceId", explicitResourceId);
            }
            if (StringUtils.hasText(context.getResourceType())) {
                additionalAttrs.put("resourceType", context.getResourceType());
                additionalAttrs.put("resourceCategory", context.getResourceType());
            }
            if (StringUtils.hasText(explicitBusinessLabel)) {
                additionalAttrs.put("resourceBusinessLabel", explicitBusinessLabel);
                additionalAttrs.put("resourceLabel", explicitBusinessLabel);
                additionalAttrs.put("businessLabel", explicitBusinessLabel);
            }
            additionalAttrs.put("contentType", request.getContentType());
            additionalAttrs.put("queryString", request.getQueryString());
            additionalAttrs.put("protocol", request.getProtocol());
            additionalAttrs.put("secure", request.isSecure());
            additionalAttrs.put("fullPath", path);
            context.setAdditionalAttributes(additionalAttrs);

        } catch (Exception e) {
            context.setResourceType(null);
            context.setIsSensitiveResource(null);
        }
    }

    private Instant resolveObservedAt(HttpServletRequest request) {
        Instant observedAt = RequestInfoExtractor.extractObservedAt(request);
        return observedAt != null ? observedAt : Instant.now();
    }

    private void enrichWithGeoLocation(HCADContext context, String clientIp) {
        if (geoIpService == null || clientIp == null) {
            return;
        }
        try {
            GeoIpService.GeoLocation location = geoIpService.lookup(clientIp);
            if (location != null && location.isKnown()) {
                context.setCountry(location.country());
                context.setCity(location.city());
                context.setLatitude(location.latitude());
                context.setLongitude(location.longitude());

                detectImpossibleTravel(context, location);
            }
        } catch (Exception e) {
            log.error("[HCADContextExtractor] GeoIP enrichment failed: ip={}", clientIp, e);
        }
    }

    private void enrichWithSecurityScope(HCADContext context, HttpServletRequest request) {
        if (context == null || request == null) {
            return;
        }
        String tenantId = firstNonBlank(
                firstHeader(request, "X-Contexa-Tenant-Id", "X-Tenant-Id"),
                firstNonBlankAttribute(request, "tenantId", "ctxa.auth.tenantId", "hcad.tenant_id", "hcad.tenantId"));
        String organizationId = firstNonBlank(
                firstHeader(request, "X-Contexa-Organization-Id", "X-Organization-Id"),
                firstNonBlankAttribute(request, "organizationId", "ctxa.auth.organizationId", "hcad.organization_id", "hcad.organizationId"));
        String orgId = firstNonBlank(
                firstHeader(request, "X-Contexa-Org-Id", "X-Org-Id"),
                firstNonBlankAttribute(request, "orgId", "ctxa.auth.orgId", "hcad.org_id", "hcad.orgId"));

        if (StringUtils.hasText(tenantId)) {
            putAdditionalAttribute(context, "tenantId", tenantId);
        }
        if (StringUtils.hasText(organizationId)) {
            putAdditionalAttribute(context, "organizationId", organizationId);
        }
        if (StringUtils.hasText(orgId)) {
            putAdditionalAttribute(context, "orgId", orgId);
        }
    }

    private void enrichWithDeviceContext(HCADContext context, HttpServletRequest request) {
        if (context == null) {
            return;
        }
        String userAgent = context.getUserAgent();
        String browserSignature = SecurityEventEnricher.extractBrowserSignature(userAgent);
        String[] browserParts = splitNameAndVersion(browserSignature);
        context.setDeviceOs(SecurityEventEnricher.extractOSFromUserAgent(userAgent));
        context.setDeviceBrowser(browserParts[0]);
        context.setDeviceBrowserVersion(browserParts[1]);
        context.setDeviceLanguage(resolveDeviceLanguage(request));
        context.setDeviceScreenResolution(resolveScreenResolution(request));
    }

    private void enrichWithIntentSignals(HCADContext context, HttpServletRequest request) {
        if (context == null || request == null) {
            return;
        }
        context.setIntentBotUserAgent(isBotUserAgent(context.getUserAgent()));
        context.setIntentMissingReferer(!StringUtils.hasText(request.getHeader("Referer")));
    }

    private Integer calculateSessionAgeMinutes(Map<Object, Object> sessionInfo, Instant observedAt) {
        if (observedAt == null) {
            return null;
        }
        String createdAt = sessionInfo != null ? text(sessionInfo.get("createdAt")) : null;
        if (!StringUtils.hasText(createdAt)) {
            return 0;
        }
        try {
            Instant sessionStart = Instant.parse(createdAt);
            long elapsedMinutes = Math.max(0L, (observedAt.toEpochMilli() - sessionStart.toEpochMilli()) / 60_000L);
            return Math.toIntExact(elapsedMinutes);
        } catch (Exception ex) {
            return 0;
        }
    }

    private String resolveDeviceLanguage(HttpServletRequest request) {
        String header = request != null ? request.getHeader("Accept-Language") : null;
        if (!StringUtils.hasText(header)) {
            return null;
        }
        String primary = header.split(",")[0].trim();
        int separator = primary.indexOf(';');
        if (separator >= 0) {
            primary = primary.substring(0, separator).trim();
        }
        return StringUtils.hasText(primary) ? primary : null;
    }

    private String resolveScreenResolution(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String explicit = firstHeader(request,
                "X-Contexa-Screen-Resolution",
                "X-Device-Screen-Resolution",
                "Sec-CH-Viewport");
        if (StringUtils.hasText(explicit)) {
            return explicit;
        }
        String width = firstHeader(request, "Sec-CH-Viewport-Width", "X-Viewport-Width");
        String height = firstHeader(request, "Sec-CH-Viewport-Height", "X-Viewport-Height");
        if (StringUtils.hasText(width) && StringUtils.hasText(height)) {
            return width.trim() + "x" + height.trim();
        }
        return null;
    }

    private String[] splitNameAndVersion(String signature) {
        if (!StringUtils.hasText(signature)) {
            return new String[] { null, null };
        }
        String normalized = signature.trim();
        int separator = normalized.indexOf('/');
        if (separator < 0) {
            return new String[] { normalized, null };
        }
        String name = normalized.substring(0, separator).trim();
        String version = normalized.substring(separator + 1).trim();
        return new String[] {
                StringUtils.hasText(name) ? name : null,
                StringUtils.hasText(version) ? version : null
        };
    }

    private String deriveIpBand(String clientIp) {
        if (!StringUtils.hasText(clientIp)) {
            return null;
        }
        String normalized = clientIp.trim();
        String[] ipv4 = normalized.split("\\.");
        if (ipv4.length == 4) {
            return ipv4[0] + "." + ipv4[1] + "." + ipv4[2] + ".0/24";
        }
        if (normalized.contains(":")) {
            String[] ipv6 = normalized.split(":");
            if (ipv6.length >= 4) {
                return String.join(":", ipv6[0], ipv6[1], ipv6[2], ipv6[3]) + "::/64";
            }
        }
        return null;
    }

    private String resolveResourceTypeFromPath(String path) {
        if (!StringUtils.hasText(path)) {
            return null;
        }
        String[] rawSegments = path.split("/");
        ArrayList<String> segments = new ArrayList<>();
        for (String rawSegment : rawSegments) {
            if (StringUtils.hasText(rawSegment)) {
                segments.add(rawSegment.trim());
            }
        }
        if (segments.isEmpty()) {
            return null;
        }
        if (segments.size() == 1) {
            return segments.get(0);
        }
        return segments.get(segments.size() - 2);
    }

    private String firstNonBlankAttribute(HttpServletRequest request, String... names) {
        if (request == null || names == null) {
            return null;
        }
        for (String name : names) {
            Object value = request.getAttribute(name);
            String text = text(value);
            if (StringUtils.hasText(text)) {
                return text;
            }
        }
        return null;
    }

    private Object firstNonNullAttribute(HttpServletRequest request, String... names) {
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

    private List<String> normalizeStringList(Object value) {
        if (value == null) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        if (value instanceof Collection<?> collection) {
            for (Object item : collection) {
                String text = text(item);
                if (StringUtils.hasText(text)) {
                    result.add(text);
                }
            }
            return result;
        }
        if (value.getClass().isArray()) {
            int length = Array.getLength(value);
            for (int i = 0; i < length; i++) {
                String text = text(Array.get(value, i));
                if (StringUtils.hasText(text)) {
                    result.add(text);
                }
            }
            return result;
        }
        String text = text(value);
        if (!StringUtils.hasText(text)) {
            return List.of();
        }
        for (String token : text.split("[,;\\n]")) {
            String normalized = token.trim();
            if (StringUtils.hasText(normalized)) {
                result.add(normalized);
            }
        }
        return result;
    }

    private String attrText(HCADContext context, String key) {
        if (context == null || context.getAdditionalAttributes() == null) {
            return null;
        }
        return text(context.getAdditionalAttributes().get(key));
    }

    private void putIfText(Map<String, Object> attrs, String key, String value) {
        if (attrs != null && StringUtils.hasText(value)) {
            attrs.put(key, value);
        }
    }

    private Boolean isBotUserAgent(String userAgent) {
        if (!StringUtils.hasText(userAgent)) {
            return null;
        }
        String normalized = userAgent.toLowerCase();
        return normalized.contains("bot")
                || normalized.contains("crawler")
                || normalized.contains("spider")
                || normalized.contains("python-requests")
                || normalized.contains("curl/")
                || normalized.contains("wget/")
                || normalized.contains("java/");
    }

    private String firstHeader(HttpServletRequest request, String... names) {
        if (request == null || names == null) {
            return null;
        }
        for (String name : names) {
            String value = request.getHeader(name);
            if (StringUtils.hasText(value)) {
                return value;
            }
        }
        return null;
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return StringUtils.hasText(text) ? text : null;
    }

    private void detectImpossibleTravel(HCADContext context, GeoIpService.GeoLocation currentLocation) {
        if (!currentLocation.hasCoordinates() || context.getUserId() == null || context.getUserId().startsWith("anonymous:") || securityContextDataStore == null) {
            return;
        }
        try {
            String userId = context.getUserId();
            String prevLocationKey = "geoloc:" + userId;

            String prevData = securityContextDataStore.getPreviousPath(prevLocationKey);

            String currentData = String.format("%f,%f,%d,%s,%s",
                    currentLocation.latitude(), currentLocation.longitude(),
                    System.currentTimeMillis(),
                    currentLocation.city() != null ? currentLocation.city() : "",
                    currentLocation.country() != null ? currentLocation.country() : "");

            if (prevData == null || prevData.isBlank()) {
                securityContextDataStore.setPreviousPath(prevLocationKey, currentData);
                return;
            }

            String[] parts = prevData.split(",", 5);
            if (parts.length < 3) {
                securityContextDataStore.setPreviousPath(prevLocationKey, currentData);
                return;
            }

            double prevLat = Double.parseDouble(parts[0]);
            double prevLon = Double.parseDouble(parts[1]);
            long prevTimeMs = Long.parseLong(parts[2]);
            String prevCity = parts.length > 3 ? parts[3] : "";
            String prevCountry = parts.length > 4 ? parts[4] : "";

            long elapsedMs = System.currentTimeMillis() - prevTimeMs;
            double distanceKm = GeoIpService.distanceKm(
                    prevLat, prevLon,
                    currentLocation.latitude(), currentLocation.longitude());

            if (GeoIpService.isImpossibleTravel(distanceKm, elapsedMs)) {
                Map<String, Object> attrs = context.getAdditionalAttributes();
                if (attrs == null) {
                    attrs = new HashMap<>();
                    context.setAdditionalAttributes(attrs);
                }
                attrs.put("impossibleTravel", true);
                attrs.put("travelDistanceKm", (int) distanceKm);
                attrs.put("travelElapsedMinutes", elapsedMs / 60000);
                attrs.put("previousLocation", prevCity.isEmpty() ? prevCountry : prevCity + ", " + prevCountry);

                log.error("[HCADContextExtractor] Impossible travel detected: userId={}, distance={}km, elapsed={}min",
                        userId, (int) distanceKm, elapsedMs / 60000);
                return; // [개선] 비정상 이동 시 갱신을 생략하여 이전의 유효한 위치를 고정/유지함
            }

            // 정상적인 이동일 경우에만 업데이트 수행
            securityContextDataStore.setPreviousPath(prevLocationKey, currentData);
        } catch (Exception e) {
            log.error("[HCADContextExtractor] Impossible travel detection failed", e);
        }
    }

    private Boolean matchesSensitiveResource(String path) {
        List<String> patterns = hcadProperties.getResource().getSensitivePatterns();
        if (patterns == null || patterns.isEmpty()) {
            return null;
        }
        for (String pattern : patterns) {
            if (pathMatcher.match(pattern, path)) {
                return true;
            }
        }
        return false;
    }

    private void putAdditionalAttribute(HCADContext context, String key, Object value) {
        Map<String, Object> attrs = context.getAdditionalAttributes();
        if (attrs == null) {
            attrs = new HashMap<>();
            context.setAdditionalAttributes(attrs);
        }
        attrs.put(key, value);
    }
}



