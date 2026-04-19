package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.autonomous.context.policy.PromptRelevantRequestPathPolicy;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.utils.OfficialVerificationRequestContext;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import jakarta.servlet.http.HttpServletRequest;
import io.contexa.contexacore.properties.HcadProperties;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;
import org.springframework.util.AntPathMatcher;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
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

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public HCADContext extractContext(HttpServletRequest request, Authentication authentication) {
        long startTime = System.nanoTime();

        try {

            String clientIp = extractClientIp(request);

            String userId = extractUserId(request, authentication);
            String username = extractUsername(request, authentication);
            String sessionId = OfficialVerificationRequestContext.resolveSessionId(request);

            if (userId.startsWith("anonymous:")) {
                userId = "anonymous:" + clientIp;
                username = "anonymous:" + clientIp;
            }

            HCADContext context = new HCADContext();
            context.setUserId(userId);
            context.setSessionId(sessionId != null ? sessionId : "unknown");
            context.setUsername(username);
            context.setRequestPath(request.getRequestURI());
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
            enrichWithDeviceContext(context, request);
            enrichWithIntentSignals(context, request);

            boolean promptRelevantPath = PromptRelevantRequestPathPolicy.isPromptRelevantPath(context.getRequestPath());

            enrichWithSessionInfo(context, userId, sessionId, promptRelevantPath, observedAt);

            enrichWithRequestPattern(context, userId, request, promptRelevantPath, observedAt);

            enrichWithSecurityInfo(context, userId, authentication, promptRelevantPath);

            enrichWithResourceInfo(context, request);

            enrichWithGeoLocation(context, clientIp);

            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);

            return context;

        } catch (Exception e) {
            log.error("[HCAD] Context extraction failed", e);

            return HCADContext.builder()
                    .userId(authentication != null ? extractUserId(request, authentication) : "unknown")
                    .sessionId(OfficialVerificationRequestContext.resolveSessionId(request))
                    .requestPath(request.getRequestURI())
                    .httpMethod(request.getMethod())
                    .remoteIp(request.getRemoteAddr())
                    .timestamp(resolveObservedAt(request))
                    .isNewSession(true)
                    .isNewUser(true)
                    .isNewDevice(true)
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

                java.lang.reflect.Method getUsernameMethod = principal.getClass().getMethod("getUsername");
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
        String[] headers = {
                "X-Forwarded-For",
                "X-Real-IP",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP",
                "HTTP_CLIENT_IP",
                "HTTP_X_FORWARDED_FOR"
        };

        for (String header : headers) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {

                if (ip.contains(",")) {
                    return ip.split(",")[0].trim();
                }
                return ip.trim();
            }
        }

        return request.getRemoteAddr();
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

            if (promptRelevantPath && isNewSession) {
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
            context.setIsNewSession(true);
            context.setIsNewDevice(true);
            context.setSessionAgeMinutes(0);
        }
    }

    private boolean checkAndRegisterDevice(String userId, String currentDevice, boolean promptRelevantPath) {
        if (userId == null || currentDevice == null || currentDevice.isEmpty()) {
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
            return true;
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
            String requestPath = request.getRequestURI();

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
                                        Authentication authentication,
                                        boolean promptRelevantPath) {
        try {

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

            String authMethod = authentication.getAuthorities().stream()
                    .anyMatch(auth -> auth.getAuthority().contains("MFA")) ? "mfa" : "password";
            context.setAuthenticationMethod(authMethod);
            context.setAuthenticationType(authMethod);

            boolean hasMfa = resolveMfaVerified(userId);
            context.setHasValidMFA(hasMfa);

            Set<String> authorities = authentication.getAuthorities().stream()
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

        } catch (Exception e) {

            context.setCurrentTrustScore(Double.NaN);
            context.setBaselineConfidence(Double.NaN);
            context.setFailedLoginAttempts(0);
            context.setHasValidMFA(false);
            context.setNewUser(true);
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
                // fall through
            }
        }
        return hcadDataStore.isMfaVerified(userId);
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
            String path = request.getRequestURI();
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
            String explicitSensitivity = firstNonBlankAttribute(request,
                    "hcad.resource_sensitivity",
                    "hcad.resourceSensitivity",
                    "resourceSensitivity",
                    "sensitivity");

            context.setResourceType(StringUtils.hasText(explicitResourceType)
                    ? explicitResourceType
                    : resolveResourceTypeFromPath(path));

            Boolean sensitiveResource = matchesSensitiveResource(path);
            if (!StringUtils.hasText(explicitSensitivity) && Boolean.TRUE.equals(sensitiveResource)) {
                explicitSensitivity = "HIGH";
            }
            context.setIsSensitiveResource(Boolean.TRUE.equals(sensitiveResource)
                    || "HIGH".equalsIgnoreCase(explicitSensitivity)
                    || "CRITICAL".equalsIgnoreCase(explicitSensitivity));

            Map<String, Object> additionalAttrs = context.getAdditionalAttributes();
            if (additionalAttrs == null) {
                additionalAttrs = new HashMap<>();
            }
            String resourceSensitivity = StringUtils.hasText(explicitSensitivity)
                    ? explicitSensitivity
                    : resolveResourceSensitivity(path, context.getIsSensitiveResource());
            if (StringUtils.hasText(explicitResourceId)) {
                additionalAttrs.put("resourceId", explicitResourceId);
            }
            if (StringUtils.hasText(context.getResourceType())) {
                additionalAttrs.put("resourceType", context.getResourceType());
                additionalAttrs.put("resourceCategory", context.getResourceType());
            }
            if (resourceSensitivity != null) {
                additionalAttrs.put("resourceSensitivity", resourceSensitivity);
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
        Instant observedAt = io.contexa.contexacore.autonomous.utils.RequestInfoExtractor.extractObservedAt(request);
        return observedAt != null ? observedAt : Instant.now();
    }

    private String resolveResourceSensitivity(String path, Boolean sensitiveResource) {
        if (path != null) {
            String lowerPath = path.toLowerCase();
            if (lowerPath.contains("/critical/")) {
                return "CRITICAL";
            }
            if (lowerPath.contains("/sensitive/")) {
                return "HIGH";
            }
        }
        if (Boolean.TRUE.equals(sensitiveResource)) {
            return "HIGH";
        }
        return null;
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
        java.util.ArrayList<String> segments = new java.util.ArrayList<>();
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

    private String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return StringUtils.hasText(text) ? text : null;
    }

    private void detectImpossibleTravel(HCADContext context, GeoIpService.GeoLocation currentLocation) {
        if (!currentLocation.hasCoordinates() || context.getUserId() == null || securityContextDataStore == null) {
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
            securityContextDataStore.setPreviousPath(prevLocationKey, currentData);

            if (prevData == null || prevData.isBlank()) {
                return;
            }

            String[] parts = prevData.split(",", 5);
            if (parts.length < 3) {
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
                    attrs = new java.util.HashMap<>();
                    context.setAdditionalAttributes(attrs);
                }
                attrs.put("impossibleTravel", true);
                attrs.put("travelDistanceKm", (int) distanceKm);
                attrs.put("travelElapsedMinutes", elapsedMs / 60000);
                attrs.put("previousLocation", prevCity.isEmpty() ? prevCountry : prevCity + ", " + prevCountry);

                log.error("[HCADContextExtractor] Impossible travel detected: userId={}, distance={}km, elapsed={}min",
                        userId, (int) distanceKm, elapsedMs / 60000);
            }
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
}



