package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.autonomous.context.PromptRelevantRequestPathPolicy;
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

            String userId = extractUserId(authentication);
            String username = extractUsername(authentication);
            String sessionId = request.getRequestedSessionId();

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
                    .userId(authentication != null ? extractUserId(authentication) : "unknown")
                    .sessionId(request.getRequestedSessionId())
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

    private String extractUserId(Authentication authentication) {
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

    private String extractUsername(Authentication authentication) {
        return extractUserId(authentication);
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

        } catch (Exception e) {
            context.setIsNewSession(true);
            context.setIsNewDevice(true);
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

            String[] segments = path.split("/");
            String firstSegment = segments.length > 1 ? segments[1] : "";
            context.setResourceType(firstSegment);

            context.setIsSensitiveResource(matchesSensitiveResource(path));

            Map<String, Object> additionalAttrs = context.getAdditionalAttributes();
            if (additionalAttrs == null) {
                additionalAttrs = new HashMap<>();
            }
            String resourceSensitivity = resolveResourceSensitivity(path, context.getIsSensitiveResource());
            if (resourceSensitivity != null) {
                additionalAttrs.put("resourceSensitivity", resourceSensitivity);
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
