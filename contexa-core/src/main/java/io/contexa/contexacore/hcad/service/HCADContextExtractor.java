package io.contexa.contexacore.hcad.service;

import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import jakarta.servlet.http.HttpServletRequest;
import io.contexa.contexacore.properties.HcadProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@RequiredArgsConstructor
public class HCADContextExtractor {

    private final RedisTemplate<String, Object> redisTemplate;
    private final HcadProperties hcadProperties;

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
            
            String userAgent;
            if (hcadProperties.isEnableSimulatedUserAgent()) {
                userAgent = request.getHeader("X-Simulated-User-Agent");
                if (userAgent == null || userAgent.isEmpty()) {
                    userAgent = request.getHeader("User-Agent");
                }
            } else {
                userAgent = request.getHeader("User-Agent");
            }
            context.setUserAgent(userAgent != null ? userAgent : "unknown");
            context.setReferer(request.getHeader("Referer"));
            context.setTimestamp(Instant.now());

            enrichWithSessionInfo(context, userId, sessionId);

            enrichWithRequestPattern(context, userId, request);

            enrichWithSecurityInfo(context, userId, authentication);

            enrichWithResourceInfo(context, request);

            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
            
            return context;

        } catch (Exception e) {
            log.error("[HCAD] 컨텍스트 추출 실패", e);
            
            return HCADContext.builder()
                .userId(authentication != null ? extractUserId(authentication) : "unknown")
                .sessionId(request.getRequestedSessionId())
                .requestPath(request.getRequestURI())
                .httpMethod(request.getMethod())
                .remoteIp(request.getRemoteAddr())
                .timestamp(Instant.now())
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
                                      String userId, String sessionId) {
        try {
            
            String sessionKey = ZeroTrustRedisKeys.sessionMetadata(sessionId);
            Map<Object, Object> sessionInfo = redisTemplate.opsForHash().entries(sessionKey);

            boolean isNewSession = (sessionInfo == null || sessionInfo.isEmpty());
            context.setIsNewSession(isNewSession);

            String currentDevice = context.getUserAgent();
            boolean isNewDevice = checkAndRegisterDevice(userId, currentDevice);
            context.setIsNewDevice(isNewDevice);

            if (isNewSession) {
                Map<String, Object> newSessionInfo = new HashMap<>();
                newSessionInfo.put("userId", userId);
                newSessionInfo.put("device", currentDevice);
                newSessionInfo.put("createdAt", Instant.now().toString());
                redisTemplate.opsForHash().putAll(sessionKey, newSessionInfo);
                redisTemplate.expire(sessionKey, Duration.ofHours(24));
            }

        } catch (Exception e) {
                        context.setIsNewSession(true);
            context.setIsNewDevice(true);
        }
    }

    private boolean checkAndRegisterDevice(String userId, String currentDevice) {
        if (userId == null || currentDevice == null || currentDevice.isEmpty()) {
            return true;  
        }

        try {
            String deviceKey = ZeroTrustRedisKeys.userDevices(userId);

            Boolean isMember = redisTemplate.opsForSet().isMember(deviceKey, currentDevice);

            if (Boolean.TRUE.equals(isMember)) {
                
                return false;
            } else {
                
                redisTemplate.opsForSet().add(deviceKey, currentDevice);
                redisTemplate.expire(deviceKey, Duration.ofDays(30));

                Long size = redisTemplate.opsForSet().size(deviceKey);
                if (size != null && size > 10) {
                    
                    Object oldDevice = redisTemplate.opsForSet().randomMember(deviceKey);
                    if (oldDevice != null && !oldDevice.equals(currentDevice)) {
                        redisTemplate.opsForSet().remove(deviceKey, oldDevice);
                    }
                }

                return true;
            }
        } catch (Exception e) {
                        return true;  
        }
    }

    private void enrichWithRequestPattern(HCADContext context,
                                         String userId, HttpServletRequest request) {
        try {
            
            String counterKey = "hcad:request:counter:" + userId;

            long currentTime = System.currentTimeMillis();
            redisTemplate.opsForZSet().add(counterKey, Long.toString(currentTime), currentTime);

            long fiveMinutesAgo = currentTime - (5 * 60 * 1000);

            redisTemplate.opsForZSet().removeRangeByScore(counterKey, 0, fiveMinutesAgo);

            Long recentCount = redisTemplate.opsForZSet().count(counterKey, fiveMinutesAgo, currentTime);
            context.setRecentRequestCount(recentCount != null ? recentCount.intValue() : 1);

            String lastRequestKey = "hcad:last:request:" + userId;
            String lastRequestTime = (String) redisTemplate.opsForValue().get(lastRequestKey);
            if (lastRequestTime != null) {
                long interval = currentTime - Long.parseLong(lastRequestTime);
                context.setLastRequestInterval(interval);
            } else {
                context.setLastRequestInterval(0L);
            }

            redisTemplate.opsForValue().set(lastRequestKey, Long.toString(currentTime),
                Duration.ofMinutes(10));

            String previousPathKey = "hcad:previous:path:" + userId;
            String previousPath = (String) redisTemplate.opsForValue().get(previousPathKey);
            context.setPreviousPath(previousPath);
            redisTemplate.opsForValue().set(previousPathKey, request.getRequestURI(),
                Duration.ofMinutes(10));

        } catch (Exception e) {
                        context.setRecentRequestCount(0);
            context.setLastRequestInterval(0L);
        }
    }

    private void enrichWithSecurityInfo(HCADContext context,
                                       String userId, Authentication authentication) {
        try {

            String registeredKey = ZeroTrustRedisKeys.userRegistered(userId);
            Boolean isRegistered = redisTemplate.hasKey(registeredKey);

            if (!isRegistered) {
                
                redisTemplate.opsForValue().set(registeredKey, "true");
                context.setNewUser(true);
                            } else {
                
                context.setNewUser(false);
                            }

            context.setCurrentTrustScore(Double.NaN);

            context.setBaselineConfidence(Double.NaN);

            context.setFailedLoginAttempts(0);

            String authMethod = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().contains("MFA")) ? "mfa" : "password";
            context.setAuthenticationMethod(authMethod);

            String mfaKey = "security:mfa:verified:" + userId;
            Boolean hasMfa = redisTemplate.hasKey(mfaKey);
            context.setHasValidMFA(hasMfa);

            if (Boolean.TRUE.equals(context.getIsNewUser())) {
                            }

        } catch (Exception e) {
                        
            context.setCurrentTrustScore(Double.NaN);
            context.setBaselineConfidence(Double.NaN);
            context.setFailedLoginAttempts(0);
            context.setHasValidMFA(false);
            context.setNewUser(true); 
        }
    }

    private void enrichWithResourceInfo(HCADContext context,
                                       HttpServletRequest request) {
        try {
            String path = request.getRequestURI();

            String[] segments = path.split("/");
            String firstSegment = segments.length > 1 ? segments[1] : "";
            context.setResourceType(firstSegment); 

            context.setIsSensitiveResource(null);

            Map<String, Object> additionalAttrs = new HashMap<>();
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
}