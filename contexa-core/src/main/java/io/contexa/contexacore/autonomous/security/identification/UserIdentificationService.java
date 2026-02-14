package io.contexa.contexacore.autonomous.security.identification;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;

import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Map;

@Slf4j
public class UserIdentificationService {

    private static final String USERNAME_PARAM = "username";
    private static final String EMAIL_PARAM = "email";
    private static final String USER_ID_PARAM = "userId";
    private static final String LOGIN_ID_PARAM = "loginId";

    @Autowired(required = false)
    private JwtDecoder jwtDecoder;

    public String extractUserId(HttpServletRequest request, 
                                Authentication authentication, 
                                Exception exception) {

        String userId = extractFromAuthentication(authentication);
        if (userId != null) {
                        return userId;
        }

        userId = extractFromPrincipal(request);
        if (userId != null) {
                        return userId;
        }

        userId = extractFromRequestParameters(request);
        if (userId != null) {
                        return userId;
        }

        userId = extractFromRequestBody(request);
        if (userId != null) {
                        return userId;
        }

        userId = extractFromSession(request);
        if (userId != null) {
                        return userId;
        }

        userId = extractFromJwtToken(request);
        if (userId != null) {
                        return userId;
        }

        userId = extractFromException(exception);
        if (userId != null) {
                        return userId;
        }

        String anonymousId = generateAnonymousId(request);
                return anonymousId;
    }

    private String extractFromAuthentication(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        
        Object principal = authentication.getPrincipal();

        if (principal instanceof UserDetails userDetails) {
            return userDetails.getUsername();
        }

        if (principal.getClass().getSimpleName().contains("UserDto")) {
            try {
                Method getUsernameMethod = principal.getClass().getMethod("getUsername");
                Object username = getUsernameMethod.invoke(principal);
                if (username != null) {
                    return username.toString();
                }
            } catch (Exception e) {
                            }
        }

        if (authentication instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
            Jwt jwt = jwtAuth.getToken();

            String userId = jwt.getClaimAsString("sub");
            if (userId != null) return userId;
            
            userId = jwt.getClaimAsString("user_id");
            if (userId != null) return userId;
            
            userId = jwt.getClaimAsString("username");
            if (userId != null) return userId;
        }

        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            return authentication.getName();
        }

        if (principal instanceof String) {
            return (String) principal;
        }

        return authentication.getName();
    }

    private String extractFromPrincipal(HttpServletRequest request) {
        Principal principal = request.getUserPrincipal();
        if (principal != null) {
            return principal.getName();
        }
        return null;
    }

    private String extractFromRequestParameters(HttpServletRequest request) {
        
        String username = request.getParameter(USERNAME_PARAM);
        if (username != null && !username.isEmpty()) {
            return username;
        }

        String email = request.getParameter(EMAIL_PARAM);
        if (email != null && !email.isEmpty()) {
            return email;
        }

        String userId = request.getParameter(USER_ID_PARAM);
        if (userId != null && !userId.isEmpty()) {
            return userId;
        }

        String loginId = request.getParameter(LOGIN_ID_PARAM);
        if (loginId != null && !loginId.isEmpty()) {
            return loginId;
        }
        
        return null;
    }

    private String extractFromRequestBody(HttpServletRequest request) {
        
        String contentType = request.getContentType();
        if (contentType == null || !contentType.contains("application/json")) {
            return null;
        }

        Object body = request.getAttribute("parsedBody");
        if (body instanceof Map) {
            Map<String, Object> bodyMap = (Map<String, Object>) body;
            
            Object username = bodyMap.get(USERNAME_PARAM);
            if (username != null) return username.toString();
            
            Object email = bodyMap.get(EMAIL_PARAM);
            if (email != null) return email.toString();
            
            Object userId = bodyMap.get(USER_ID_PARAM);
            if (userId != null) return userId.toString();
        }
        
        return null;
    }

    private String extractFromSession(HttpServletRequest request) {
        if (request.getSession(false) != null) {
            Object userId = request.getSession().getAttribute("userId");
            if (userId != null) {
                return userId.toString();
            }
            
            Object username = request.getSession().getAttribute("username");
            if (username != null) {
                return username.toString();
            }
        }
        return null;
    }

    private String extractFromJwtToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }

        String token = authHeader.substring(7);

        if (jwtDecoder != null) {
            try {
                Jwt jwt = jwtDecoder.decode(token);

                String userId = jwt.getClaimAsString("sub");
                if (userId != null && !userId.isEmpty()) {
                                        return userId;
                }

                userId = jwt.getClaimAsString("user_id");
                if (userId != null && !userId.isEmpty()) {
                                        return userId;
                }

                userId = jwt.getClaimAsString("username");
                if (userId != null && !userId.isEmpty()) {
                                        return userId;
                }

                                return null;

            } catch (JwtException e) {
                log.error("[ZeroTrust] JWT signature verification failed - forged or expired token: {}", e.getMessage());
                return null;
            } catch (Exception e) {
                log.error("[ZeroTrust] JWT decoding exception", e);
                return null;
            }
        }

        log.error("[ZeroTrust] JwtDecoder not configured - cannot extract userId from JWT without signature verification");
        return null;
    }

    private String extractFromException(Exception exception) {
        if (exception == null) {
            return null;
        }
        
        String message = exception.getMessage();
        if (message != null) {
            
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("User '([^']+)'");
            java.util.regex.Matcher matcher = pattern.matcher(message);
            if (matcher.find()) {
                return matcher.group(1);
            }

            pattern = java.util.regex.Pattern.compile("Username:\\s*(\\S+)");
            matcher = pattern.matcher(message);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        
        return null;
    }

    private String generateAnonymousId(HttpServletRequest request) {
        String ip = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        
        if (ip == null) ip = "unknown";
        if (userAgent == null) userAgent = "unknown";

        String combined = ip + ":" + userAgent;
        int hash = combined.hashCode();
        
        return "anonymous_" + Integer.toHexString(hash);
    }

    private String getClientIp(HttpServletRequest request) {
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

    public String extractFromWebDetails(WebAuthenticationDetails details) {
        if (details == null) {
            return null;
        }

        String sessionId = details.getSessionId();
        if (sessionId != null) {
            
            return "session_" + Integer.toHexString(sessionId.hashCode());
        }
        
        return null;
    }

    public String extractFromOAuth2(Authentication authentication) {
        if (authentication == null) {
            return null;
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof Map) {
            Map<String, Object> attributes = (Map<String, Object>) principal;

            Object id = attributes.get("id");
            if (id != null) return id.toString();
            
            id = attributes.get("sub");
            if (id != null) return id.toString();
            
            id = attributes.get("email");
            if (id != null) return id.toString();
            
            id = attributes.get("login");
            if (id != null) return id.toString();
        }
        
        return authentication.getName();
    }
}