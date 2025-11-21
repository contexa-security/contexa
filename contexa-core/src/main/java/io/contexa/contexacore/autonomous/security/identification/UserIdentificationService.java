package io.contexa.contexacore.autonomous.security.identification;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;

import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Map;

/**
 * 사용자 식별 서비스
 * 
 * 모든 시나리오에서 사용자 ID를 안정적으로 추출합니다.
 * - 로그인 성공
 * - 로그인 실패
 * - 인가 실패
 * - JWT 토큰
 * - OAuth2
 * - Anonymous
 */
@Slf4j
public class UserIdentificationService {
    
    private static final String USERNAME_PARAM = "username";
    private static final String EMAIL_PARAM = "email";
    private static final String USER_ID_PARAM = "userId";
    private static final String LOGIN_ID_PARAM = "loginId";
    
    /**
     * 모든 가능한 소스에서 사용자 ID 추출
     * 
     * @param request HTTP 요청
     * @param authentication 인증 객체 (nullable)
     * @param exception 예외 (로그인 실패시)
     * @return 사용자 ID 또는 null
     */
    public String extractUserId(HttpServletRequest request, 
                                Authentication authentication, 
                                Exception exception) {
        
        // 1. Authentication 객체에서 추출 시도
        String userId = extractFromAuthentication(authentication);
        if (userId != null) {
            log.trace("Authentication에서 userId 추출: {}", userId);
            return userId;
        }
        
        // 2. Request Principal 에서 추출 시도
        userId = extractFromPrincipal(request);
        if (userId != null) {
            log.trace("Principal에서 userId 추출: {}", userId);
            return userId;
        }
        
        // 3. Request Parameter 에서 추출 시도 (로그인 실패시)
        userId = extractFromRequestParameters(request);
        if (userId != null) {
            log.trace("Request Parameter에서 userId 추출: {}", userId);
            return userId;
        }
        
        // 4. Request Body 에서 추출 시도 (JSON 로그인)
        userId = extractFromRequestBody(request);
        if (userId != null) {
            log.trace("Request Body에서 userId 추출: {}", userId);
            return userId;
        }
        
        // 5. Session 에서 추출 시도
        userId = extractFromSession(request);
        if (userId != null) {
            log.trace("Session에서 userId 추출: {}", userId);
            return userId;
        }
        
        // 6. JWT Token 에서 추출 시도
        userId = extractFromJwtToken(request);
        if (userId != null) {
            log.trace("JWT Token에서 userId 추출: {}", userId);
            return userId;
        }
        
        // 7. Exception 메시지에서 추출 시도 (최후의 수단)
        userId = extractFromException(exception);
        if (userId != null) {
            log.trace("Exception에서 userId 추출: {}", userId);
            return userId;
        }
        
        // 8. Anonymous 사용자 처리
        String anonymousId = generateAnonymousId(request);
        log.debug("Anonymous userId 생성: {}", anonymousId);
        return anonymousId;
    }
    
    /**
     * Authentication 객체에서 사용자 ID 추출
     */
    private String extractFromAuthentication(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        
        Object principal = authentication.getPrincipal();
        
        // UserDetails 타입 (Spring Security 표준)
        if (principal instanceof UserDetails userDetails) {
            return userDetails.getUsername();
        }
        
        // Custom User DTO 타입 (리플렉션으로 처리)
        if (principal.getClass().getSimpleName().contains("UserDto")) {
            try {
                Method getUsernameMethod = principal.getClass().getMethod("getUsername");
                Object username = getUsernameMethod.invoke(principal);
                if (username != null) {
                    return username.toString();
                }
            } catch (Exception e) {
                log.debug("UserDto 리플렉션 실패: {}", e.getMessage());
            }
        }
        
        // JWT Authentication
        if (authentication instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
            Jwt jwt = jwtAuth.getToken();
            
            // JWT claims 에서 추출
            String userId = jwt.getClaimAsString("sub");
            if (userId != null) return userId;
            
            userId = jwt.getClaimAsString("user_id");
            if (userId != null) return userId;
            
            userId = jwt.getClaimAsString("username");
            if (userId != null) return userId;
        }
        
        // Username Password Authentication
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            return authentication.getName();
        }
        
        // String principal
        if (principal instanceof String) {
            return (String) principal;
        }
        
        // 기본값
        return authentication.getName();
    }
    
    /**
     * Request Principal에서 추출
     */
    private String extractFromPrincipal(HttpServletRequest request) {
        Principal principal = request.getUserPrincipal();
        if (principal != null) {
            return principal.getName();
        }
        return null;
    }
    
    /**
     * Request Parameter에서 추출 (Form 로그인)
     */
    private String extractFromRequestParameters(HttpServletRequest request) {
        // username 파라미터
        String username = request.getParameter(USERNAME_PARAM);
        if (username != null && !username.isEmpty()) {
            return username;
        }
        
        // email 파라미터
        String email = request.getParameter(EMAIL_PARAM);
        if (email != null && !email.isEmpty()) {
            return email;
        }
        
        // userId 파라미터
        String userId = request.getParameter(USER_ID_PARAM);
        if (userId != null && !userId.isEmpty()) {
            return userId;
        }
        
        // loginId 파라미터
        String loginId = request.getParameter(LOGIN_ID_PARAM);
        if (loginId != null && !loginId.isEmpty()) {
            return loginId;
        }
        
        return null;
    }
    
    /**
     * Request Body에서 추출 (JSON 로그인)
     */
    private String extractFromRequestBody(HttpServletRequest request) {
        // Content-Type 확인
        String contentType = request.getContentType();
        if (contentType == null || !contentType.contains("application/json")) {
            return null;
        }
        
        // Request Attribute에서 파싱된 body 확인
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
    
    /**
     * Session에서 추출
     */
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
    
    /**
     * JWT Token에서 추출
     */
    private String extractFromJwtToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            
            try {
                // JWT 파싱 (간단한 Base64 디코딩)
                String[] parts = token.split("\\.");
                if (parts.length >= 2) {
                    String payload = parts[1];
                    // Base64 디코딩 및 JSON 파싱
                    java.util.Base64.Decoder decoder = java.util.Base64.getUrlDecoder();
                    String json = new String(decoder.decode(payload));
                    
                    // 간단한 JSON 파싱 (정규식)
                    java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"sub\"\\s*:\\s*\"([^\"]+)\"");
                    java.util.regex.Matcher matcher = pattern.matcher(json);
                    if (matcher.find()) {
                        return matcher.group(1);
                    }
                    
                    pattern = java.util.regex.Pattern.compile("\"user_id\"\\s*:\\s*\"([^\"]+)\"");
                    matcher = pattern.matcher(json);
                    if (matcher.find()) {
                        return matcher.group(1);
                    }
                }
            } catch (Exception e) {
                log.debug("JWT 파싱 실패", e);
            }
        }
        return null;
    }
    
    /**
     * Exception 메시지에서 추출
     */
    private String extractFromException(Exception exception) {
        if (exception == null) {
            return null;
        }
        
        String message = exception.getMessage();
        if (message != null) {
            // "User 'username' not found" 패턴
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("User '([^']+)'");
            java.util.regex.Matcher matcher = pattern.matcher(message);
            if (matcher.find()) {
                return matcher.group(1);
            }
            
            // "Username: xxx" 패턴
            pattern = java.util.regex.Pattern.compile("Username:\\s*(\\S+)");
            matcher = pattern.matcher(message);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        
        return null;
    }
    
    /**
     * Anonymous 사용자 ID 생성
     */
    private String generateAnonymousId(HttpServletRequest request) {
        String ip = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        
        if (ip == null) ip = "unknown";
        if (userAgent == null) userAgent = "unknown";
        
        // IP + UserAgent 해시
        String combined = ip + ":" + userAgent;
        int hash = combined.hashCode();
        
        return "anonymous_" + Integer.toHexString(hash);
    }
    
    /**
     * 클라이언트 IP 추출
     */
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
    
    /**
     * WebAuthenticationDetails에서 사용자 정보 추출
     */
    public String extractFromWebDetails(WebAuthenticationDetails details) {
        if (details == null) {
            return null;
        }
        
        // Session ID를 기반으로 사용자 추적
        String sessionId = details.getSessionId();
        if (sessionId != null) {
            // Session ID를 해시하여 익명 ID 생성
            return "session_" + Integer.toHexString(sessionId.hashCode());
        }
        
        return null;
    }
    
    /**
     * OAuth2 인증에서 사용자 ID 추출
     */
    public String extractFromOAuth2(Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        
        // OAuth2 principal 처리
        Object principal = authentication.getPrincipal();
        if (principal instanceof Map) {
            Map<String, Object> attributes = (Map<String, Object>) principal;
            
            // 다양한 OAuth2 provider의 ID 필드 확인
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