package io.contexa.contexacore.autonomous.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * User Identification Strategy for Zero Trust Architecture
 * 
 * Zero Trust 아키텍처를 위한 일관된 사용자 식별 전략
 * 
 * 핵심 원칙:
 * 1. userId = username (유니크한 문자열 식별자)
 * 2. 익명 사용자는 null 반환
 * 3. Long id는 DB 참조용으로만 사용
 * 
 * 이 전략은 모든 보안 이벤트와 컨텍스트에서 사용자를 일관되게 식별합니다.
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
public class UserIdentificationStrategy {
    
    private static final String ANONYMOUS_USER = "anonymousUser";
    
    /**
     * Authentication 객체에서 userId 추출
     * 
     * @param authentication Spring Security Authentication
     * @return userId (username) 또는 null (익명 사용자)
     */
    public static String getUserId(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return null; // 익명 사용자
        }
        
        // anonymousUser 체크
        if (ANONYMOUS_USER.equals(authentication.getPrincipal())) {
            return null;
        }
        
        // username을 userId로 사용 (유니크한 식별자)
        return authentication.getName();
    }
    
    /**
     * UserDto 객체에서 userId 추출 (리플렉션 사용)
     * 
     * @param userDto 사용자 DTO 객체
     * @return userId (username)
     */
    public static String getUserId(Object userDto) {
        if (userDto == null) {
            return null;
        }
        
        try {
            // getUsername() 메서드를 리플렉션으로 호출
            java.lang.reflect.Method getUsernameMethod = userDto.getClass().getMethod("getUsername");
            Object username = getUsernameMethod.invoke(userDto);
            
            if (username instanceof String) {
                return (String) username;
            }
        } catch (Exception e) {
            // 리플렉션 실패 시 null 반환
            return null;
        }
        
        return null;
    }
    
    /**
     * SecurityContextHolder에서 현재 사용자의 userId 추출
     * 
     * @return 현재 인증된 사용자의 userId 또는 null
     */
    public static String getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return getUserId(authentication);
    }
    
    /**
     * 현재 사용자가 인증되었는지 확인
     * 
     * @return 인증된 사용자면 true
     */
    public static boolean isAuthenticated() {
        String userId = getCurrentUserId();
        return userId != null && !userId.isEmpty();
    }
    
    /**
     * 현재 사용자가 익명 사용자인지 확인
     * 
     * @return 익명 사용자면 true
     */
    public static boolean isAnonymous() {
        return !isAuthenticated();
    }
    
    /**
     * userId 검증
     * 
     * @param userId 검증할 userId
     * @return 유효한 userId면 true
     */
    public static boolean isValidUserId(String userId) {
        return userId != null && !userId.trim().isEmpty() && !ANONYMOUS_USER.equals(userId);
    }
    
    /**
     * 두 userId가 동일한지 비교
     * 
     * @param userId1 첫 번째 userId
     * @param userId2 두 번째 userId
     * @return 동일하면 true
     */
    public static boolean isSameUser(String userId1, String userId2) {
        if (userId1 == null || userId2 == null) {
            return false;
        }
        return userId1.equals(userId2);
    }
    
    /**
     * 현재 사용자와 주어진 userId가 동일한지 확인
     * 
     * @param userId 비교할 userId
     * @return 현재 사용자와 동일하면 true
     */
    public static boolean isCurrentUser(String userId) {
        String currentUserId = getCurrentUserId();
        return isSameUser(currentUserId, userId);
    }
    
    /**
     * UserDto 객체에서 userId 추출 (null-safe, 리플렉션 사용)
     * Long id가 있으면 문자열로 변환하여 보조 정보로 사용
     * 
     * @param userDto 사용자 DTO 객체
     * @return userId와 id 정보를 포함한 문자열
     */
    public static String getUserIdWithContext(Object userDto) {
        if (userDto == null) {
            return null;
        }
        
        try {
            // getUsername() 메서드를 리플렉션으로 호출
            java.lang.reflect.Method getUsernameMethod = userDto.getClass().getMethod("getUsername");
            Object username = getUsernameMethod.invoke(userDto);
            
            if (username instanceof String) {
                return (String) username; // 실제로는 username만 사용
            }
        } catch (Exception e) {
            // 리플렉션 실패 시 null 반환
            return null;
        }
        
        return null;
    }
    
    /**
     * Zero Trust를 위한 사용자 식별 정보 생성
     * 
     * @param authentication 인증 객체
     * @param sessionId 세션 ID
     * @return 사용자 식별 정보
     */
    public static UserIdentity createUserIdentity(Authentication authentication, String sessionId) {
        String userId = getUserId(authentication);
        
        return UserIdentity.builder()
            .userId(userId)
            .sessionId(sessionId)
            .authenticated(userId != null)
            .timestamp(System.currentTimeMillis())
            .build();
    }
    
    /**
     * 사용자 식별 정보
     */
    public static class UserIdentity {
        private final String userId;
        private final String sessionId;
        private final boolean authenticated;
        private final long timestamp;
        
        private UserIdentity(Builder builder) {
            this.userId = builder.userId;
            this.sessionId = builder.sessionId;
            this.authenticated = builder.authenticated;
            this.timestamp = builder.timestamp;
        }
        
        public static Builder builder() {
            return new Builder();
        }
        
        public String getUserId() {
            return userId;
        }
        
        public String getSessionId() {
            return sessionId;
        }
        
        public boolean isAuthenticated() {
            return authenticated;
        }
        
        public long getTimestamp() {
            return timestamp;
        }
        
        public static class Builder {
            private String userId;
            private String sessionId;
            private boolean authenticated;
            private long timestamp;
            
            public Builder userId(String userId) {
                this.userId = userId;
                return this;
            }
            
            public Builder sessionId(String sessionId) {
                this.sessionId = sessionId;
                return this;
            }
            
            public Builder authenticated(boolean authenticated) {
                this.authenticated = authenticated;
                return this;
            }
            
            public Builder timestamp(long timestamp) {
                this.timestamp = timestamp;
                return this;
            }
            
            public UserIdentity build() {
                return new UserIdentity(this);
            }
        }
    }
}