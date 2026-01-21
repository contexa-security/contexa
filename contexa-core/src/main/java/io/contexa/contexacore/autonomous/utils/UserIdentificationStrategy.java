package io.contexa.contexacore.autonomous.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class UserIdentificationStrategy {
    
    private static final String ANONYMOUS_USER = "anonymousUser";

    public static String getUserId(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return null; 
        }

        if (ANONYMOUS_USER.equals(authentication.getPrincipal())) {
            return null;
        }

        return authentication.getName();
    }

    public static String getUserId(Object userDto) {
        if (userDto == null) {
            return null;
        }
        
        try {
            
            java.lang.reflect.Method getUsernameMethod = userDto.getClass().getMethod("getUsername");
            Object username = getUsernameMethod.invoke(userDto);
            
            if (username instanceof String) {
                return (String) username;
            }
        } catch (Exception e) {
            
            return null;
        }
        
        return null;
    }

    public static String getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return getUserId(authentication);
    }

    public static boolean isAuthenticated() {
        String userId = getCurrentUserId();
        return userId != null && !userId.isEmpty();
    }

    public static boolean isAnonymous() {
        return !isAuthenticated();
    }

    public static boolean isValidUserId(String userId) {
        return userId != null && !userId.trim().isEmpty() && !ANONYMOUS_USER.equals(userId);
    }

    public static boolean isSameUser(String userId1, String userId2) {
        if (userId1 == null || userId2 == null) {
            return false;
        }
        return userId1.equals(userId2);
    }

    public static boolean isCurrentUser(String userId) {
        String currentUserId = getCurrentUserId();
        return isSameUser(currentUserId, userId);
    }

    public static String getUserIdWithContext(Object userDto) {
        if (userDto == null) {
            return null;
        }
        
        try {
            
            java.lang.reflect.Method getUsernameMethod = userDto.getClass().getMethod("getUsername");
            Object username = getUsernameMethod.invoke(userDto);
            
            if (username instanceof String) {
                return (String) username; 
            }
        } catch (Exception e) {
            
            return null;
        }
        
        return null;
    }

    public static UserIdentity createUserIdentity(Authentication authentication, String sessionId) {
        String userId = getUserId(authentication);
        
        return UserIdentity.builder()
            .userId(userId)
            .sessionId(sessionId)
            .authenticated(userId != null)
            .timestamp(System.currentTimeMillis())
            .build();
    }

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