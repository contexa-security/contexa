package io.contexa.contexamcp.service;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserSessionService {
    
    private final RedisTemplate<String, Object> redisTemplate;
    
    private static final String SESSION_KEY_PREFIX = "session:";
    private static final String USER_SESSIONS_KEY_PREFIX = "user:sessions:";
    private static final long SESSION_TIMEOUT_MINUTES = 30;

    public SessionInfo createSession(String userId, String ipAddress, String userAgent) {
        String sessionId = UUID.randomUUID().toString();
        
        SessionInfo session = SessionInfo.builder()
            .sessionId(sessionId)
            .userId(userId)
            .ipAddress(ipAddress)
            .userAgent(userAgent)
            .createdAt(Instant.now())
            .lastAccessedAt(Instant.now())
            .active(true)
            .build();

        String sessionKey = SESSION_KEY_PREFIX + sessionId;
        redisTemplate.opsForValue().set(sessionKey, session, SESSION_TIMEOUT_MINUTES, TimeUnit.MINUTES);

        String userSessionsKey = USER_SESSIONS_KEY_PREFIX + userId;
        redisTemplate.opsForSet().add(userSessionsKey, sessionId);
        redisTemplate.expire(userSessionsKey, SESSION_TIMEOUT_MINUTES, TimeUnit.MINUTES);

        return session;
    }

    public List<SessionInfo> findActiveSessionsByUserId(String userId) {
        String userSessionsKey = USER_SESSIONS_KEY_PREFIX + userId;
        Set<Object> sessionIds = redisTemplate.opsForSet().members(userSessionsKey);
        
        if (sessionIds == null || sessionIds.isEmpty()) {
            return Collections.emptyList();
        }
        
        List<Object> staleSessionIds = new ArrayList<>();
        List<SessionInfo> result = new ArrayList<>();

        for (Object id : sessionIds) {
            String sessionKey = SESSION_KEY_PREFIX + id;
            SessionInfo session = (SessionInfo) redisTemplate.opsForValue().get(sessionKey);
            if (session == null) {
                staleSessionIds.add(id);
            } else if (session.isActive()) {
                result.add(session);
            }
        }

        // Lazy cleanup: remove stale session IDs whose session keys have expired
        if (!staleSessionIds.isEmpty()) {
            redisTemplate.opsForSet().remove(userSessionsKey, staleSessionIds.toArray());
            log.error("Cleaned up {} stale session index entries for user {}", staleSessionIds.size(), userId);
        }

        return result;
    }

    public boolean terminateSession(String sessionId) {
        String sessionKey = SESSION_KEY_PREFIX + sessionId;
        SessionInfo session = (SessionInfo) redisTemplate.opsForValue().get(sessionKey);
        
        if (session == null) {
            log.error("Session not found: {}", sessionId);
            return false;
        }

        session.setActive(false);
        session.setTerminatedAt(Instant.now());
        redisTemplate.opsForValue().set(sessionKey, session, 1, TimeUnit.MINUTES); 

        String userSessionsKey = USER_SESSIONS_KEY_PREFIX + session.getUserId();
        redisTemplate.opsForSet().remove(userSessionsKey, sessionId);

        return true;
    }

    public int terminateAllUserSessions(String userId) {
        List<SessionInfo> sessions = findActiveSessionsByUserId(userId);
        int terminated = 0;
        
        for (SessionInfo session : sessions) {
            if (terminateSession(session.getSessionId())) {
                terminated++;
            }
        }

        return terminated;
    }

    public void refreshSession(String sessionId) {
        String sessionKey = SESSION_KEY_PREFIX + sessionId;
        SessionInfo session = (SessionInfo) redisTemplate.opsForValue().get(sessionKey);

        if (session != null && session.isActive()) {
            session.setLastAccessedAt(Instant.now());
            redisTemplate.opsForValue().set(sessionKey, session, SESSION_TIMEOUT_MINUTES, TimeUnit.MINUTES);

            // Sync user session index TTL with session TTL
            String userSessionsKey = USER_SESSIONS_KEY_PREFIX + session.getUserId();
            redisTemplate.expire(userSessionsKey, SESSION_TIMEOUT_MINUTES, TimeUnit.MINUTES);
        }
    }

    public Optional<SessionInfo> getSession(String sessionId) {
        String sessionKey = SESSION_KEY_PREFIX + sessionId;
        SessionInfo session = (SessionInfo) redisTemplate.opsForValue().get(sessionKey);
        return Optional.ofNullable(session);
    }

    public void cleanupExpiredSessions() {
        Set<String> userSessionKeys = redisTemplate.keys(USER_SESSIONS_KEY_PREFIX + "*");
        if (userSessionKeys == null || userSessionKeys.isEmpty()) {
            return;
        }

        int totalCleaned = 0;
        for (String userSessionsKey : userSessionKeys) {
            Set<Object> sessionIds = redisTemplate.opsForSet().members(userSessionsKey);
            if (sessionIds == null || sessionIds.isEmpty()) {
                continue;
            }

            List<Object> staleIds = new ArrayList<>();
            for (Object id : sessionIds) {
                String sessionKey = SESSION_KEY_PREFIX + id;
                if (Boolean.FALSE.equals(redisTemplate.hasKey(sessionKey))) {
                    staleIds.add(id);
                }
            }

            if (!staleIds.isEmpty()) {
                redisTemplate.opsForSet().remove(userSessionsKey, staleIds.toArray());
                totalCleaned += staleIds.size();
            }
        }

        if (totalCleaned > 0) {
            log.error("Expired session cleanup completed: removed {} stale entries", totalCleaned);
        }
    }

    @Data
    @Builder
    public static class SessionInfo {
        private String sessionId;
        private String userId;
        private String ipAddress;
        private String userAgent;
        private Instant createdAt;
        private Instant lastAccessedAt;
        private Instant terminatedAt;
        private boolean active;
        private Map<String, Object> attributes;
    }
}