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
import java.util.stream.Collectors;


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
        
        log.info("Session created: {} for user: {}", sessionId, userId);
        
        return session;
    }
    
    
    public List<SessionInfo> findActiveSessionsByUserId(String userId) {
        String userSessionsKey = USER_SESSIONS_KEY_PREFIX + userId;
        Set<Object> sessionIds = redisTemplate.opsForSet().members(userSessionsKey);
        
        if (sessionIds == null || sessionIds.isEmpty()) {
            return Collections.emptyList();
        }
        
        return sessionIds.stream()
            .map(id -> SESSION_KEY_PREFIX + id)
            .map(key -> (SessionInfo) redisTemplate.opsForValue().get(key))
            .filter(Objects::nonNull)
            .filter(SessionInfo::isActive)
            .collect(Collectors.toList());
    }
    
    
    public boolean terminateSession(String sessionId) {
        String sessionKey = SESSION_KEY_PREFIX + sessionId;
        SessionInfo session = (SessionInfo) redisTemplate.opsForValue().get(sessionKey);
        
        if (session == null) {
            log.warn("Session not found: {}", sessionId);
            return false;
        }
        
        
        session.setActive(false);
        session.setTerminatedAt(Instant.now());
        redisTemplate.opsForValue().set(sessionKey, session, 1, TimeUnit.MINUTES); 
        
        
        String userSessionsKey = USER_SESSIONS_KEY_PREFIX + session.getUserId();
        redisTemplate.opsForSet().remove(userSessionsKey, sessionId);
        
        log.info("Session terminated: {} for user: {}", sessionId, session.getUserId());
        
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
        
        log.info("Terminated {} sessions for user: {}", terminated, userId);
        
        return terminated;
    }
    
    
    public void refreshSession(String sessionId) {
        String sessionKey = SESSION_KEY_PREFIX + sessionId;
        SessionInfo session = (SessionInfo) redisTemplate.opsForValue().get(sessionKey);
        
        if (session != null && session.isActive()) {
            session.setLastAccessedAt(Instant.now());
            redisTemplate.opsForValue().set(sessionKey, session, SESSION_TIMEOUT_MINUTES, TimeUnit.MINUTES);
        }
    }
    
    
    public Optional<SessionInfo> getSession(String sessionId) {
        String sessionKey = SESSION_KEY_PREFIX + sessionId;
        SessionInfo session = (SessionInfo) redisTemplate.opsForValue().get(sessionKey);
        return Optional.ofNullable(session);
    }
    
    
    public void cleanupExpiredSessions() {
        
        log.debug("Session cleanup triggered (handled by Redis TTL)");
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