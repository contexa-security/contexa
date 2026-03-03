package io.contexa.contexamcp.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
@RequiredArgsConstructor
public class RedisUserSessionService implements UserSessionService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String SESSION_KEY_PREFIX = "session:";
    private static final String USER_SESSIONS_KEY_PREFIX = "user:sessions:";

    @Override
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
            Object sessionObj = redisTemplate.opsForValue().get(sessionKey);
            if (sessionObj == null) {
                staleSessionIds.add(id);
            } else if (sessionObj instanceof SessionInfo session) {
                if (session.isActive()) {
                    result.add(session);
                }
            } else {
                staleSessionIds.add(id);
            }
        }

        // Lazy cleanup: remove stale session IDs whose session keys have expired
        if (!staleSessionIds.isEmpty()) {
            redisTemplate.opsForSet().remove(userSessionsKey, staleSessionIds.toArray());
            log.error("Cleaned up {} stale session index entries for user {}", staleSessionIds.size(), userId);
        }

        return result;
    }

    @Override
    public boolean terminateSession(String sessionId) {
        String sessionKey = SESSION_KEY_PREFIX + sessionId;
        Object sessionObj = redisTemplate.opsForValue().get(sessionKey);

        if (!(sessionObj instanceof SessionInfo session)) {
            log.error("Session not found or invalid type: {}", sessionId);
            return false;
        }

        session.setActive(false);
        session.setTerminatedAt(Instant.now());
        redisTemplate.opsForValue().set(sessionKey, session, 1, TimeUnit.MINUTES);

        String userSessionsKey = USER_SESSIONS_KEY_PREFIX + session.getUserId();
        redisTemplate.opsForSet().remove(userSessionsKey, sessionId);

        return true;
    }
}
