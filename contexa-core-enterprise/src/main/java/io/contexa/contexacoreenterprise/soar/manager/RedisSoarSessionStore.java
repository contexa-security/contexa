package io.contexa.contexacoreenterprise.soar.manager;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class RedisSoarSessionStore implements SoarSessionStore {

    private final RedisTemplate<String, Object> redisTemplate;
    private final Map<String, SoarInteractionManager.InteractionSession> localCache = new ConcurrentHashMap<>();

    private static final String SESSION_KEY_PREFIX = "soar:session:";
    private static final Duration SESSION_TTL = Duration.ofHours(2);

    public RedisSoarSessionStore(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public Optional<SoarInteractionManager.InteractionSession> getSession(String sessionId) {
        try {
            String key = SESSION_KEY_PREFIX + sessionId;
            SoarInteractionManager.InteractionSession session =
                    (SoarInteractionManager.InteractionSession) redisTemplate.opsForValue().get(key);
            if (session != null) {
                return Optional.of(session);
            }
        } catch (Exception e) {
            log.error("[SoarSessionStore] Failed to get session from Redis: sessionId={}", sessionId, e);
        }
        return Optional.ofNullable(localCache.get(sessionId));
    }

    @Override
    public void saveSession(SoarInteractionManager.InteractionSession session) {
        try {
            String key = SESSION_KEY_PREFIX + session.getSessionId();
            redisTemplate.opsForValue().set(key, session, SESSION_TTL);
        } catch (Exception e) {
            log.error("[SoarSessionStore] Failed to save session to Redis: sessionId={}", session.getSessionId(), e);
        }
        localCache.put(session.getSessionId(), session);
    }

    @Override
    public void removeSession(String sessionId) {
        try {
            String key = SESSION_KEY_PREFIX + sessionId;
            redisTemplate.delete(key);
        } catch (Exception e) {
            log.error("[SoarSessionStore] Failed to remove session from Redis: sessionId={}", sessionId, e);
        }
        localCache.remove(sessionId);
    }
}
