package io.contexa.contexacore.security.session;

import io.contexa.contexacore.properties.SecuritySessionProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.concurrent.TimeUnit;

/**
 * Redis-backed implementation of SessionIdResolver for distributed mode.
 * Validates session existence and TTL against Redis store.
 */
@Slf4j
public class RedisSessionIdResolver extends AbstractSessionIdResolver {

    private static final String SESSION_ATTRIBUTE_NAME =
            "org.springframework.session.SessionRepository.CURRENT_SESSION_ID";

    private final RedisTemplate<String, Object> redisTemplate;

    public RedisSessionIdResolver(RedisTemplate<String, Object> redisTemplate,
                                  SecuritySessionProperties securitySessionProperties) {
        super(securitySessionProperties);
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected boolean validateSession(String sessionId) {
        String redisKey = "spring:session:sessions:" + sessionId;
        Boolean exists = redisTemplate.hasKey(redisKey);

        if (Boolean.FALSE.equals(exists)) {
            return false;
        }

        Long ttl = redisTemplate.getExpire(redisKey, TimeUnit.SECONDS);
        return ttl == null || ttl > 0;
    }

    @Override
    protected String[] getSessionAttributeNames() {
        return new String[]{SESSION_ATTRIBUTE_NAME, "sessionId"};
    }
}
