package io.contexa.contexaidentity.security.token.store;

import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexacommon.enums.TokenStoreType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@Slf4j
public class RefreshTokenStoreFactory {

    public static RefreshTokenStore create(JwtDecoder jwtDecoder,
                                           AuthContextProperties props,
                                           StringRedisTemplate redisTemplate) {
        return create(jwtDecoder, props, redisTemplate, null, null);
    }

    public static RefreshTokenStore create(JwtDecoder jwtDecoder,
                                           AuthContextProperties props,
                                           StringRedisTemplate redisTemplate,
                                           RedisDistributedLockService lockService,
                                           RedisEventPublisher eventPublisher) {
        TokenStoreType storeType = props.getTokenStoreType();

        switch (storeType) {
            case MEMORY:
                                return new MemoryRefreshTokenStore(jwtDecoder, props);

            case REDIS:
                if (redisTemplate == null) {
                    log.error("Redis template is null but REDIS store type is configured. " +
                            "Falling back to MEMORY store.");
                    return new MemoryRefreshTokenStore(jwtDecoder, props);
                }
                                return new RedisRefreshTokenStore(redisTemplate, jwtDecoder, props,
                        lockService, eventPublisher);

            default:
                log.warn("Unknown token store type: {}. Using default MEMORY store.", storeType);
                return new MemoryRefreshTokenStore(jwtDecoder, props);
        }
    }

    public static RefreshTokenStore create(JwtDecoder jwtDecoder,
                                           AuthContextProperties props) {
        return create(jwtDecoder, props, null);
    }
}