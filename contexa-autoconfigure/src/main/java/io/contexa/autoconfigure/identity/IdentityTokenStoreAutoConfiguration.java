package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.enums.TokenStoreType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.token.store.MemoryRefreshTokenStore;
import io.contexa.contexaidentity.security.token.store.RedisRefreshTokenStore;
import io.contexa.contexaidentity.security.token.store.RefreshTokenStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@Slf4j
@AutoConfiguration
@ConditionalOnBean(PlatformConfig.class)
@RequiredArgsConstructor
public class IdentityTokenStoreAutoConfiguration {

    private final AuthContextProperties authContextProperties;

    @Bean
    @ConditionalOnMissingBean(RefreshTokenStore.class)
    public RefreshTokenStore refreshTokenStore(
            JwtDecoder jwtDecoder,
            StringRedisTemplate redisTemplate) {

        TokenStoreType storeType = authContextProperties.getTokenStoreType();

        if (storeType == TokenStoreType.MEMORY) {
            return new MemoryRefreshTokenStore(jwtDecoder, authContextProperties);
        }

        if (storeType == TokenStoreType.REDIS) {
            if (redisTemplate == null) {
                log.warn("REDIS token store is configured but Redis is not available. " +
                        "Falling back to MEMORY store.");
                return new MemoryRefreshTokenStore(jwtDecoder, authContextProperties);
            }

            return new RedisRefreshTokenStore(redisTemplate, jwtDecoder, authContextProperties);
        }

        log.warn("Unknown token store type: {}. Using default MEMORY store.", storeType);
        return new MemoryRefreshTokenStore(jwtDecoder, authContextProperties);
    }

    @Bean
    @ConditionalOnClass(RedisTemplate.class)
    @ConditionalOnMissingBean(RedisDistributedLockService.class)
    public RedisDistributedLockService redisDistributedLockService(
            @Autowired(required = false) RedisTemplate<String, Object> redisTemplate) {

        if (redisTemplate != null) {
            return new RedisDistributedLockService(redisTemplate);
        }
        return null;
    }
}
