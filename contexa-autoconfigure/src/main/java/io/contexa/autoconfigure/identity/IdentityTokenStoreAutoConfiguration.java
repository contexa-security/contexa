package io.contexa.autoconfigure.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexacommon.enums.TokenStoreType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.management.EnhancedRefreshTokenStore;
import io.contexa.contexaidentity.security.token.management.RefreshTokenAnomalyDetector;
import io.contexa.contexaidentity.security.token.management.RefreshTokenManagementService;
import io.contexa.contexaidentity.security.token.management.TokenChainManager;
import io.contexa.contexaidentity.security.token.store.MemoryRefreshTokenStore;
import io.contexa.contexaidentity.security.token.store.RedisRefreshTokenStore;
import io.contexa.contexaidentity.security.token.store.RefreshTokenStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@Slf4j
@AutoConfiguration
@ConditionalOnBean(PlatformConfig.class)
@RequiredArgsConstructor
public class IdentityTokenStoreAutoConfiguration {

    private final AuthContextProperties authContextProperties;

    @Value("${spring.auth.enhanced-security:false}")
    private boolean enhancedSecurityEnabled;

    @Bean
    @ConditionalOnMissingBean(RefreshTokenStore.class)
    public RefreshTokenStore refreshTokenStore(
            JwtDecoder jwtDecoder,
            @Autowired(required = false) StringRedisTemplate redisTemplate,
            @Autowired(required = false) RedisDistributedLockService lockService,
            @Autowired(required = false) RedisEventPublisher eventPublisher,
            @Autowired(required = false) TokenChainManager tokenChainManager,
            @Autowired(required = false) RefreshTokenAnomalyDetector anomalyDetector,
            @Autowired(required = false) RefreshTokenManagementService managementService) {

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

            return new RedisRefreshTokenStore(
                    redisTemplate, jwtDecoder, authContextProperties,
                    lockService, eventPublisher,
                    tokenChainManager, anomalyDetector, managementService);
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

    @Bean
    @ConditionalOnProperty(name = "spring.auth.enhanced-security", havingValue = "true")
    @ConditionalOnMissingBean(TokenChainManager.class)
    public TokenChainManager tokenChainManager(
            @Autowired(required = false) StringRedisTemplate redisTemplate,
            @Autowired(required = false) RedisDistributedLockService lockService) {

        if (redisTemplate != null && lockService != null) {
            return new TokenChainManager(redisTemplate, lockService);
        }
        log.warn("TokenChainManager requires Redis and LockService. Skipping creation.");
        return null;
    }

    @Bean
    @ConditionalOnProperty(name = "spring.auth.enhanced-security", havingValue = "true")
    @ConditionalOnMissingBean(RefreshTokenAnomalyDetector.class)
    public RefreshTokenAnomalyDetector refreshTokenAnomalyDetector(
            @Autowired(required = false) StringRedisTemplate redisTemplate,
            @Autowired(required = false) RedisEventPublisher eventPublisher) {

        if (redisTemplate != null && eventPublisher != null) {
            RefreshTokenAnomalyDetector.GeoLocationService geoService = (loc1, loc2) -> 0.0;
            return new RefreshTokenAnomalyDetector(redisTemplate, eventPublisher);
        }
        log.warn("RefreshTokenAnomalyDetector requires Redis and EventPublisher. Skipping creation.");
        return null;
    }

    @Bean
    @ConditionalOnProperty(name = "spring.auth.enhanced-security", havingValue = "true")
    @ConditionalOnMissingBean(RefreshTokenManagementService.class)
    public RefreshTokenManagementService refreshTokenManagementService(
            @Lazy @Autowired(required = false) RefreshTokenStore tokenStore,
            @Autowired(required = false) StringRedisTemplate redisTemplate,
            @Autowired(required = false) RedisEventPublisher eventPublisher,
            ObjectMapper objectMapper) {

        if (tokenStore instanceof EnhancedRefreshTokenStore enhancedStore
                && redisTemplate != null && eventPublisher != null) {
            return new RefreshTokenManagementService(redisTemplate, eventPublisher, enhancedStore, objectMapper);
        }
        log.warn("RefreshTokenManagementService requires EnhancedRefreshTokenStore implementation. Skipping creation.");
        return null;
    }
}
