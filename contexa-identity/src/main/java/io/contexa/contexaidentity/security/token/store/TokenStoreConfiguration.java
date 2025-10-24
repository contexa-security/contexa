package io.contexa.contexaidentity.security.token.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexaidentity.security.enums.TokenStoreType;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.management.EnhancedRefreshTokenStore;
import io.contexa.contexaidentity.security.token.management.RefreshTokenAnomalyDetector;
import io.contexa.contexaidentity.security.token.management.RefreshTokenManagementService;
import io.contexa.contexaidentity.security.token.management.TokenChainManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * 토큰 저장소 관련 설정
 *
 * TokenStoreType 설정에 따라 적절한 RefreshTokenStore 구현체를 생성합니다.
 * - MEMORY: 단일 서버 환경용 (기본값)
 * - REDIS: 분산 서버 환경용
 *
 * 보안 강화 기능 활성화 옵션:
 * - spring.auth.enhanced-security: 보안 강화 기능 활성화 (기본값: false)
 *
 * @since 2024.12
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class TokenStoreConfiguration {

    private final AuthContextProperties authContextProperties;

    @Value("${spring.auth.enhanced-security:false}")
    private boolean enhancedSecurityEnabled;

    /**
     * RefreshTokenStore 빈 생성
     *
     * @param jwtDecoder JWT 디코더 (RSA 공개키 사용)
     * @param redisTemplate Redis 템플릿 (optional)
     * @param lockService 분산 락 서비스 (optional)
     * @param eventPublisher 이벤트 발행 서비스 (optional)
     * @param tokenChainManager 토큰 체인 관리자 (optional - 보안 강화 기능)
     * @param anomalyDetector 비정상 패턴 감지기 (optional - 보안 강화 기능)
     * @param managementService 토큰 관리 서비스 (optional - 보안 강화 기능)
     * @return RefreshTokenStore 구현체
     */
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

        // 메모리 저장소
        if (storeType == TokenStoreType.MEMORY) {
            log.info("Creating memory-based refresh token store for single server environment (RSA-based)");
            return new MemoryRefreshTokenStore(jwtDecoder, authContextProperties);
        }

        // Redis 저장소
        if (storeType == TokenStoreType.REDIS) {
            if (redisTemplate == null) {
                log.warn("REDIS token store is configured but Redis is not available. " +
                        "Falling back to MEMORY store.");
                return new MemoryRefreshTokenStore(jwtDecoder, authContextProperties);
            }

            if (enhancedSecurityEnabled) {
                log.info("Creating Redis-based refresh token store with enhanced security features (RSA-based)");
                log.info("Security components - ChainManager: {}, AnomalyDetector: {}, ManagementService: {}",
                        tokenChainManager != null, anomalyDetector != null, managementService != null);
            } else {
                log.info("Creating standard Redis-based refresh token store (RSA-based)");
            }

            return new RedisRefreshTokenStore(
                    redisTemplate, jwtDecoder, authContextProperties,
                    lockService, eventPublisher,
                    tokenChainManager, anomalyDetector, managementService
            );
        }

        // 기본값
        log.warn("Unknown token store type: {}. Using default MEMORY store.", storeType);
        return new MemoryRefreshTokenStore(jwtDecoder, authContextProperties);
    }

    /**
     * RedisDistributedLockService 빈 생성
     * Redis가 활성화된 경우에만 생성됩니다.
     */
    @Bean
    @ConditionalOnClass(RedisTemplate.class)
    @ConditionalOnMissingBean(RedisDistributedLockService.class)
    public RedisDistributedLockService redisDistributedLockService(
            @Autowired(required = false) RedisTemplate<String, Object> redisTemplate) {

        if (redisTemplate != null) {
            log.info("Creating RedisDistributedLockService");
            return new RedisDistributedLockService(redisTemplate);
        }
        return null;
    }

    /**
     * TokenChainManager 빈 생성
     * 보안 강화 기능이 활성화된 경우에만 생성됩니다.
     */
    @Bean
    @ConditionalOnProperty(name = "spring.auth.enhanced-security", havingValue = "true")
    @ConditionalOnMissingBean(TokenChainManager.class)
    public TokenChainManager tokenChainManager(
            @Autowired(required = false) StringRedisTemplate redisTemplate,
            @Autowired(required = false) RedisDistributedLockService lockService) {

        if (redisTemplate != null && lockService != null) {
            log.info("Creating TokenChainManager for enhanced security");
            return new TokenChainManager(redisTemplate, lockService);
        }
        log.warn("TokenChainManager requires Redis and LockService. Skipping creation.");
        return null;
    }

    /**
     * RefreshTokenAnomalyDetector 빈 생성
     * 보안 강화 기능이 활성화된 경우에만 생성됩니다.
     */
    @Bean
    @ConditionalOnProperty(name = "spring.auth.enhanced-security", havingValue = "true")
    @ConditionalOnMissingBean(RefreshTokenAnomalyDetector.class)
    public RefreshTokenAnomalyDetector refreshTokenAnomalyDetector(
            @Autowired(required = false) StringRedisTemplate redisTemplate,
            @Autowired(required = false) RedisEventPublisher eventPublisher) {

        if (redisTemplate != null && eventPublisher != null) {
            log.info("Creating RefreshTokenAnomalyDetector for enhanced security");
            RefreshTokenAnomalyDetector.GeoLocationService geoService = (loc1, loc2) -> 0.0;
            return new RefreshTokenAnomalyDetector(redisTemplate, eventPublisher);
        }
        log.warn("RefreshTokenAnomalyDetector requires Redis and EventPublisher. Skipping creation.");
        return null;
    }

    /**
     * RefreshTokenManagementService 빈 생성
     * 보안 강화 기능이 활성화되고 EnhancedRefreshTokenStore 인터페이스를 구현한 경우에만 생성됩니다.
     *
     * 순환 참조 방지: @Lazy 어노테이션을 사용하여 RefreshTokenStore를 지연 주입합니다.
     */
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
            log.info("Creating RefreshTokenManagementService for token management with lazy-loaded tokenStore");
            return new RefreshTokenManagementService(redisTemplate, eventPublisher, enhancedStore, objectMapper);
        }
        log.warn("RefreshTokenManagementService requires EnhancedRefreshTokenStore implementation. Skipping creation.");
        return null;
    }
}