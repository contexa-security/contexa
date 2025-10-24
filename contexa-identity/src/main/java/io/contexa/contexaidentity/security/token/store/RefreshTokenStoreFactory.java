package io.contexa.contexaidentity.security.token.store;

import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexaidentity.security.enums.TokenStoreType;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * RefreshTokenStore 구현체를 생성하는 팩토리 클래스
 *
 * 설정된 TokenStoreType에 따라 적절한 구현체를 생성합니다:
 * - MEMORY: MemoryRefreshTokenStore (기존 구현)
 * - REDIS: RedisRefreshTokenStore (새로운 구현)
 *
 * @since 2024.12
 * @updated 2025.01 - JwtDecoder 기반으로 리팩토링 (RSA 지원)
 */
@Slf4j
public class RefreshTokenStoreFactory {

    /**
     * RefreshTokenStore 구현체 생성 (기본 - 선택적 의존성 없이)
     *
     * @param jwtDecoder JWT 디코더 (RSA 공개키 사용)
     * @param props 인증 설정 프로퍼티
     * @param redisTemplate Redis 템플릿 (Redis 타입인 경우에만 필요)
     * @return RefreshTokenStore 구현체
     */
    public static RefreshTokenStore create(JwtDecoder jwtDecoder,
                                           AuthContextProperties props,
                                           StringRedisTemplate redisTemplate) {
        return create(jwtDecoder, props, redisTemplate, null, null);
    }

    /**
     * RefreshTokenStore 구현체 생성 (표준 기능)
     *
     * @param jwtDecoder JWT 디코더 (RSA 공개키 사용)
     * @param props 인증 설정 프로퍼티
     * @param redisTemplate Redis 템플릿 (Redis 타입인 경우에만 필요)
     * @param lockService 분산 락 서비스 (optional)
     * @param eventPublisher 이벤트 발행 서비스 (optional)
     * @return RefreshTokenStore 구현체
     */
    public static RefreshTokenStore create(JwtDecoder jwtDecoder,
                                           AuthContextProperties props,
                                           StringRedisTemplate redisTemplate,
                                           RedisDistributedLockService lockService,
                                           RedisEventPublisher eventPublisher) {
        TokenStoreType storeType = props.getTokenStoreType();

        log.info("Creating RefreshTokenStore with type: {} (RSA-based)", storeType);

        switch (storeType) {
            case MEMORY:
                log.info("Using in-memory refresh token store (single server mode, RSA-based)");
                return new MemoryRefreshTokenStore(jwtDecoder, props);

            case REDIS:
                if (redisTemplate == null) {
                    log.error("Redis template is null but REDIS store type is configured. " +
                            "Falling back to MEMORY store.");
                    return new MemoryRefreshTokenStore(jwtDecoder, props);
                }
                log.info("Using Redis-based refresh token store (distributed mode, RSA-based)");
                return new RedisRefreshTokenStore(redisTemplate, jwtDecoder, props,
                        lockService, eventPublisher);

            default:
                log.warn("Unknown token store type: {}. Using default MEMORY store.", storeType);
                return new MemoryRefreshTokenStore(jwtDecoder, props);
        }
    }

    /**
     * RefreshTokenStore 구현체 생성 (Redis 미사용)
     *
     * @param jwtDecoder JWT 디코더 (RSA 공개키 사용)
     * @param props 인증 설정 프로퍼티
     * @return RefreshTokenStore 구현체
     */
    public static RefreshTokenStore create(JwtDecoder jwtDecoder,
                                           AuthContextProperties props) {
        return create(jwtDecoder, props, null);
    }
}