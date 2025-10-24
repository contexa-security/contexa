package io.contexa.contexaidentity.security.token.management;

import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * 토큰 체인 관리자
 *
 * 토큰 재사용 공격을 방지하기 위해 토큰 체인을 관리합니다.
 * 각 리프레시 토큰은 고유한 체인 ID를 가지며,
 * 토큰이 갱신될 때마다 체인이 연결됩니다.
 *
 * 재사용 감지 시 전체 체인을 무효화합니다.
 *
 * @since 2024.12
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TokenChainManager {

    private static final String CHAIN_KEY_PREFIX = "token:chain:";
    private static final String TOKEN_TO_CHAIN_PREFIX = "token:to:chain:";
    private static final String USED_TOKEN_PREFIX = "token:used:";
    private static final Duration CHAIN_LOCK_TIMEOUT = Duration.ofSeconds(5);

    private final StringRedisTemplate redisTemplate;
    private final RedisDistributedLockService lockService;

    /**
     * 새로운 토큰 체인 시작
     */
    public String startNewChain(String token, String username, String deviceId) {
        String chainId = generateChainId(username, deviceId);

        // 토큰 -> 체인 ID 매핑
        String tokenKey = TOKEN_TO_CHAIN_PREFIX + token;
        redisTemplate.opsForValue().set(tokenKey, chainId,
                Duration.ofDays(30)); // 리프레시 토큰 최대 수명

        // 체인 정보 저장
        String chainKey = CHAIN_KEY_PREFIX + chainId;
        redisTemplate.opsForHash().put(chainKey, "currentToken", token);
        redisTemplate.opsForHash().put(chainKey, "username", username);
        redisTemplate.opsForHash().put(chainKey, "deviceId", deviceId);
        redisTemplate.opsForHash().put(chainKey, "createdAt", String.valueOf(System.currentTimeMillis()));
        redisTemplate.expire(chainKey, 30, TimeUnit.DAYS);

        log.debug("Started new token chain: {} for user: {}, device: {}", chainId, username, deviceId);
        return chainId;
    }

    /**
     * 토큰 갱신 (체인 연결)
     *
     * @return 갱신 성공 시 체인 ID, 실패 시 null
     */
    public String rotateToken(String oldToken, String newToken, String username, String deviceId) {
        String lockKey = "chain:lock:" + oldToken;

        try {
            return lockService.executeWithLock(lockKey, CHAIN_LOCK_TIMEOUT, () -> {
                // 1. 이미 사용된 토큰인지 확인
                if (isTokenUsed(oldToken)) {
                    log.error("Token reuse detected! Token: {}, User: {}", oldToken, username);
                    // 전체 체인 무효화
                    invalidateTokenChain(oldToken);
                    throw new TokenReuseException("Token has already been used");
                }

                // 2. 체인 ID 조회
                String chainId = getChainId(oldToken);
                if (chainId == null) {
                    log.warn("No chain found for token: {}. Starting new chain.", oldToken);
                    return startNewChain(newToken, username, deviceId);
                }

                // 3. 체인 유효성 검증
                if (!isChainValid(chainId, oldToken)) {
                    log.error("Invalid chain state detected. Chain: {}, Token: {}", chainId, oldToken);
                    invalidateChain(chainId);
                    throw new InvalidChainException("Token chain is invalid");
                }

                // 4. 토큰 갱신
                updateChain(chainId, oldToken, newToken);

                // 5. 이전 토큰을 사용됨으로 표시
                markTokenAsUsed(oldToken);

                log.debug("Token rotated successfully. Chain: {}, Old: {}, New: {}",
                        chainId, oldToken, newToken);
                return chainId;
            });

        } catch (RedisDistributedLockService.LockAcquisitionException e) {
            log.error("Failed to acquire lock for token rotation. Token: {}", oldToken, e);
            throw new TokenRotationException("Could not acquire lock for token rotation", e);
        }
    }

    /**
     * 토큰이 이미 사용되었는지 확인
     */
    public boolean isTokenUsed(String token) {
        String key = USED_TOKEN_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    /**
     * 토큰을 사용됨으로 표시
     */
    private void markTokenAsUsed(String token) {
        String key = USED_TOKEN_PREFIX + token;
        redisTemplate.opsForValue().set(key, "1", Duration.ofDays(30));
    }

    /**
     * 체인 ID 조회
     */
    private String getChainId(String token) {
        String key = TOKEN_TO_CHAIN_PREFIX + token;
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * 체인 유효성 확인
     */
    private boolean isChainValid(String chainId, String token) {
        String chainKey = CHAIN_KEY_PREFIX + chainId;
        String currentToken = (String) redisTemplate.opsForHash().get(chainKey, "currentToken");
        return token.equals(currentToken);
    }

    /**
     * 체인 업데이트
     */
    private void updateChain(String chainId, String oldToken, String newToken) {
        String chainKey = CHAIN_KEY_PREFIX + chainId;

        // 새 토큰으로 현재 토큰 업데이트
        redisTemplate.opsForHash().put(chainKey, "currentToken", newToken);
        redisTemplate.opsForHash().put(chainKey, "lastRotated", String.valueOf(System.currentTimeMillis()));

        // 새 토큰 -> 체인 ID 매핑
        String newTokenKey = TOKEN_TO_CHAIN_PREFIX + newToken;
        redisTemplate.opsForValue().set(newTokenKey, chainId, Duration.ofDays(30));

        // 토큰 히스토리 추가 (최근 10개만 유지)
        String historyKey = chainKey + ":history";
        redisTemplate.opsForList().leftPush(historyKey, oldToken);
        redisTemplate.opsForList().trim(historyKey, 0, 9);
    }

    /**
     * 토큰 체인 무효화 (토큰 재사용 감지 시)
     */
    private void invalidateTokenChain(String token) {
        String chainId = getChainId(token);
        if (chainId != null) {
            invalidateChain(chainId);

            // 보안 이벤트 발생
            publishSecurityEvent(chainId, "TOKEN_REUSE_DETECTED", token);
        }
    }

    /**
     * 체인 무효화
     */
    private void invalidateChain(String chainId) {
        String chainKey = CHAIN_KEY_PREFIX + chainId;

        // 체인 정보 조회
        String username = (String) redisTemplate.opsForHash().get(chainKey, "username");
        String deviceId = (String) redisTemplate.opsForHash().get(chainKey, "deviceId");

        // 체인 무효화 표시
        redisTemplate.opsForHash().put(chainKey, "invalidated", "true");
        redisTemplate.opsForHash().put(chainKey, "invalidatedAt", String.valueOf(System.currentTimeMillis()));

        log.warn("Token chain invalidated. Chain: {}, User: {}, Device: {}",
                chainId, username, deviceId);
    }

    /**
     * 체인 ID 생성
     */
    private String generateChainId(String username, String deviceId) {
        return username + ":" + deviceId + ":" + UUID.randomUUID().toString();
    }

    /**
     * 보안 이벤트 발행
     */
    private void publishSecurityEvent(String chainId, String eventType, String token) {
        // RedisEventPublisher를 통해 이벤트 발행
        // 실제 구현 시 주입받아 사용
        log.error("SECURITY_EVENT: {} - Chain: {}, Token: {}", eventType, chainId, token);
    }

    // ===== 예외 클래스 =====

    public static class TokenReuseException extends RuntimeException {
        public TokenReuseException(String message) {
            super(message);
        }
    }

    public static class InvalidChainException extends RuntimeException {
        public InvalidChainException(String message) {
            super(message);
        }
    }

    public static class TokenRotationException extends RuntimeException {
        public TokenRotationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}