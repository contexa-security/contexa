package io.contexa.contexaidentity.security.token.management;

import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;


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

    
    public String startNewChain(String token, String username, String deviceId) {
        String chainId = generateChainId(username, deviceId);

        
        String tokenKey = TOKEN_TO_CHAIN_PREFIX + token;
        redisTemplate.opsForValue().set(tokenKey, chainId,
                Duration.ofDays(30)); 

        
        String chainKey = CHAIN_KEY_PREFIX + chainId;
        redisTemplate.opsForHash().put(chainKey, "currentToken", token);
        redisTemplate.opsForHash().put(chainKey, "username", username);
        redisTemplate.opsForHash().put(chainKey, "deviceId", deviceId);
        redisTemplate.opsForHash().put(chainKey, "createdAt", String.valueOf(System.currentTimeMillis()));
        redisTemplate.expire(chainKey, 30, TimeUnit.DAYS);

        log.debug("Started new token chain: {} for user: {}, device: {}", chainId, username, deviceId);
        return chainId;
    }

    
    public String rotateToken(String oldToken, String newToken, String username, String deviceId) {
        String lockKey = "chain:lock:" + oldToken;

        try {
            return lockService.executeWithLock(lockKey, CHAIN_LOCK_TIMEOUT, () -> {
                
                if (isTokenUsed(oldToken)) {
                    log.error("Token reuse detected! Token: {}, User: {}", oldToken, username);
                    
                    invalidateTokenChain(oldToken);
                    throw new TokenReuseException("Token has already been used");
                }

                
                String chainId = getChainId(oldToken);
                if (chainId == null) {
                    log.warn("No chain found for token: {}. Starting new chain.", oldToken);
                    return startNewChain(newToken, username, deviceId);
                }

                
                if (!isChainValid(chainId, oldToken)) {
                    log.error("Invalid chain state detected. Chain: {}, Token: {}", chainId, oldToken);
                    invalidateChain(chainId);
                    throw new InvalidChainException("Token chain is invalid");
                }

                
                updateChain(chainId, oldToken, newToken);

                
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

    
    public boolean isTokenUsed(String token) {
        String key = USED_TOKEN_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    
    private void markTokenAsUsed(String token) {
        String key = USED_TOKEN_PREFIX + token;
        redisTemplate.opsForValue().set(key, "1", Duration.ofDays(30));
    }

    
    private String getChainId(String token) {
        String key = TOKEN_TO_CHAIN_PREFIX + token;
        return redisTemplate.opsForValue().get(key);
    }

    
    private boolean isChainValid(String chainId, String token) {
        String chainKey = CHAIN_KEY_PREFIX + chainId;
        String currentToken = (String) redisTemplate.opsForHash().get(chainKey, "currentToken");
        return token.equals(currentToken);
    }

    
    private void updateChain(String chainId, String oldToken, String newToken) {
        String chainKey = CHAIN_KEY_PREFIX + chainId;

        
        redisTemplate.opsForHash().put(chainKey, "currentToken", newToken);
        redisTemplate.opsForHash().put(chainKey, "lastRotated", String.valueOf(System.currentTimeMillis()));

        
        String newTokenKey = TOKEN_TO_CHAIN_PREFIX + newToken;
        redisTemplate.opsForValue().set(newTokenKey, chainId, Duration.ofDays(30));

        
        String historyKey = chainKey + ":history";
        redisTemplate.opsForList().leftPush(historyKey, oldToken);
        redisTemplate.opsForList().trim(historyKey, 0, 9);
    }

    
    private void invalidateTokenChain(String token) {
        String chainId = getChainId(token);
        if (chainId != null) {
            invalidateChain(chainId);

            
            publishSecurityEvent(chainId, "TOKEN_REUSE_DETECTED", token);
        }
    }

    
    private void invalidateChain(String chainId) {
        String chainKey = CHAIN_KEY_PREFIX + chainId;

        
        String username = (String) redisTemplate.opsForHash().get(chainKey, "username");
        String deviceId = (String) redisTemplate.opsForHash().get(chainKey, "deviceId");

        
        redisTemplate.opsForHash().put(chainKey, "invalidated", "true");
        redisTemplate.opsForHash().put(chainKey, "invalidatedAt", String.valueOf(System.currentTimeMillis()));

        log.warn("Token chain invalidated. Chain: {}, User: {}, Device: {}",
                chainId, username, deviceId);
    }

    
    private String generateChainId(String username, String deviceId) {
        return username + ":" + deviceId + ":" + UUID.randomUUID().toString();
    }

    
    private void publishSecurityEvent(String chainId, String eventType, String token) {
        
        
        log.error("SECURITY_EVENT: {} - Chain: {}, Token: {}", eventType, chainId, token);
    }

    

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