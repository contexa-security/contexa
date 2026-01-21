package io.contexa.contexacore.infra.redis;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@RequiredArgsConstructor
public class RedisDistributedLockService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String LOCK_PREFIX = "distributed:lock:";
    private static final int MAX_KEY_LENGTH = 128; 

    private static final String ACQUIRE_SCRIPT =
            "local lockKey = KEYS[1] " +
                    "local owner = ARGV[1] " +
                    "local ttl = tonumber(ARGV[2]) or 30 " +  
                    "if not lockKey or not owner then " +
                    "  return 0 " +
                    "end " +
                    "if redis.call('exists', lockKey) == 0 then " +
                    "  redis.call('hset', lockKey, 'owner', owner) " +
                    "  redis.call('hset', lockKey, 'count', '1') " +
                    "  redis.call('expire', lockKey, ttl) " +
                    "  return 1 " +
                    "else " +
                    "  local currentOwner = redis.call('hget', lockKey, 'owner') " +
                    "  if currentOwner and currentOwner == owner then " +
                    "    redis.call('hincrby', lockKey, 'count', 1) " +
                    "    redis.call('expire', lockKey, ttl) " +
                    "    return 1 " +
                    "  else " +
                    "    return 0 " +
                    "  end " +
                    "end";

    private static final String RELEASE_SCRIPT =
            "local lockKey = KEYS[1] " +
                    "local owner = ARGV[1] " +
                    "if not lockKey or not owner then " +
                    "  return 0 " +
                    "end " +
                    "local currentOwner = redis.call('hget', lockKey, 'owner') " +
                    "if not currentOwner then " +
                    "  return -1 " +  
                    "end " +
                    "if currentOwner ~= owner then " +
                    "  return -2 " +  
                    "end " +
                    "local countStr = redis.call('hget', lockKey, 'count') " +
                    "local count = countStr and tonumber(countStr) or 0 " +
                    "if count <= 1 then " +
                    "  return redis.call('del', lockKey) " +
                    "else " +
                    "  redis.call('hincrby', lockKey, 'count', -1) " +
                    "  return 1 " +
                    "end";

    private static final String LOCK_STATUS_SCRIPT =
            "local lockKey = KEYS[1] " +
                    "if redis.call('exists', lockKey) == 0 then " +
                    "  return 'NOT_EXISTS' " +
                    "end " +
                    "local owner = redis.call('hget', lockKey, 'owner') " +
                    "local count = redis.call('hget', lockKey, 'count') " +
                    "local ttl = redis.call('ttl', lockKey) " +
                    "return (owner or 'unknown') .. '|' .. (count or '0') .. '|' .. (ttl or '-1')";

    private String sanitizeKey(String key) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }

        String sanitized = key.replaceAll("[^a-zA-Z0-9:_\\-.]", "_");

        sanitized = sanitized.replaceAll("_{2,}", "_");

        sanitized = sanitized.replaceAll("^_+|_+$", "");

        if (sanitized.length() > MAX_KEY_LENGTH) {
            String prefix = sanitized.substring(0, 40);
            String hash = generateHash(key);
            sanitized = prefix + "_" + hash;
        }

        return sanitized;
    }

    private String generateHash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            
            return String.valueOf(Math.abs(input.hashCode()));
        }
    }

    public boolean tryLock(String resourceKey, String owner, Duration timeout) {
        
        String sanitizedKey = sanitizeKey(resourceKey);
        String lockKey = LOCK_PREFIX + sanitizedKey;

        try {
            
            long timeoutSeconds = timeout.getSeconds();
            if (timeoutSeconds <= 0) {
                timeoutSeconds = 30; 
            }

            if (owner == null || owner.trim().isEmpty()) {
                throw new IllegalArgumentException("Owner cannot be null or empty");
            }

            Long result = redisTemplate.execute(
                    new DefaultRedisScript<>(ACQUIRE_SCRIPT, Long.class),
                    Collections.singletonList(lockKey),
                    owner.trim(),  
                    Long.toString(timeoutSeconds)  
            );

            boolean acquired = result != null && result == 1L;

            if (acquired) {
                            } else {
                            }

            return acquired;

        } catch (Exception e) {
            log.error("Failed to acquire lock for resource: {} (key: {}). Error: {}",
                    resourceKey, sanitizedKey, e.getMessage(), e);
            return false;
        }
    }

    public boolean unlock(String resourceKey, String owner) {
        String sanitizedKey = sanitizeKey(resourceKey);
        String lockKey = LOCK_PREFIX + sanitizedKey;

        try {
            Long result = redisTemplate.execute(
                    new DefaultRedisScript<>(RELEASE_SCRIPT, Long.class),
                    Collections.singletonList(lockKey),
                    owner
            );

            if (result == null) {
                log.warn("Lock release failed for resource: {} (key: {}) - Redis script returned null",
                        resourceKey, sanitizedKey);
                return false;
            }

            if (result > 0) {
                                return true;
            } else if (result == -1) {
                log.warn("Lock release failed for resource: {} (key: {}) - Lock doesn't exist (expired or already deleted)",
                        resourceKey, sanitizedKey);
                logLockStatus(lockKey, resourceKey, sanitizedKey);
                return false;
            } else if (result == -2) {
                log.warn("Lock release failed for resource: {} (key: {}) - Owner mismatch (expected: {})",
                        resourceKey, sanitizedKey, owner);
                logLockStatus(lockKey, resourceKey, sanitizedKey);
                return false;
            } else {
                log.warn("Lock release failed for resource: {} (key: {}) - Unknown error (result: {})",
                        resourceKey, sanitizedKey, result);
                logLockStatus(lockKey, resourceKey, sanitizedKey);
                return false;
            }

        } catch (Exception e) {
            log.error("Exception during lock release for resource: {} (key: {}) - {}",
                    resourceKey, sanitizedKey, e.getMessage(), e);
            return false;
        }
    }

    public <T> T executeWithLock(String resourceKey, Duration timeout, LockableOperation<T> operation) {
        String owner = generateLockOwner();

        if (!tryLock(resourceKey, owner, timeout)) {
            throw new LockAcquisitionException("Failed to acquire lock for: " + resourceKey);
        }

        try {
            return operation.execute();
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new RuntimeException("Operation failed", e);
        } finally {
            unlock(resourceKey, owner);
        }
    }

    public boolean tryLockWithWait(String resourceKey, String owner, Duration timeout, Duration waitTime) {
        long deadline = System.currentTimeMillis() + waitTime.toMillis();
        long backoff = 50; 

        while (System.currentTimeMillis() < deadline) {
            if (tryLock(resourceKey, owner, timeout)) {
                return true;
            }

            try {
                Thread.sleep(Math.min(backoff, deadline - System.currentTimeMillis()));
                backoff = Math.min(backoff * 2, 1000); 
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }

        return false;
    }

    private void logLockStatus(String lockKey, String resourceKey, String sanitizedKey) {
        try {
            
            Boolean exists = redisTemplate.hasKey(lockKey);
            if (exists == null || !exists) {
                log.warn("Lock status for resource: {} (key: {}) - DOES NOT EXIST",
                        resourceKey, sanitizedKey);
                return;
            }

            String currentOwner = (String) redisTemplate.opsForHash().get(lockKey, "owner");
            String count = (String) redisTemplate.opsForHash().get(lockKey, "count");
            Long ttl = redisTemplate.getExpire(lockKey, TimeUnit.SECONDS);
            
            log.warn("Lock status for resource: {} (key: {}) - Owner: {}, Count: {}, TTL: {}s",
                    resourceKey, sanitizedKey, 
                    currentOwner != null ? currentOwner : "unknown",
                    count != null ? count : "0",
                    ttl != null ? ttl : -1);
                    
        } catch (Exception e) {
            log.warn("Failed to get lock status for resource: {} (key: {}) - {}",
                    resourceKey, sanitizedKey, e.getMessage());
        }
    }

    public LockInfo getLockInfo(String resourceKey) {
        String sanitizedKey = sanitizeKey(resourceKey);
        String lockKey = LOCK_PREFIX + sanitizedKey;

        try {
            String owner = (String) redisTemplate.opsForHash().get(lockKey, "owner");
            if (owner == null) {
                return null;
            }

            Object countObj = redisTemplate.opsForHash().get(lockKey, "count");
            Integer count = countObj != null ? Integer.valueOf(countObj.toString()) : 0;

            Long ttl = redisTemplate.getExpire(lockKey, TimeUnit.SECONDS);

            return new LockInfo(owner, count, ttl != null ? ttl : 0);

        } catch (Exception e) {
            log.error("Failed to get lock info for resource: {} (key: {})",
                    resourceKey, sanitizedKey, e);
            return null;
        }
    }

    private String generateLockOwner() {
        return Thread.currentThread().getName() + ":" + UUID.randomUUID().toString();
    }

    public boolean forceUnlock(String resourceKey) {
        String sanitizedKey = sanitizeKey(resourceKey);
        String lockKey = LOCK_PREFIX + sanitizedKey;

        try {
            Boolean deleted = redisTemplate.delete(lockKey);
            if (Boolean.TRUE.equals(deleted)) {
                log.warn("Force unlocked resource: {} (key: {})", resourceKey, sanitizedKey);
                return true;
            }
            return false;
        } catch (Exception e) {
            log.error("Failed to force unlock resource: {} (key: {})", resourceKey, sanitizedKey, e);
            return false;
        }
    }

    public void clearAllLocks() {
        try {
            Set<String> keys = redisTemplate.keys(LOCK_PREFIX + "*");
            if (keys != null && !keys.isEmpty()) {
                redisTemplate.delete(keys);
                log.warn("Cleared {} locks", keys.size());
            }
        } catch (Exception e) {
            log.error("Failed to clear all locks", e);
        }
    }

    public boolean isLocked(String resourceKey) {
        String sanitizedKey = sanitizeKey(resourceKey);
        String lockKey = LOCK_PREFIX + sanitizedKey;

        try {
            return Boolean.TRUE.equals(redisTemplate.hasKey(lockKey));
        } catch (Exception e) {
            log.error("Failed to check lock existence for resource: {}", resourceKey, e);
            return false;
        }
    }

    public static class LockInfo {
        private final String owner;
        private final int count;
        private final long ttlSeconds;

        public LockInfo(String owner, int count, long ttlSeconds) {
            this.owner = owner;
            this.count = count;
            this.ttlSeconds = ttlSeconds;
        }

        public String getOwner() { return owner; }
        public int getCount() { return count; }
        public long getTtlSeconds() { return ttlSeconds; }
    }

    @FunctionalInterface
    public interface LockableOperation<T> {
        T execute() throws Exception;
    }

    public static class LockAcquisitionException extends RuntimeException {
        public LockAcquisitionException(String message) {
            super(message);
        }
    }
}