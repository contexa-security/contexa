/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.infra.redis;

import io.contexa.contexacore.infra.lock.DistributedLockService;
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

/**
 * Redis-backed lock service. Z-16 (F4): it answers as InMemoryDistributedLockService does. A lock lasts the timeout it
 * is taken with, to the millisecond, and thirty seconds without one; distinct resource keys are distinct locks; a lock
 * past its timeout is lost to its owner; a failing operation is wrapped alike; blank arguments are refused alike.
 */
@Slf4j
@RequiredArgsConstructor
public class RedisDistributedLockService implements DistributedLockService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String LOCK_PREFIX = "distributed:lock:";
    private static final int MAX_KEY_LENGTH = 128;
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    /**
     * KEYS[1] the lock; ARGV[1] the owner, ARGV[2] the timeout in milliseconds, read as the digits it holds whatever
     * the serializer.
     */
    private static final String ACQUIRE_SCRIPT =
            "local lockKey = KEYS[1] " +
                    "local owner = ARGV[1] " +
                    "local ttl = tonumber(string.match(ARGV[2], '%-?%d+')) " +
                    "if not lockKey or not owner or not ttl then " +
                    "  return 0 " +
                    "end " +
                    "if redis.call('exists', lockKey) == 0 then " +
                    "  redis.call('hset', lockKey, 'owner', owner) " +
                    "  redis.call('hset', lockKey, 'count', '1') " +
                    "  redis.call('pexpire', lockKey, ttl) " +
                    "  return 1 " +
                    "else " +
                    "  local currentOwner = redis.call('hget', lockKey, 'owner') " +
                    "  if currentOwner and currentOwner == owner then " +
                    "    redis.call('hincrby', lockKey, 'count', 1) " +
                    "    redis.call('pexpire', lockKey, ttl) " +
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

    /**
     * The Redis key part of a resource key. A key that sanitizing changes or that is too long ends with a hash of the
     * resource key, so distinct resource keys never share a lock (Z-16, F4: {@code a@b.com} and {@code a#b.com} once
     * did).
     */
    private String sanitizeKey(String key) {
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException("resourceKey and owner must not be null or blank");
        }

        String sanitized = key.replaceAll("[^a-zA-Z0-9:_\\-.]", "_");

        sanitized = sanitized.replaceAll("_{2,}", "_");

        sanitized = sanitized.replaceAll("^_+|_+$", "");

        if (!sanitized.equals(key) || sanitized.length() > MAX_KEY_LENGTH) {
            String prefix = sanitized.substring(0, Math.min(40, sanitized.length()));
            String hash = generateHash(key);
            sanitized = prefix + "_" + hash;
        }

        return sanitized;
    }

    private static void requireKeyAndOwner(String resourceKey, String owner) {
        if (resourceKey == null || resourceKey.isBlank() || owner == null || owner.isBlank()) {
            throw new IllegalArgumentException("resourceKey and owner must not be null or blank");
        }
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
        requireKeyAndOwner(resourceKey, owner);
        String sanitizedKey = sanitizeKey(resourceKey);
        String lockKey = LOCK_PREFIX + sanitizedKey;

        try {
            // As the in-memory service: the timeout as given, to the millisecond; thirty seconds without one.
            long timeoutMs = (timeout != null ? timeout : DEFAULT_TIMEOUT).toMillis();

            Long result = redisTemplate.execute(
                    new DefaultRedisScript<>(ACQUIRE_SCRIPT, Long.class),
                    Collections.singletonList(lockKey),
                    owner,
                    Long.toString(timeoutMs)
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
        requireKeyAndOwner(resourceKey, owner);
        String sanitizedKey = sanitizeKey(resourceKey);
        String lockKey = LOCK_PREFIX + sanitizedKey;

        try {
            Long result = redisTemplate.execute(
                    new DefaultRedisScript<>(RELEASE_SCRIPT, Long.class),
                    Collections.singletonList(lockKey),
                    owner
            );

            if (result != null && result > 0) {
                                return true;
            } else if (result != null && result == -1) {
                log.error("Lock release failed for resource: {} (key: {}) - Lock doesn't exist (expired or already deleted)",
                        resourceKey, sanitizedKey);
                logLockStatus(lockKey, resourceKey, sanitizedKey);
                return false;
            } else if (result != null && result == -2) {
                log.error("Lock release failed for resource: {} (key: {}) - Owner mismatch (expected: {})",
                        resourceKey, sanitizedKey, owner);
                logLockStatus(lockKey, resourceKey, sanitizedKey);
                return false;
            } else {
                log.error("Lock release failed for resource: {} (key: {}) - Unknown error (result: {})",
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
        } catch (LockAcquisitionException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Operation failed while holding lock: " + resourceKey, e);
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
                return;
            }

            String currentOwner = (String) redisTemplate.opsForHash().get(lockKey, "owner");
            String count = (String) redisTemplate.opsForHash().get(lockKey, "count");
            Long ttl = redisTemplate.getExpire(lockKey, TimeUnit.SECONDS);
            

        } catch (Exception e) {
            log.error("Failed to get lock status for resource: {} (key: {}) - {}",
                    resourceKey, sanitizedKey, e.getMessage());
        }
    }

    public LockInfo getLockInfo(String resourceKey) {
        if (resourceKey == null || resourceKey.isBlank()) {
            return null;
        }
        String sanitizedKey = sanitizeKey(resourceKey);
        String lockKey = LOCK_PREFIX + sanitizedKey;

        try {
            String owner = (String) redisTemplate.opsForHash().get(lockKey, "owner");
            if (owner == null) {
                return null;
            }

            Object countObj = redisTemplate.opsForHash().get(lockKey, "count");
            int count = countObj != null ? Integer.valueOf(countObj.toString()) : 0;

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
        if (resourceKey == null || resourceKey.isBlank()) {
            return false;
        }
        String sanitizedKey = sanitizeKey(resourceKey);
        String lockKey = LOCK_PREFIX + sanitizedKey;

        try {
            Boolean deleted = redisTemplate.delete(lockKey);
            if (Boolean.TRUE.equals(deleted)) {
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
            }
        } catch (Exception e) {
            log.error("Failed to clear all locks", e);
        }
    }

    public boolean isLocked(String resourceKey) {
        if (resourceKey == null || resourceKey.isBlank()) {
            return false;
        }
        String sanitizedKey = sanitizeKey(resourceKey);
        String lockKey = LOCK_PREFIX + sanitizedKey;

        try {
            return redisTemplate.hasKey(lockKey);
        } catch (Exception e) {
            log.error("Failed to check lock existence for resource: {}", resourceKey, e);
            return false;
        }
    }

}