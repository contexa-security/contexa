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
package io.contexa.contexacore.autonomous.repository;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Slf4j
public class ZeroTrustActionRedisRepository implements ZeroTrustActionRepository {

    private static final Duration LAST_VERIFIED_ACTION_TTL = Duration.ofHours(24);
    private static final Duration DEFAULT_FAIL_COUNT_TTL = Duration.ofHours(24);
    private static final ObjectMapper LEGACY_HASH_VALUE_READER = new ObjectMapper();
    private final RedisTemplate<String, Object> redisTemplate;
    private final StringRedisTemplate stringRedisTemplate;
    private final Duration failCountTtl;

    public ZeroTrustActionRedisRepository(RedisTemplate<String, Object> redisTemplate,
                                          StringRedisTemplate stringRedisTemplate) {
        this(redisTemplate, stringRedisTemplate, DEFAULT_FAIL_COUNT_TTL);
    }

    public ZeroTrustActionRedisRepository(RedisTemplate<String, Object> redisTemplate,
                                          StringRedisTemplate stringRedisTemplate,
                                          Duration failCountTtl) {
        this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate");
        this.stringRedisTemplate = Objects.requireNonNull(stringRedisTemplate, "stringRedisTemplate");
        this.failCountTtl = Objects.requireNonNull(failCountTtl, "failCountTtl");
    }

    public ZeroTrustAction getCurrentAction(String userId) {
        if (userId == null || userId.isBlank()) {
            return ZeroTrustAction.PENDING_ANALYSIS;
        }

        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes)
                    RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                String contextBindingHash = SessionFingerprintUtil
                        .generateContextBindingHash(attrs.getRequest());
                return getCurrentAction(userId, contextBindingHash);
            }
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to get request context, falling back to non-context check: userId={}", userId, e);
        }

        try {
            String blockKey = ZeroTrustRedisKeys.userBlocked(userId);
            if ("true".equals(stringRedisTemplate.opsForValue().get(blockKey))) {
                return ZeroTrustAction.BLOCK;
            }

            Map<Object, Object> analysis = readAnalysis(userId);
            Object actionValue = analysis.get("action");
            if (actionValue != null) {
                return ZeroTrustAction.fromString(actionValue.toString());
            }

            String lastAction = readLastVerifiedAction(userId);
            if (lastAction != null) {
                return ZeroTrustAction.fromString(lastAction);
            }

            return ZeroTrustAction.PENDING_ANALYSIS;
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to get current action: userId={}", userId, e);
            return ZeroTrustAction.PENDING_ANALYSIS;
        }
    }

    public ZeroTrustAction getCurrentAction(String userId, String contextBindingHash) {
        if (userId == null || userId.isBlank()) {
            return ZeroTrustAction.PENDING_ANALYSIS;
        }

        try {
            String blockKey = ZeroTrustRedisKeys.userBlocked(userId);
            if ("true".equals(stringRedisTemplate.opsForValue().get(blockKey))) {
                return ZeroTrustAction.BLOCK;
            }

            Map<Object, Object> analysis = readAnalysis(userId);
            if (analysis.isEmpty()) {
                return ZeroTrustAction.PENDING_ANALYSIS;
            }
            Object actionValue = analysis.get("action");
            Object storedHash = analysis.get("contextBindingHash");

            if (actionValue != null) {
                ZeroTrustAction action = ZeroTrustAction.fromString(actionValue.toString());
                if (action != ZeroTrustAction.PENDING_ANALYSIS
                        && action != ZeroTrustAction.BLOCK
                        && contextBindingHash != null
                        && storedHash != null
                        && !storedHash.toString().equals(contextBindingHash)) {
                    log.error("[ZeroTrustActionRedisRepository] Context binding hash mismatch detected: userId={}, action={}", userId, action);
                    return ZeroTrustAction.PENDING_ANALYSIS;
                }
                return action;
            }

            String lastAction = readLastVerifiedAction(userId);
            if (lastAction != null) {
                ZeroTrustAction action = ZeroTrustAction.fromString(lastAction);
                if (action != ZeroTrustAction.PENDING_ANALYSIS
                        && action != ZeroTrustAction.BLOCK
                        && contextBindingHash != null) {
                    String lastContextHash = readLastVerifiedActionContext(userId);
                    if (lastContextHash != null && !lastContextHash.equals(contextBindingHash)) {
                        log.error("[ZeroTrustActionRedisRepository] Last verified context binding hash mismatch: userId={}, action={}", userId, action);
                        return ZeroTrustAction.PENDING_ANALYSIS;
                    }
                }
                return action;
            }

            return ZeroTrustAction.PENDING_ANALYSIS;
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to get current action with context: userId={}", userId, e);
            return ZeroTrustAction.PENDING_ANALYSIS;
        }
    }

    public ZeroTrustAnalysisData getAnalysisData(String userId) {
        if (userId == null || userId.isBlank()) {
            return ZeroTrustAnalysisData.pending();
        }

        try {
            Map<Object, Object> entries = readAnalysis(userId);

            if (entries.isEmpty()) {
                return ZeroTrustAnalysisData.pending();
            }

            String action = entries.get("action") != null ? entries.get("action").toString() : null;
            if (action == null) {
                return ZeroTrustAnalysisData.pending();
            }

            return new ZeroTrustAnalysisData(
                    action,
                    parseDouble(entries.get("riskScore")),
                    parseDouble(entries.get("confidence")),
                    entries.get("threatEvidence") != null ? entries.get("threatEvidence").toString() : null,
                    parseInteger(entries.get("analysisDepth")),
                    entries.get("updatedAt") != null ? entries.get("updatedAt").toString() : null,
                    entries.get("reasoning") != null ? entries.get("reasoning").toString() : null,
                    entries.get("reasoningSummary") != null ? entries.get("reasoningSummary").toString() : null,
                    entries.get("requestId") != null ? entries.get("requestId").toString() : null,
                    entries.get("contextBindingHash") != null ? entries.get("contextBindingHash").toString() : null,
                    entries.get("llmProposedAction") != null ? entries.get("llmProposedAction").toString() : null
            );
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to get analysis data: userId={}", userId, e);
            return ZeroTrustAnalysisData.pending();
        }
    }

    public ZeroTrustAction getActionFromHash(String userId) {
        if (userId == null || userId.isBlank()) {
            return null;
        }

        try {
            Object actionValue = readAnalysis(userId).get("action");
            if (actionValue != null) {
                return ZeroTrustAction.fromString(actionValue.toString());
            }
            return null;
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to get action from hash: userId={}", userId, e);
            return null;
        }
    }

    public ZeroTrustAction getPreviousActionFromHash(String userId) {
        if (userId == null || userId.isBlank()) {
            return null;
        }

        try {
            Object actionValue = readAnalysis(userId).get("previousAction");
            if (actionValue != null) {
                return ZeroTrustAction.fromString(actionValue.toString());
            }
            return null;
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to get previous action from hash: userId={}", userId, e);
            return null;
        }
    }

    public boolean isStale(String userId, long maxAgeMs) {
        if (userId == null || userId.isBlank()) {
            return true;
        }

        try {
            Object updatedAtValue = readAnalysis(userId).get("updatedAt");

            if (updatedAtValue == null) {
                return true;
            }

            Instant updatedInstant = Instant.parse(updatedAtValue.toString());
            return Instant.now().toEpochMilli() - updatedInstant.toEpochMilli() > maxAgeMs;
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to check staleness: userId={}", userId, e);
            return true;
        }
    }

    @Override
    public boolean isBlockMfaPending(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        try {
            String key = ZeroTrustRedisKeys.blockMfaPending(userId);
            return "true".equals(stringRedisTemplate.opsForValue().get(key));
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to check block-mfa-pending: userId={}", userId, e);
            return false;
        }
    }

    @Override
    public void setBlockMfaPending(String userId) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        try {
            String key = ZeroTrustRedisKeys.blockMfaPending(userId);
            stringRedisTemplate.opsForValue().set(key, "true", Duration.ofMinutes(10));
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to set block-mfa-pending: userId={}", userId, e);
        }
    }

    @Override
    public boolean hasEscalateRetry(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        try {
            String retryKey = "security:escalate:retry:" + userId;
            return Boolean.TRUE.equals(stringRedisTemplate.hasKey(retryKey));
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to check escalate retry: userId={}", userId, e);
            return false;
        }
    }

    @Override
    public void setEscalateRetry(String userId, Duration ttl) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        try {
            String retryKey = "security:escalate:retry:" + userId;
            if (!Boolean.TRUE.equals(stringRedisTemplate.hasKey(retryKey))) {
                stringRedisTemplate.opsForValue().set(retryKey, "1", ttl);
            }
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to set escalate retry: userId={}", userId, e);
        }
    }

    public void saveAction(String userId, ZeroTrustAction action, Map<String, Object> additionalFields) {
        if (userId == null || userId.isBlank() || action == null) {
            return;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.autonomousActionAnalysis(userId);

            Object previousAction = readAnalysis(userId).get("action");

            Map<String, Object> fields = new HashMap<>();
            if (previousAction != null) {
                fields.put("previousAction", previousAction.toString());
            }
            fields.put("action", action.name());
            fields.put("updatedAt", Instant.now().toString());
            if (additionalFields != null) {
                fields.putAll(additionalFields);
            }

            Duration ttl = action.getDefaultTtl();
            replaceAnalysisAtomically(analysisKey, fields, ttl);

            String lastActionKey = ZeroTrustRedisKeys.autonomousLastVerifiedAction(userId);
            stringRedisTemplate.opsForValue().set(lastActionKey, action.name(), LAST_VERIFIED_ACTION_TTL);

            String lastContextKey = ZeroTrustRedisKeys.autonomousLastVerifiedActionContext(userId);
            if (additionalFields != null && additionalFields.containsKey("contextBindingHash")) {
                stringRedisTemplate.opsForValue().set(lastContextKey,
                        additionalFields.get("contextBindingHash").toString(), LAST_VERIFIED_ACTION_TTL);
            } else {
                stringRedisTemplate.delete(lastContextKey);
            }
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to save action: userId={}, action={}", userId, action, e);
        }
    }

    public void saveActionWithPrevious(String userId, ZeroTrustAction newAction) {
        if (userId == null || userId.isBlank() || newAction == null) {
            return;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.autonomousActionAnalysis(userId);

            Object previousAction = readAnalysis(userId).get("action");
            String previousActionStr = previousAction != null
                    ? previousAction.toString()
                    : ZeroTrustAction.PENDING_ANALYSIS.name();

            Map<String, Object> fields = mutableAnalysis(userId);
            fields.put("previousAction", previousActionStr);
            fields.put("action", newAction.name());
            fields.put("updatedAt", Instant.now().toString());

            Duration ttl = newAction.getDefaultTtl();
            replaceAnalysisAtomically(analysisKey, fields, ttl);

            String lastActionKey = ZeroTrustRedisKeys.autonomousLastVerifiedAction(userId);
            stringRedisTemplate.opsForValue().set(lastActionKey, newAction.name(), LAST_VERIFIED_ACTION_TTL);

            String lastContextKey = ZeroTrustRedisKeys.autonomousLastVerifiedActionContext(userId);
            stringRedisTemplate.delete(lastContextKey);
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to save action with previous: userId={}, action={}", userId, newAction, e);
        }
    }

    public void saveActionWithPrevious(String userId, ZeroTrustAction newAction, String contextBindingHash) {
        if (userId == null || userId.isBlank() || newAction == null) {
            return;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.autonomousActionAnalysis(userId);

            Object previousAction = readAnalysis(userId).get("action");
            String previousActionStr = previousAction != null
                    ? previousAction.toString()
                    : ZeroTrustAction.PENDING_ANALYSIS.name();

            Map<String, Object> fields = mutableAnalysis(userId);
            fields.put("previousAction", previousActionStr);
            fields.put("action", newAction.name());
            fields.put("updatedAt", Instant.now().toString());
            if (contextBindingHash != null) {
                fields.put("contextBindingHash", contextBindingHash);
            }

            Duration ttl = newAction.getDefaultTtl();
            replaceAnalysisAtomically(analysisKey, fields, ttl);

            String lastActionKey = ZeroTrustRedisKeys.autonomousLastVerifiedAction(userId);
            stringRedisTemplate.opsForValue().set(lastActionKey, newAction.name(), LAST_VERIFIED_ACTION_TTL);

            String lastContextKey = ZeroTrustRedisKeys.autonomousLastVerifiedActionContext(userId);
            if (contextBindingHash != null) {
                stringRedisTemplate.opsForValue().set(lastContextKey, contextBindingHash, LAST_VERIFIED_ACTION_TTL);
            } else {
                stringRedisTemplate.delete(lastContextKey);
            }
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to save action with previous and context: userId={}, action={}", userId, newAction, e);
        }
    }

    public void setBlockedFlag(String userId) {
        if (userId == null || userId.isBlank()) {
            return;
        }

        try {
            String userBlockedKey = ZeroTrustRedisKeys.userBlocked(userId);
            stringRedisTemplate.opsForValue().set(userBlockedKey, "true");
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to set blocked flag: userId={}", userId, e);
        }
    }

    public ZeroTrustAction getLastVerifiedAction(String userId) {
        if (userId == null || userId.isBlank()) {
            return null;
        }

        try {
            String lastAction = readLastVerifiedAction(userId);
            return lastAction != null ? ZeroTrustAction.fromString(lastAction) : null;
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to get last verified action: userId={}", userId, e);
            return null;
        }
    }

    public long incrementBlockMfaFailCount(String userId) {
        if (userId == null || userId.isBlank()) {
            return 0;
        }

        try {
            String key = ZeroTrustRedisKeys.blockMfaFailCount(userId);
            Long count = stringRedisTemplate.opsForValue().increment(key);
            stringRedisTemplate.expire(key, failCountTtl);
            return count != null ? count : 0;
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to increment block MFA fail count: userId={}", userId, e);
            return 0;
        }
    }

    public long getBlockMfaFailCount(String userId) {
        if (userId == null || userId.isBlank()) {
            return 0;
        }

        try {
            String key = ZeroTrustRedisKeys.blockMfaFailCount(userId);
            String value = stringRedisTemplate.opsForValue().get(key);
            return value != null ? Long.parseLong(value) : 0;
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to get block MFA fail count: userId={}", userId, e);
            return 0;
        }
    }

    public void clearBlockMfaPending(String userId) {
        if (userId == null || userId.isBlank()) {
            return;
        }

        try {
            stringRedisTemplate.delete(ZeroTrustRedisKeys.blockMfaPending(userId));
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to clear block MFA pending: userId={}", userId, e);
        }
    }

    public void removeBlockedFlag(String userId) {
        if (userId == null || userId.isBlank()) {
            return;
        }

        try {
            String userBlockedKey = ZeroTrustRedisKeys.userBlocked(userId);
            stringRedisTemplate.delete(userBlockedKey);
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to remove blocked flag: userId={}", userId, e);
        }
    }

    public void removeAllUserData(String userId) {
        if (userId == null || userId.isBlank()) {
            return;
        }

        try {
            redisTemplate.delete(ZeroTrustRedisKeys.autonomousActionAnalysis(userId));

            List<String> stringKeys = List.of(
                    ZeroTrustRedisKeys.autonomousLastVerifiedAction(userId),
                    ZeroTrustRedisKeys.autonomousLastVerifiedActionContext(userId),
                    ZeroTrustRedisKeys.userBlocked(userId),
                    ZeroTrustRedisKeys.blockMfaPending(userId),
                    ZeroTrustRedisKeys.blockMfaVerified(userId),
                    ZeroTrustRedisKeys.blockMfaFailCount(userId)
            );
            stringRedisTemplate.delete(stringKeys);
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to remove all user data: userId={}", userId, e);
        }
    }

    public void approveOverrideAtomically(String userId, ZeroTrustAction newAction) {
        if (userId == null || userId.isBlank() || newAction == null) {
            return;
        }

        try {
            String blockKey = ZeroTrustRedisKeys.userBlocked(userId);
            String analysisKey = ZeroTrustRedisKeys.autonomousActionAnalysis(userId);
            String lastActionKey = ZeroTrustRedisKeys.autonomousLastVerifiedAction(userId);

            Map<String, Object> fields = mutableAnalysis(userId);
            fields.put("action", newAction.name());
            fields.put("updatedAt", Instant.now().toString());

            Duration ttl = newAction.getDefaultTtl();
            redisTemplate.execute(new SessionCallback<List<Object>>() {
                @Override
                public List<Object> execute(RedisOperations operations) throws DataAccessException {
                    operations.multi();
                    operations.delete(blockKey);
                    operations.delete(analysisKey);
                    operations.opsForHash().putAll(analysisKey, fields);

                    if (ttl != null) {
                        operations.expire(analysisKey, ttl);
                    }

                    return operations.exec();
                }
            });

            stringRedisTemplate.opsForValue().set(lastActionKey, newAction.name(), LAST_VERIFIED_ACTION_TTL);

            String lastContextKey = ZeroTrustRedisKeys.autonomousLastVerifiedActionContext(userId);
            stringRedisTemplate.delete(lastContextKey);
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed atomic override approval: userId={}, action={}",
                    userId, newAction, e);
        }
    }

    private Double parseDouble(Object value) {
        if (value == null) {
            return null;
        }
        try {
            return Double.parseDouble(value.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private Integer parseInteger(Object value) {
        if (value == null) {
            return null;
        }
        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private Map<Object, Object> readAnalysis(String userId) {
        String canonicalKey = ZeroTrustRedisKeys.autonomousActionAnalysis(userId);
        try {
            Map<Object, Object> canonical = redisTemplate.opsForHash().entries(canonicalKey);
            return canonical != null ? canonical : Map.of();
        } catch (SerializationException ex) {
            Map<Object, Object> legacy = stringRedisTemplate.opsForHash().entries(canonicalKey);
            if (legacy == null || legacy.isEmpty()) {
                throw ex;
            }
            Map<Object, Object> decoded = new HashMap<>();
            legacy.forEach((key, value) -> decoded.put(key, decodeLegacyHashValue(value)));
            log.warn("[ZeroTrustActionRedisRepository] Read legacy action hash for compatible migration: key={}",
                    canonicalKey);
            return decoded;
        }
    }

    private Object decodeLegacyHashValue(Object value) {
        if (!(value instanceof String serialized)) {
            return value;
        }
        try {
            return LEGACY_HASH_VALUE_READER.readValue(serialized, Object.class);
        } catch (Exception ignored) {
            return serialized;
        }
    }

    private Map<String, Object> mutableAnalysis(String userId) {
        Map<String, Object> result = new HashMap<>();
        readAnalysis(userId).forEach((key, value) -> result.put(key.toString(), value));
        return result;
    }

    private void replaceAnalysisAtomically(String analysisKey,
                                           Map<String, Object> fields,
                                           Duration ttl) {
        Map<String, Object> canonicalFields = new HashMap<>();
        fields.forEach((key, value) -> canonicalFields.put(key, canonicalizeRedisValue(value)));
        redisTemplate.execute(new SessionCallback<List<Object>>() {
            @Override
            public List<Object> execute(RedisOperations operations) throws DataAccessException {
                operations.multi();
                operations.delete(analysisKey);
                operations.opsForHash().putAll(analysisKey, canonicalFields);
                if (ttl != null) {
                    operations.expire(analysisKey, ttl);
                }
                return operations.exec();
            }
        });
    }

    private Object canonicalizeRedisValue(Object value) {
        if (value instanceof Map<?, ?> mapValue) {
            Map<String, Object> canonical = new HashMap<>();
            mapValue.forEach((key, nestedValue) ->
                    canonical.put(key.toString(), canonicalizeRedisValue(nestedValue)));
            return canonical;
        }
        if (value instanceof Iterable<?> iterableValue) {
            List<Object> canonical = new ArrayList<>();
            iterableValue.forEach(item -> canonical.add(canonicalizeRedisValue(item)));
            return canonical;
        }
        return value;
    }

    private String readLastVerifiedAction(String userId) {
        String canonicalKey = ZeroTrustRedisKeys.autonomousLastVerifiedAction(userId);
        return stringRedisTemplate.opsForValue().get(canonicalKey);
    }

    private String readLastVerifiedActionContext(String userId) {
        String canonicalKey = ZeroTrustRedisKeys.autonomousLastVerifiedActionContext(userId);
        return stringRedisTemplate.opsForValue().get(canonicalKey);
    }

}
