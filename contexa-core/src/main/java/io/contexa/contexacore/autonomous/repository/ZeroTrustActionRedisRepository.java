package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class ZeroTrustActionRedisRepository {

    private static final Duration LAST_VERIFIED_ACTION_TTL = Duration.ofHours(24);

    private final RedisTemplate<String, Object> redisTemplate;
    private final StringRedisTemplate stringRedisTemplate;

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

            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object actionValue = redisTemplate.opsForHash().get(analysisKey, "action");
            if (actionValue != null) {
                return ZeroTrustAction.fromString(actionValue.toString());
            }

            String lastActionKey = ZeroTrustRedisKeys.hcadLastVerifiedAction(userId);
            String lastAction = stringRedisTemplate.opsForValue().get(lastActionKey);
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

            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            List<Object> values = redisTemplate.opsForHash()
                    .multiGet(analysisKey, List.of("action", "contextBindingHash"));
            Object actionValue = values.get(0);
            Object storedHash = values.get(1);

            if (actionValue != null) {
                ZeroTrustAction action = ZeroTrustAction.fromString(actionValue.toString());
                if (action == ZeroTrustAction.ALLOW
                        && contextBindingHash != null
                        && storedHash != null
                        && !storedHash.toString().equals(contextBindingHash)) {
                    return ZeroTrustAction.PENDING_ANALYSIS;
                }
                return action;
            }

            String lastActionKey = ZeroTrustRedisKeys.hcadLastVerifiedAction(userId);
            String lastAction = stringRedisTemplate.opsForValue().get(lastActionKey);
            if (lastAction != null) {
                ZeroTrustAction action = ZeroTrustAction.fromString(lastAction);
                if (action == ZeroTrustAction.ALLOW && contextBindingHash != null) {
                    String lastContextKey = ZeroTrustRedisKeys.hcadLastVerifiedActionContext(userId);
                    String lastContextHash = stringRedisTemplate.opsForValue().get(lastContextKey);
                    if (lastContextHash != null && !lastContextHash.equals(contextBindingHash)) {
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
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Map<Object, Object> entries = redisTemplate.opsForHash().entries(analysisKey);

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
                    entries.get("updatedAt") != null ? entries.get("updatedAt").toString() : null
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
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object actionValue = redisTemplate.opsForHash().get(analysisKey, "action");
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
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object actionValue = redisTemplate.opsForHash().get(analysisKey, "previousAction");
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
            return false;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            Object updatedAtValue = redisTemplate.opsForHash().get(analysisKey, "updatedAt");

            if (updatedAtValue == null) {
                return false;
            }

            Instant updatedInstant = Instant.parse(updatedAtValue.toString());
            return Instant.now().toEpochMilli() - updatedInstant.toEpochMilli() > maxAgeMs;
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to check staleness: userId={}", userId, e);
            return false;
        }
    }

    public void saveAction(String userId, ZeroTrustAction action, Map<String, Object> additionalFields) {
        if (userId == null || userId.isBlank() || action == null) {
            return;
        }

        try {
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);

            Map<String, Object> fields = new HashMap<>();
            fields.put("action", action.name());
            fields.put("updatedAt", Instant.now().toString());
            if (additionalFields != null) {
                fields.putAll(additionalFields);
            }

            redisTemplate.opsForHash().putAll(analysisKey, fields);

            Duration ttl = action.getDefaultTtl();
            if (ttl != null) {
                redisTemplate.expire(analysisKey, ttl);
            }

            String lastActionKey = ZeroTrustRedisKeys.hcadLastVerifiedAction(userId);
            stringRedisTemplate.opsForValue().set(lastActionKey, action.name(), LAST_VERIFIED_ACTION_TTL);

            String lastContextKey = ZeroTrustRedisKeys.hcadLastVerifiedActionContext(userId);
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
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);

            Object previousAction = redisTemplate.opsForHash().get(analysisKey, "action");
            String previousActionStr = previousAction != null
                    ? previousAction.toString()
                    : ZeroTrustAction.PENDING_ANALYSIS.name();

            Map<String, Object> fields = new HashMap<>();
            fields.put("previousAction", previousActionStr);
            fields.put("action", newAction.name());
            fields.put("updatedAt", Instant.now().toString());

            redisTemplate.opsForHash().putAll(analysisKey, fields);

            Duration ttl = newAction.getDefaultTtl();
            if (ttl != null) {
                redisTemplate.expire(analysisKey, ttl);
            }

            String lastActionKey = ZeroTrustRedisKeys.hcadLastVerifiedAction(userId);
            stringRedisTemplate.opsForValue().set(lastActionKey, newAction.name(), LAST_VERIFIED_ACTION_TTL);

            String lastContextKey = ZeroTrustRedisKeys.hcadLastVerifiedActionContext(userId);
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
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);

            Object previousAction = redisTemplate.opsForHash().get(analysisKey, "action");
            String previousActionStr = previousAction != null
                    ? previousAction.toString()
                    : ZeroTrustAction.PENDING_ANALYSIS.name();

            Map<String, Object> fields = new HashMap<>();
            fields.put("previousAction", previousActionStr);
            fields.put("action", newAction.name());
            fields.put("updatedAt", Instant.now().toString());
            if (contextBindingHash != null) {
                fields.put("contextBindingHash", contextBindingHash);
            }

            redisTemplate.opsForHash().putAll(analysisKey, fields);

            Duration ttl = newAction.getDefaultTtl();
            if (ttl != null) {
                redisTemplate.expire(analysisKey, ttl);
            }

            String lastActionKey = ZeroTrustRedisKeys.hcadLastVerifiedAction(userId);
            stringRedisTemplate.opsForValue().set(lastActionKey, newAction.name(), LAST_VERIFIED_ACTION_TTL);

            String lastContextKey = ZeroTrustRedisKeys.hcadLastVerifiedActionContext(userId);
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
            String lastActionKey = ZeroTrustRedisKeys.hcadLastVerifiedAction(userId);
            String lastAction = stringRedisTemplate.opsForValue().get(lastActionKey);
            return lastAction != null ? ZeroTrustAction.fromString(lastAction) : null;
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to get last verified action: userId={}", userId, e);
            return null;
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

    public void approveOverrideAtomically(String userId, ZeroTrustAction newAction) {
        if (userId == null || userId.isBlank() || newAction == null) {
            return;
        }

        try {
            String blockKey = ZeroTrustRedisKeys.userBlocked(userId);
            String analysisKey = ZeroTrustRedisKeys.hcadAnalysis(userId);
            String lastActionKey = ZeroTrustRedisKeys.hcadLastVerifiedAction(userId);

            Map<String, Object> fields = new HashMap<>();
            fields.put("action", newAction.name());
            fields.put("updatedAt", Instant.now().toString());

            redisTemplate.execute(new SessionCallback<List<Object>>() {
                @Override
                public List<Object> execute(RedisOperations operations) throws DataAccessException {
                    operations.multi();
                    operations.delete(blockKey);
                    operations.opsForHash().putAll(analysisKey, fields);

                    Duration ttl = newAction.getDefaultTtl();
                    if (ttl != null) {
                        operations.expire(analysisKey, ttl);
                    }

                    return operations.exec();
                }
            });

            stringRedisTemplate.opsForValue().set(lastActionKey, newAction.name(), LAST_VERIFIED_ACTION_TTL);

            String lastContextKey = ZeroTrustRedisKeys.hcadLastVerifiedActionContext(userId);
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

    public record ZeroTrustAnalysisData(
            String action,
            Double riskScore,
            Double confidence,
            String threatEvidence,
            Integer analysisDepth,
            String updatedAt
    ) {
        public static ZeroTrustAnalysisData pending() {
            return new ZeroTrustAnalysisData(
                    ZeroTrustAction.PENDING_ANALYSIS.name(), null, null, null, null, null
            );
        }
    }
}
