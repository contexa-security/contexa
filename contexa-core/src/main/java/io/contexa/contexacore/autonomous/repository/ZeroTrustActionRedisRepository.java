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
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.store.StoreFailures;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.serializer.GenericToStringSerializer;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.ScanOptions;

@Slf4j
public class ZeroTrustActionRedisRepository implements ZeroTrustActionRepository {

    private static final Duration LAST_VERIFIED_ACTION_TTL = Duration.ofHours(24);
    private static final Duration DEFAULT_FAIL_COUNT_TTL = Duration.ofHours(24);
    private static final ObjectMapper LEGACY_HASH_VALUE_READER = new ObjectMapper();
    private static final RedisSerializer<Long> SCRIPT_RESULT_SERIALIZER = new GenericToStringSerializer<>(Long.class);
    /** The users a server keeps a restriction for: far more than are restricted at one time. */
    private static final int RESTRICTIONS_KEPT = 100_000;
    /** How long the record's answer for a user stands while Redis does not answer: one read, not one per request. */
    private static final Duration BLOCK_RECORD_ANSWER_TTL = Duration.ofSeconds(30);

    /**
     * A restriction this server read, and until when it holds; a BLOCK holds until a read says otherwise. A CHALLENGE held
     * for the sessions that did not answer it (Q-12) names the session that read it answered: only that one goes on.
     */
    private record Restriction(ZeroTrustAction action, long untilMillis, String answeredContext) {

        static Restriction of(ZeroTrustAction action, String answeredContext) {
            return of(action, action.getDefaultTtl(), answeredContext);
        }

        static Restriction of(ZeroTrustAction action, Duration ttl, String answeredContext) {
            return new Restriction(action, ttl != null ? System.currentTimeMillis() + ttl.toMillis() : Long.MAX_VALUE,
                    answeredContext);
        }

        boolean holdsFor(String context) {
            return System.currentTimeMillis() < untilMillis && (answeredContext == null || !answeredContext.equals(context));
        }
    }

    /** What the store holds for a user, and whether it is a CHALLENGE no model decided. */
    private record StoredAction(ZeroTrustAction action, boolean technical) {

        static StoredAction of(ZeroTrustAction action) {
            return new StoredAction(action, false);
        }

        /** The mark is read as the script reads it: the field is there, whatever it holds. */
        static StoredAction of(ZeroTrustAction action, Map<Object, Object> analysis) {
            return new StoredAction(action, action == ZeroTrustAction.CHALLENGE && analysis.containsKey(TECHNICAL_CHALLENGE));
        }

        /** How long what was read stands while Redis does not answer: as long as it lasts by itself. */
        Duration ttl() {
            return technical ? TECHNICAL_CHALLENGE_TTL : action.getDefaultTtl();
        }
    }

    /**
     * Replaces the analysis hash and the last verified keys unless the stored action refuses the
     * new one. KEYS: analysis hash, last verified action, last verified context, BLOCK flag, the
     * CHALLENGE held for other sessions. ARGV: hash field names of action and previousAction, whether
     * the BLOCK flag refuses the new action ('1' when it is less strict than a BLOCK), the refusing
     * stored action values, the hash field of the technical CHALLENGE mark and the stored action
     * values that refuse the new action unless that mark is there (Q-5), the plain and stored value
     * of every action, the analysis TTL in milliseconds (0 keeps no TTL), the action name, the last
     * verified TTL in milliseconds, a context flag and value, whether a held CHALLENGE refuses it
     * ('1' when it is less strict, unless its context answered), then the hash field/value pairs.
     * Returns 0 when refused and 1 when written.
     */
    private static final DefaultRedisScript<Long> SAVE_FINAL_ACTION_SCRIPT = new DefaultRedisScript<>("""
            local actionField = ARGV[1]
            local previousField = ARGV[2]
            if ARGV[3] == '1' and redis.call('GET', KEYS[4]) == 'true' then
                return 0
            end
            local current = redis.call('HGET', KEYS[1], actionField)
            local index = 4
            local refusedCount = tonumber(ARGV[index])
            index = index + 1
            for i = index, index + refusedCount - 1 do
                if current == ARGV[i] then
                    return 0
                end
            end
            index = index + refusedCount
            local technical = redis.call('HEXISTS', KEYS[1], ARGV[index]) == 1
            local unmarkedCount = tonumber(ARGV[index + 1])
            index = index + 2
            for i = index, index + unmarkedCount - 1 do
                if current == ARGV[i] and not technical then
                    return 0
                end
            end
            index = index + unmarkedCount
            local previous = current
            local formCount = tonumber(ARGV[index])
            index = index + 1
            for i = index, index + 2 * formCount - 1, 2 do
                if current == ARGV[i] then
                    previous = ARGV[i + 1]
                end
            end
            index = index + 2 * formCount
            local analysisTtl = ARGV[index]
            local lastAction = ARGV[index + 1]
            local lastTtl = ARGV[index + 2]
            local contextPresent = ARGV[index + 3]
            local context = ARGV[index + 4]
            local heldBack = ARGV[index + 5]
            index = index + 6
            if heldBack == '1' and redis.call('EXISTS', KEYS[5]) == 1
                    and (contextPresent ~= '1' or redis.call('HEXISTS', KEYS[5], context) == 0) then
                return 0
            end
            redis.call('DEL', KEYS[1])
            if previous then
                redis.call('HSET', KEYS[1], previousField, previous)
            end
            for i = index, #ARGV, 2 do
                redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])
            end
            if tonumber(analysisTtl) > 0 then
                redis.call('PEXPIRE', KEYS[1], analysisTtl)
            end
            redis.call('SET', KEYS[2], lastAction, 'PX', lastTtl)
            if contextPresent == '1' then
                redis.call('SET', KEYS[3], context, 'PX', lastTtl)
            else
                redis.call('DEL', KEYS[3])
            end
            return 1
            """, Long.class);

    /**
     * Q-12: starts what is held for the other sessions from the CHALLENGE in force, with the time it has left, or adds
     * a session to what is held. KEYS: analysis hash, held contexts. ARGV: hash field name of action, the plain and
     * stored CHALLENGE, the field of the decision's time and that time, the context (empty without one), the TTL to
     * use when the CHALLENGE shows none. Returns 1 when something is held and 0 when nothing is.
     */
    private static final DefaultRedisScript<Long> HOLD_CHALLENGE_SCRIPT = new DefaultRedisScript<>("""
            local action = redis.call('HGET', KEYS[1], ARGV[1])
            local context = ARGV[6]
            if action == ARGV[2] or action == ARGV[3] then
                local ttl = redis.call('PTTL', KEYS[1])
                if ttl <= 0 then
                    ttl = tonumber(ARGV[7])
                end
                redis.call('DEL', KEYS[2])
                redis.call('HSET', KEYS[2], ARGV[4], ARGV[5])
                if context ~= '' then
                    redis.call('HSET', KEYS[2], context, '1')
                end
                redis.call('PEXPIRE', KEYS[2], ttl)
                return 1
            end
            if redis.call('EXISTS', KEYS[2]) == 1 then
                if context ~= '' then
                    redis.call('HSET', KEYS[2], context, '1')
                end
                return 1
            end
            return 0
            """, Long.class);

    /** The field of a held CHALLENGE that says when it was decided; the other fields are the contexts that answered. */
    private static final String HOLD_SINCE_FIELD = "since";

    private final RedisTemplate<String, Object> redisTemplate;
    private final StringRedisTemplate stringRedisTemplate;
    private final Duration failCountTtl;

    /** Set by a final write the calling thread made that a stricter action in effect kept out (W5-3). */
    private final ThreadLocal<Boolean> finalWriteKeptStricter = new ThreadLocal<>();

    /** What a stored ESCALATE is replaced with when it is read; null keeps it. */
    private volatile ZeroTrustAction escalateReplacement;

    private volatile Duration allowValidity = ZeroTrustAction.ALLOW.getDefaultTtl();

    /** Q-28: how long an ALLOW answers its context without a new analysis. */
    public void setAllowValidity(Duration allowValidity) {
        this.allowValidity = ZeroTrustActionPrecedence.allowValidity(allowValidity);
    }

    /**
     * D-1 (PR-84): the restrictions this server read last. A read that fails used to answer PENDING_ANALYSIS, which every
     * reader lets through, so a Redis outage lifted every BLOCK and CHALLENGE. Each read refreshes this, so a restriction
     * lifted while Redis answers is gone from it too.
     */
    private final Cache<String, Restriction> restrictionsRead = Caffeine.newBuilder().maximumSize(RESTRICTIONS_KEPT).build();
    private final Cache<String, Boolean> blockRecordAnswers = Caffeine.newBuilder().maximumSize(RESTRICTIONS_KEPT)
            .expireAfterWrite(BLOCK_RECORD_ANSWER_TTL).build();
    /** Whether the database's record holds a block in force for a user; the second copy of a BLOCK. */
    private volatile Predicate<String> blockRecord;

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

    @Override
    public void setEscalateTerminalAction(ZeroTrustAction action) {
        this.escalateReplacement = ZeroTrustActionPrecedence.storedEscalateReplacement(action);
    }

    /**
     * What to ask about a user this server read no restriction for, while Redis does not answer. A BLOCK decided on
     * another server, or before this one started, is known only there.
     */
    public void setBlockRecord(Predicate<String> blockRecord) {
        this.blockRecord = blockRecord;
    }

    /**
     * Keeps what a read found for the moment Redis stops answering, and passes it on. It is kept under the key a restriction
     * is enforced under, so every spelling of a name meets it. It stands as long as it lasts by itself: a CHALLENGE
     * no model decided is short, and an outage of the store does not make it long.
     */
    private ZeroTrustAction read(String userId, StoredAction stored) {
        ZeroTrustAction action = stored.action();
        if (action.isAccessRestricted()) {
            restrictionsRead.put(ZeroTrustUserKey.of(userId), Restriction.of(action, stored.ttl(), null));
        } else {
            restrictionsRead.invalidate(ZeroTrustUserKey.of(userId));
        }
        return action;
    }

    /**
     * The action in force for a user whose stored decision cannot be read: the restriction this server read last, or the
     * block the database records. Nothing else is known, so anything else goes on undecided, as the operating mode
     * specifies; the store's gate reports the outage and the protected calls that passed.
     */
    private ZeroTrustAction inForceWhileUnreadable(String userId, String contextBindingHash, Exception failure) {
        if (!StoreFailures.isReportedOutage(failure)) {
            log.error("[ZeroTrustActionRedisRepository] Failed to get current action: userId={}", userId, failure);
        }
        Restriction restriction = restrictionsRead.getIfPresent(ZeroTrustUserKey.of(userId));
        if (restriction != null && restriction.holdsFor(contextBindingHash)) {
            return restriction.action();
        }
        return blockRecorded(userId) ? ZeroTrustAction.BLOCK : ZeroTrustAction.PENDING_ANALYSIS;
    }

    /** How long what this server read of the user stands while Redis does not answer; 0 when it read no restriction. */
    long restrictionHeldMillis(String userId) {
        Restriction restriction = restrictionsRead.getIfPresent(ZeroTrustUserKey.of(userId));
        return restriction != null ? Math.max(0L, restriction.untilMillis() - System.currentTimeMillis()) : 0L;
    }

    private boolean blockRecorded(String userId) {
        Predicate<String> record = blockRecord;
        if (record == null) {
            return false;
        }
        String key = ZeroTrustUserKey.of(userId);
        Boolean answered = blockRecordAnswers.getIfPresent(key);
        if (answered != null) {
            return answered;
        }
        boolean recorded;
        try {
            recorded = record.test(userId);
        } catch (RuntimeException unavailable) {
            if (!StoreFailures.isReportedOutage(unavailable)) {
                log.error("[ZeroTrustActionRedisRepository] Failed to read the block record: userId={}", userId, unavailable);
            }
            return false;
        }
        blockRecordAnswers.put(key, recorded);
        return recorded;
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
            if (blockedFlagStands(userId)) {
                return read(userId, StoredAction.of(ZeroTrustAction.BLOCK));
            }

            Map<Object, Object> analysis = settledAnalysis(userId);
            Object actionValue = analysis.get("action");
            // Z-16 (1-a): outside a request a decision past its TTL lapses as it does in one
            // (ZeroTrustActionPrecedence: an ALLOW or CHALLENGE lapses with its TTL); only an unresolved ESCALATE stays.
            StoredAction stored = actionValue != null
                    ? StoredAction.of(ZeroTrustAction.fromString(actionValue.toString()), analysis)
                    : StoredAction.of(unresolvedEscalationOrPending(userId));
            return heldBack(userId, null, read(userId, stored));
        } catch (Exception e) {
            return inForceWhileUnreadable(userId, null, e);
        }
    }

    public ZeroTrustAction getCurrentAction(String userId, String contextBindingHash) {
        if (userId == null || userId.isBlank()) {
            return ZeroTrustAction.PENDING_ANALYSIS;
        }

        try {
            OneTrip oneTrip = oneTrip(userId, contextBindingHash);
            if (blockedFlagStands(userId, oneTrip)) {
                return read(userId, StoredAction.of(ZeroTrustAction.BLOCK));
            }
            return heldBack(userId, contextBindingHash, read(userId, storedAction(userId, contextBindingHash, oneTrip)), oneTrip);
        } catch (Exception e) {
            return inForceWhileUnreadable(userId, contextBindingHash, e);
        }
    }

    private StoredAction storedAction(String userId, String contextBindingHash, OneTrip oneTrip) {
        Map<Object, Object> analysis = settledAnalysis(userId, oneTrip);
        if (analysis.isEmpty()) {
            return StoredAction.of(unresolvedEscalationOrPending(userId));
        }
        Object actionValue = analysis.get("action");
        Object storedHash = analysis.get("contextBindingHash");

        if (actionValue != null) {
            ZeroTrustAction action = ZeroTrustAction.fromString(actionValue.toString());
            if (ZeroTrustActionPrecedence.isContextBound(action)
                    && contextBindingHash != null
                    && storedHash != null
                    && !storedHash.toString().equals(contextBindingHash)) {
                log.debug("[ZeroTrustActionRedisRepository] Context binding hash mismatch detected: userId={}, action={}", userId, action);
                return StoredAction.of(ZeroTrustAction.PENDING_ANALYSIS);
            }
            return StoredAction.of(action, analysis);
        }

        String lastAction = readLastVerifiedAction(userId);
        if (lastAction != null) {
            ZeroTrustAction action = ZeroTrustAction.fromString(lastAction);
            if (ZeroTrustActionPrecedence.isContextBound(action)
                    && contextBindingHash != null) {
                String lastContextHash = readLastVerifiedActionContext(userId);
                if (lastContextHash != null && !lastContextHash.equals(contextBindingHash)) {
                    log.debug("[ZeroTrustActionRedisRepository] Last verified context binding hash mismatch: userId={}, action={}", userId, action);
                    return StoredAction.of(ZeroTrustAction.PENDING_ANALYSIS);
                }
            }
            return StoredAction.of(action);
        }

        return StoredAction.of(ZeroTrustAction.PENDING_ANALYSIS);
    }

    /**
     * Q-12: what the context reads under a CHALLENGE held for the sessions that did not answer it. Only a read that
     * would be less strict is looked at, so what is stricter than the CHALLENGE costs nothing.
     */
    private ZeroTrustAction heldBack(String userId, String contextBindingHash, ZeroTrustAction action) {
        return heldBack(userId, contextBindingHash, action, null);
    }

    private ZeroTrustAction heldBack(String userId, String contextBindingHash, ZeroTrustAction action, OneTrip oneTrip) {
        if (!ZeroTrustActionPrecedence.keepsActiveRestriction(ZeroTrustAction.CHALLENGE, action)) {
            return action;
        }
        List<Object> held = oneTrip != null ? oneTrip.held() : stringRedisTemplate.opsForHash().multiGet(
                ZeroTrustRedisKeys.autonomousChallengeHold(userId),
                List.of(HOLD_SINCE_FIELD, contextBindingHash != null ? contextBindingHash : HOLD_SINCE_FIELD));
        if (held.get(0) == null) {
            return action;
        }
        boolean answered = contextBindingHash != null && held.get(1) != null;
        // The hold outlives an outage as a restriction does: the sessions that did not answer stay stopped. It has the
        // time of the CHALLENGE it was made from, a short one when no model decided it, and stands no longer than that.
        Long left = stringRedisTemplate.getExpire(ZeroTrustRedisKeys.autonomousChallengeHold(userId), TimeUnit.MILLISECONDS);
        Duration ttl = left != null && left > 0 ? Duration.ofMillis(left) : ZeroTrustAction.CHALLENGE.getDefaultTtl();
        restrictionsRead.put(ZeroTrustUserKey.of(userId),
                Restriction.of(ZeroTrustAction.CHALLENGE, ttl, answered ? contextBindingHash : null));
        return answered ? action : ZeroTrustAction.CHALLENGE;
    }

    /** The write fails with an exception: an answer that could not be kept to its session releases no one. */
    @Override
    @SuppressWarnings("unchecked")
    public void holdChallengeForOtherSessions(String userId, String contextBindingHash) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        RedisSerializer<Object> hashKeySerializer = (RedisSerializer<Object>) redisTemplate.getHashKeySerializer();
        RedisSerializer<Object> hashValueSerializer = (RedisSerializer<Object>) redisTemplate.getHashValueSerializer();
        Object decidedAt = readAnalysis(userId).get("updatedAt");
        stringRedisTemplate.execute(HOLD_CHALLENGE_SCRIPT, RedisSerializer.byteArray(), SCRIPT_RESULT_SERIALIZER,
                List.of(ZeroTrustRedisKeys.autonomousActionAnalysis(userId), ZeroTrustRedisKeys.autonomousChallengeHold(userId)),
                (Object[]) new byte[][] {
                        serialize(hashKeySerializer, "action"),
                        utf8(ZeroTrustAction.CHALLENGE.name()),
                        serialize(hashValueSerializer, ZeroTrustAction.CHALLENGE.name()),
                        utf8(HOLD_SINCE_FIELD),
                        utf8(decidedAt != null ? decidedAt.toString() : Instant.now().toString()),
                        utf8(contextBindingHash != null ? contextBindingHash : ""),
                        utf8(Long.toString(ZeroTrustAction.CHALLENGE.getDefaultTtl().toMillis()))});
    }

    @Override
    public Instant challengeHeldSince(String userId) {
        if (userId == null || userId.isBlank()) {
            return null;
        }
        try {
            Object since = stringRedisTemplate.opsForHash().get(ZeroTrustRedisKeys.autonomousChallengeHold(userId),
                    HOLD_SINCE_FIELD);
            return since != null ? Instant.parse(since.toString()) : null;
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to read a held challenge: userId={}", userId, e);
            return null;
        }
    }

    /** The user's BLOCK flag, or the one an earlier version stored under the name as typed. */
    private boolean blockedFlagStands(String userId, OneTrip oneTrip) {
        if (oneTrip != null) {
            return "true".equals(oneTrip.blocked()) || "true".equals(oneTrip.blockedAsTyped());
        }
        return blockedFlagStands(userId);
    }

    private boolean blockedFlagStands(String userId) {
        String blockKey = ZeroTrustRedisKeys.userBlocked(userId);
        if ("true".equals(stringRedisTemplate.opsForValue().get(blockKey))) {
            return true;
        }
        String typedKey = ZeroTrustRedisKeys.userBlockedAsTyped(userId);
        return !typedKey.equals(blockKey) && "true".equals(stringRedisTemplate.opsForValue().get(typedKey));
    }

    // An ESCALATE whose analysis hash expires without resolution keeps reading as ESCALATE through the 24 h
    // last-verified key, so the access filter promotes it to BLOCK; every other expired action reads as PENDING_ANALYSIS.
    // With a replacement set it ends here instead, and nothing promotes it.
    private ZeroTrustAction unresolvedEscalationOrPending(String userId) {
        String lastAction = readLastVerifiedAction(userId);
        if (lastAction == null || ZeroTrustAction.fromString(lastAction) != ZeroTrustAction.ESCALATE) {
            return endedMeanwhileOrPending(userId);
        }
        ZeroTrustAction replacement = escalateReplacement;
        if (replacement == null) {
            return ZeroTrustAction.ESCALATE;
        }
        replaceStoredEscalate(userId, replacement, Map.of());
        return replacement;
    }

    /**
     * A reader that found no analysis can meet the last-verified record another reader has just written as it ended the
     * ESCALATE: the replacement stands, and a request read as pending would get past it.
     */
    private ZeroTrustAction endedMeanwhileOrPending(String userId) {
        ZeroTrustAction replacement = escalateReplacement;
        Object action = replacement != null ? readAnalysis(userId).get("action") : null;
        return action != null && ZeroTrustAction.fromString(action.toString()) == replacement
                ? replacement : ZeroTrustAction.PENDING_ANALYSIS;
    }

    /** The user's analysis for a reader: an ESCALATE in it ends first, when a replacement is set. */
    private Map<Object, Object> settledAnalysis(String userId) {
        return settledAnalysis(userId, null);
    }

    private Map<Object, Object> settledAnalysis(String userId, OneTrip oneTrip) {
        Map<Object, Object> analysis = oneTrip != null ? oneTrip.analysis() : readAnalysis(userId);
        ZeroTrustAction replacement = escalateReplacement;
        Object action = analysis.get("action");
        if (replacement == null || action == null
                || ZeroTrustAction.fromString(action.toString()) != ZeroTrustAction.ESCALATE) {
            return analysis;
        }
        replaceStoredEscalate(userId, replacement, analysis);
        return readAnalysis(userId);
    }

    /**
     * Ends the ESCALATE left in the store as the replacement, with the replacement's own TTL; the analysis stays with it
     * (a step-up learns the request it stopped from its id). The check and the write run in one script, so any other
     * action stored by now, or a BLOCK flag, keeps the store as it is: a decision that landed first is never overwritten.
     */
    private void replaceStoredEscalate(String userId, ZeroTrustAction replacement, Map<Object, Object> analysis) {
        Map<String, Object> kept = new HashMap<>();
        analysis.forEach((field, value) -> kept.put(field.toString(), value));
        kept.keySet().removeAll(List.of("action", "previousAction", "updatedAt"));
        List<ZeroTrustAction> otherActions = Arrays.stream(ZeroTrustAction.values())
                .filter(action -> action != ZeroTrustAction.ESCALATE).toList();
        Long written = stringRedisTemplate.execute(SAVE_FINAL_ACTION_SCRIPT, RedisSerializer.byteArray(),
                SCRIPT_RESULT_SERIALIZER, finalActionKeys(userId),
                actionScriptArgs(replacement, kept, true, otherActions, List.of(), false).toArray());
        if (written != null && written == 1L) {
            log.warn("[ZeroTrustActionRedisRepository] Stored ESCALATE ended: userId={}, action={}", userId, replacement);
        }
    }

    public ZeroTrustAnalysisData getAnalysisData(String userId) {
        if (userId == null || userId.isBlank()) {
            return ZeroTrustAnalysisData.pending();
        }

        try {
            Map<Object, Object> entries = settledAnalysis(userId);

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
            if (!StoreFailures.isReportedOutage(e)) {
                log.error("[ZeroTrustActionRedisRepository] Failed to get analysis data: userId={}", userId, e);
            }
            return ZeroTrustAnalysisData.pending();
        }
    }

    public ZeroTrustAction getActionFromHash(String userId) {
        if (userId == null || userId.isBlank()) {
            return null;
        }

        try {
            Object actionValue = settledAnalysis(userId).get("action");
            if (actionValue != null) {
                return ZeroTrustAction.fromString(actionValue.toString());
            }
            return null;
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to get action from hash: userId={}", userId, e);
            return null;
        }
    }

    @Override
    public boolean isTechnicalChallenge(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        try {
            Map<Object, Object> analysis = readAnalysis(userId);
            Object action = analysis.get("action");
            return action != null && StoredAction.of(ZeroTrustAction.fromString(action.toString()), analysis).technical();
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to read the technical CHALLENGE mark: userId={}", userId, e);
            return false;
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
            if (!StoreFailures.isReportedOutage(e)) {
                log.error("[ZeroTrustActionRedisRepository] Failed to check block-mfa-pending: userId={}", userId, e);
            }
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
            String retryKey = ZeroTrustRedisKeys.escalateRetry(userId);
            return Boolean.TRUE.equals(stringRedisTemplate.hasKey(retryKey));
        } catch (Exception e) {
            if (!StoreFailures.isReportedOutage(e)) {
                log.error("[ZeroTrustActionRedisRepository] Failed to check escalate retry: userId={}", userId, e);
            }
            return false;
        }
    }

    @Override
    public void setEscalateRetry(String userId, Duration ttl) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        try {
            String retryKey = ZeroTrustRedisKeys.escalateRetry(userId);
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

            Duration ttl = ZeroTrustActionPrecedence.ttlOf(action, additionalFields, allowValidity);
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

    @Override
    public boolean saveFinalAction(
            String userId,
            ZeroTrustAction action,
            Map<String, Object> additionalFields) {
        if (userId == null || userId.isBlank() || action == null || additionalFields == null) {
            return false;
        }
        Object observationId = additionalFields.get("observationId");
        Object processingGeneration = additionalFields.get("processingGeneration");
        if (observationId == null || observationId.toString().isBlank()
                || processingGeneration == null || processingGeneration.toString().isBlank()) {
            return false;
        }

        // A less strict result never replaces an active user-level BLOCK, CHALLENGE or ESCALATE, whichever
        // session it was analysed for (RL-13). A BLOCK is active while its analysis says so or its flag
        // stands. The check and the write run in one script so that a concurrent final write cannot slip
        // in between. A refused write is reported as applied because the stricter action stays in effect;
        // reporting it as a failure would only cause retries.
        Long written;
        try {
            written = stringRedisTemplate.execute(SAVE_FINAL_ACTION_SCRIPT, RedisSerializer.byteArray(),
                    SCRIPT_RESULT_SERIALIZER, finalActionKeys(userId),
                    finalActionScriptArgs(action, additionalFields).toArray());
        } catch (Exception exception) {
            log.error("[ZeroTrustActionRedisRepository] Failed to save final action: userId={}, action={}",
                    userId, action, exception);
            return false;
        }
        if (written == null) {
            log.error("[ZeroTrustActionRedisRepository] Final action script gave no answer: userId={}, action={}",
                    userId, action);
            return false;
        }
        if (written == 0L) {
            finalWriteKeptStricter.set(Boolean.TRUE);
        }
        // The script checked and wrote in one step, so its answer is the outcome of this write, as the in-memory
        // repository's write under the user's lock is. The keys are not read back: a later decision of the same user
        // may have replaced this one by then, and that is no failed write (PR-72).
        return true;
    }

    @Override
    public FinalActionWrite writeFinalAction(String userId, ZeroTrustAction action, Map<String, Object> additionalFields) {
        finalWriteKeptStricter.remove();
        try {
            if (!saveFinalAction(userId, action, additionalFields)) {
                return FinalActionWrite.FAILED;
            }
            return Boolean.TRUE.equals(finalWriteKeptStricter.get())
                    ? FinalActionWrite.KEPT_STRICTER : FinalActionWrite.APPLIED;
        } finally {
            finalWriteKeptStricter.remove();
        }
    }

    /**
     * Checked and written in the script of a final decision: a BLOCK flag, a stored BLOCK or ESCALATE, a CHALLENGE a
     * model decided (one without the mark of a CHALLENGE no model decided) and a CHALLENGE held for the sessions that
     * did not answer it each keep the store as it is.
     */
    @Override
    public FinalActionWrite writeUndecidedChallenge(String userId, Map<String, Object> fields) {
        if (userId == null || userId.isBlank()) {
            return FinalActionWrite.FAILED;
        }
        Map<String, Object> challenge = fields != null ? new HashMap<>(fields) : new HashMap<>();
        Long written;
        try {
            written = stringRedisTemplate.execute(SAVE_FINAL_ACTION_SCRIPT, RedisSerializer.byteArray(),
                    SCRIPT_RESULT_SERIALIZER, finalActionKeys(userId),
                    actionScriptArgs(ZeroTrustAction.CHALLENGE, challenge, true,
                            List.of(ZeroTrustAction.BLOCK, ZeroTrustAction.ESCALATE), List.of(ZeroTrustAction.CHALLENGE),
                            true).toArray());
        } catch (Exception exception) {
            log.error("[ZeroTrustActionRedisRepository] Failed to save an undecided CHALLENGE: userId={}", userId,
                    exception);
            return FinalActionWrite.FAILED;
        }
        if (written == null) {
            return FinalActionWrite.FAILED;
        }
        return written == 0L ? FinalActionWrite.KEPT_STRICTER : FinalActionWrite.APPLIED;
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
            fields.remove(TECHNICAL_CHALLENGE);
            fields.put("previousAction", previousActionStr);
            fields.put("action", newAction.name());
            fields.put("updatedAt", Instant.now().toString());

            Duration ttl = ZeroTrustActionPrecedence.ttlOf(newAction, null, allowValidity);
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
            fields.remove(TECHNICAL_CHALLENGE);
            fields.put("previousAction", previousActionStr);
            fields.put("action", newAction.name());
            fields.put("updatedAt", Instant.now().toString());
            if (contextBindingHash != null) {
                fields.put("contextBindingHash", contextBindingHash);
            }

            Duration ttl = ZeroTrustActionPrecedence.ttlOf(newAction, null, allowValidity);
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
            throw new IllegalStateException("Required BLOCK flag could not be stored", e);
        }
    }

    /**
     * Writes the BLOCK flag only where there is none: an existing flag keeps its value and its time (it has none). Like the
     * flag of a BLOCK decided here it has no expiry, and it is written with a failure that reaches the caller.
     */
    @Override
    public boolean restoreBlockedFlag(String userId) {
        if (userId == null || userId.isBlank()) {
            return false;
        }

        try {
            return Boolean.TRUE.equals(stringRedisTemplate.opsForValue().setIfAbsent(ZeroTrustRedisKeys.userBlocked(userId), "true"));
        } catch (Exception e) {
            throw new IllegalStateException("A BLOCK flag could not be restored", e);
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

    /** A read that fails is thrown: an empty answer would say no decision is on record. */
    @Override
    public String decidedContext(String userId) {
        if (userId == null || userId.isBlank()) {
            return null;
        }
        Object context = readAnalysis(userId).get("contextBindingHash");
        return context != null ? context.toString() : readLastVerifiedActionContext(userId);
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
            if (!StoreFailures.isReportedOutage(e)) {
                log.error("[ZeroTrustActionRedisRepository] Failed to get block MFA fail count: userId={}", userId, e);
            }
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
            stringRedisTemplate.delete(List.of(ZeroTrustRedisKeys.userBlocked(userId),
                    ZeroTrustRedisKeys.userBlockedAsTyped(userId), ZeroTrustRedisKeys.blockMfaVerified(userId)));
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to remove blocked flag: userId={}", userId, e);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public void removeLogoutData(String userId) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        // BLOCK, ESCALATE and CHALLENGE restrict the user rather than the session that logs out, so
        // an active one keeps every key. Each action is passed plain and serialized; ARGV[1] is BLOCK and
        // ARGV[3] ESCALATE. Z-16 (1-b): an ESCALATE whose analysis expired unresolved still reads as ESCALATE
        // through its last verified key, so it is kept too, as in the in-memory repository.
        RedisSerializer<Object> hashValueSerializer = (RedisSerializer<Object>) redisTemplate.getHashValueSerializer();
        List<String> retainedActions = new ArrayList<>();
        for (ZeroTrustAction retained : List.of(ZeroTrustAction.BLOCK, ZeroTrustAction.ESCALATE, ZeroTrustAction.CHALLENGE)) {
            retainedActions.add(retained.name());
            retainedActions.add(new String(hashValueSerializer.serialize(retained.name()), StandardCharsets.UTF_8));
        }
        DefaultRedisScript<Long> script = new DefaultRedisScript<>("""
                local action = redis.call('HGET', KEYS[1], 'action')
                local lastVerified = redis.call('GET', KEYS[2])
                if redis.call('GET', KEYS[3]) == 'true'
                    or lastVerified == ARGV[1] then
                    return 0
                end
                if not action and lastVerified == ARGV[3] then
                    return 0
                end
                for _, retained in ipairs(ARGV) do
                    if action == retained then
                        return 0
                    end
                end
                return redis.call('DEL', unpack(KEYS))
                """, Long.class);
        // The context of the last decision stays: the logout ends one session, and another one stolen elsewhere is
        // still compared with it. It answers nothing by itself and lapses with its own time.
        stringRedisTemplate.execute(script, List.of(
                ZeroTrustRedisKeys.autonomousActionAnalysis(userId),
                ZeroTrustRedisKeys.autonomousLastVerifiedAction(userId),
                ZeroTrustRedisKeys.userBlocked(userId),
                ZeroTrustRedisKeys.blockMfaPending(userId),
                ZeroTrustRedisKeys.blockMfaVerified(userId),
                ZeroTrustRedisKeys.blockMfaFailCount(userId)),
                retainedActions.toArray());
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
                    ZeroTrustRedisKeys.userBlockedAsTyped(userId),
                    ZeroTrustRedisKeys.blockMfaPending(userId),
                    ZeroTrustRedisKeys.blockMfaVerified(userId),
                    ZeroTrustRedisKeys.blockMfaFailCount(userId),
                    ZeroTrustRedisKeys.autonomousDecisionAuditPending(userId),
                    ZeroTrustRedisKeys.autonomousChallengeHold(userId),
                    ZeroTrustRedisKeys.escalateRetry(userId)
            );
            stringRedisTemplate.delete(stringKeys);
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to remove all user data: userId={}", userId, e);
        }
    }

    @Override
    public void removeAllAgentData(String userId) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        String agentKeys = ZeroTrustRedisKeys.globLiteral(ZeroTrustUserKey.of(userId)) + LearningSubject.AGENT_KEY + "*";
        List<String> keys = new ArrayList<>();
        for (String pattern : List.of(
                ZeroTrustRedisKeys.autonomousActionAnalysis(agentKeys),
                ZeroTrustRedisKeys.autonomousLastVerifiedAction(agentKeys),
                ZeroTrustRedisKeys.autonomousLastVerifiedActionContext(agentKeys),
                ZeroTrustRedisKeys.userBlocked(agentKeys),
                ZeroTrustRedisKeys.blockMfaPending(agentKeys),
                ZeroTrustRedisKeys.blockMfaVerified(agentKeys),
                ZeroTrustRedisKeys.blockMfaFailCount(agentKeys),
                ZeroTrustRedisKeys.autonomousDecisionAuditPending(agentKeys),
                ZeroTrustRedisKeys.autonomousChallengeHold(agentKeys),
                ZeroTrustRedisKeys.escalateRetry(agentKeys))) {
            try (Cursor<String> cursor = stringRedisTemplate.scan(
                    ScanOptions.scanOptions().match(pattern).count(500).build())) {
                cursor.forEachRemaining(keys::add);
            }
        }
        if (!keys.isEmpty()) {
            stringRedisTemplate.delete(keys);
        }
    }

    @Override
    public void markDecisionAuditPending(String userId, String contextBindingHash, Duration ttl) {
        if (userId == null || userId.isBlank() || ttl == null || ttl.isZero() || ttl.isNegative()) {
            return;
        }
        try {
            String key = ZeroTrustRedisKeys.autonomousDecisionAuditPending(userId);
            long expiresAtMs = System.currentTimeMillis() + ttl.toMillis();
            stringRedisTemplate.opsForHash().put(key, decisionAuditContextKey(contextBindingHash), Long.toString(expiresAtMs));
            Long remainingMs = stringRedisTemplate.getExpire(key, TimeUnit.MILLISECONDS);
            if (remainingMs == null || remainingMs < ttl.toMillis()) {
                stringRedisTemplate.expire(key, ttl);
            }
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to mark decision audit pending: userId={}", userId, e);
        }
    }

    @Override
    public boolean isDecisionAuditPending(String userId, String contextBindingHash) {
        if (userId == null || userId.isBlank()) {
            return false;
        }
        try {
            Object expiresAt = stringRedisTemplate.opsForHash().get(
                    ZeroTrustRedisKeys.autonomousDecisionAuditPending(userId),
                    decisionAuditContextKey(contextBindingHash));
            if (expiresAt == null) {
                return false;
            }
            return System.currentTimeMillis() < Long.parseLong(expiresAt.toString().trim());
        } catch (Exception e) {
            if (!StoreFailures.isReportedOutage(e)) {
                log.error("[ZeroTrustActionRedisRepository] Failed to read decision audit pending marker: userId={}", userId, e);
            }
            return false;
        }
    }

    @Override
    public void clearDecisionAuditPending(String userId, String contextBindingHash) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        try {
            stringRedisTemplate.opsForHash().delete(
                    ZeroTrustRedisKeys.autonomousDecisionAuditPending(userId),
                    decisionAuditContextKey(contextBindingHash));
        } catch (Exception e) {
            log.error("[ZeroTrustActionRedisRepository] Failed to clear decision audit pending marker: userId={}", userId, e);
        }
    }

    private String decisionAuditContextKey(String contextBindingHash) {
        return contextBindingHash == null || contextBindingHash.isBlank() ? "no-context" : contextBindingHash;
    }

    public void approveOverrideAtomically(String userId, ZeroTrustAction newAction) {
        if (userId == null || userId.isBlank() || newAction == null) {
            return;
        }

        try {
            String blockKey = ZeroTrustRedisKeys.userBlocked(userId);
            String typedBlockKey = ZeroTrustRedisKeys.userBlockedAsTyped(userId);
            String holdKey = ZeroTrustRedisKeys.autonomousChallengeHold(userId);
            String verifiedKey = ZeroTrustRedisKeys.blockMfaVerified(userId);
            String analysisKey = ZeroTrustRedisKeys.autonomousActionAnalysis(userId);
            String lastActionKey = ZeroTrustRedisKeys.autonomousLastVerifiedAction(userId);

            Map<String, Object> fields = mutableAnalysis(userId);
            fields.remove(TECHNICAL_CHALLENGE);
            fields.put("action", newAction.name());
            fields.put("updatedAt", Instant.now().toString());

            Duration ttl = ZeroTrustActionPrecedence.ttlOf(newAction, null, allowValidity);
            redisTemplate.execute(new SessionCallback<List<Object>>() {
                @Override
                public List<Object> execute(RedisOperations operations) throws DataAccessException {
                    operations.multi();
                    operations.delete(blockKey);
                    operations.delete(typedBlockKey);
                    operations.delete(holdKey);
                    // A verification answers the BLOCK it was passed under, so the next BLOCK needs its own.
                    operations.delete(verifiedKey);
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

    /**
     * What a call of {@code getCurrentAction} reads first, in the order it reads it: the BLOCK flag (and the flag under the name
     * as typed, when that is another key), the analysis hash and the CHALLENGE held for the other sessions. They were three
     * round trips to Redis one after the other and a protected request makes the call seven times, and a round trip is most
     * of what a request waits for, so they are asked for in one. What each answers is what its own read answers.
     */
    private record OneTrip(String blocked, String blockedAsTyped, Map<Object, Object> analysis, List<Object> held) {
    }

    /** Whether {@code getCurrentAction} reads in one trip; off only in a test that compares it with the reads one by one. */
    private volatile boolean readInOneTrip = true;
    private final AtomicLong readsInOneTrip = new AtomicLong();

    void useOneTripReads(boolean on) {
        this.readInOneTrip = on;
    }

    long oneTripReads() {
        return readsInOneTrip.get();
    }

    /**
     * The three reads in one pipeline, or null when they are to be made one by one: an analysis in a form the template cannot
     * read (an earlier version wrote one) is read by the old way, which knows that form. A store that does not answer fails
     * here as it would at the first of the reads, and the caller handles it the same.
     */
    @SuppressWarnings("unchecked")
    private OneTrip oneTrip(String userId, String contextBindingHash) {
        if (!readInOneTrip) {
            return null;
        }
        String blockKey = ZeroTrustRedisKeys.userBlocked(userId);
        String typedKey = ZeroTrustRedisKeys.userBlockedAsTyped(userId);
        boolean typedDiffers = !typedKey.equals(blockKey);
        RedisSerializer<Object> keys = (RedisSerializer<Object>) redisTemplate.getKeySerializer();
        RedisSerializer<Object> stringKeys = (RedisSerializer<Object>) stringRedisTemplate.getKeySerializer();
        RedisSerializer<Object> holdFields = (RedisSerializer<Object>) stringRedisTemplate.getHashKeySerializer();
        if (keys == null || stringKeys == null || holdFields == null) {
            return null;
        }
        byte[] rawBlock = stringKeys.serialize(blockKey);
        byte[] rawTyped = typedDiffers ? stringKeys.serialize(typedKey) : null;
        byte[] rawAnalysis = keys.serialize(ZeroTrustRedisKeys.autonomousActionAnalysis(userId));
        byte[] rawHold = stringKeys.serialize(ZeroTrustRedisKeys.autonomousChallengeHold(userId));
        byte[] rawSince = holdFields.serialize(HOLD_SINCE_FIELD);
        byte[] rawContext = holdFields.serialize(contextBindingHash != null ? contextBindingHash : HOLD_SINCE_FIELD);
        List<Object> results;
        try {
            results = redisTemplate.executePipelined((RedisCallback<Object>) connection -> {
                connection.stringCommands().get(rawBlock);
                if (rawTyped != null) {
                    connection.stringCommands().get(rawTyped);
                }
                connection.hashCommands().hGetAll(rawAnalysis);
                connection.hashCommands().hMGet(rawHold, rawSince, rawContext);
                return null;
            }, RedisSerializer.string());
        } catch (SerializationException unreadableForm) {
            return null;
        }
        int expected = typedDiffers ? 4 : 3;
        if (results == null || results.size() != expected
                || !(results.get(expected - 2) instanceof Map<?, ?>) || !(results.get(expected - 1) instanceof List<?>)) {
            return null;
        }
        readsInOneTrip.incrementAndGet();
        return new OneTrip((String) results.get(0), typedDiffers ? (String) results.get(1) : null,
                (Map<Object, Object>) results.get(expected - 2), (List<Object>) results.get(expected - 1));
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

    private static List<String> finalActionKeys(String userId) {
        return List.of(ZeroTrustRedisKeys.autonomousActionAnalysis(userId),
                ZeroTrustRedisKeys.autonomousLastVerifiedAction(userId),
                ZeroTrustRedisKeys.autonomousLastVerifiedActionContext(userId),
                ZeroTrustRedisKeys.userBlocked(userId),
                ZeroTrustRedisKeys.autonomousChallengeHold(userId));
    }

    private List<byte[]> finalActionScriptArgs(ZeroTrustAction action, Map<String, Object> additionalFields) {
        List<ZeroTrustAction> restrictions = List.of(ZeroTrustAction.BLOCK, ZeroTrustAction.CHALLENGE,
                ZeroTrustAction.ESCALATE);
        List<ZeroTrustAction> refusing = restrictions.stream()
                .filter(active -> ZeroTrustActionPrecedence.keepsActiveRestriction(active, true, action, additionalFields))
                .toList();
        List<ZeroTrustAction> refusingUnmarked = restrictions.stream()
                .filter(active -> !refusing.contains(active)
                        && ZeroTrustActionPrecedence.keepsActiveRestriction(active, false, action, additionalFields))
                .toList();
        return actionScriptArgs(action, additionalFields,
                ZeroTrustActionPrecedence.keepsActiveRestriction(ZeroTrustAction.BLOCK, action), refusing,
                refusingUnmarked, ZeroTrustActionPrecedence.keepsActiveRestriction(ZeroTrustAction.CHALLENGE, action));
    }

    /**
     * Builds the SAVE_FINAL_ACTION_SCRIPT arguments. Hash fields and values are serialized with the
     * template serializers, as {@link #saveAction} stores them; stored action values are compared in
     * plain and serialized form, as in {@link #removeLogoutData}.
     *
     * @param refusedByBlockFlag whether a standing BLOCK flag refuses the write
     * @param refusing           the stored actions that refuse the write
     * @param refusingUnmarked   the stored actions that refuse the write unless they are a technical CHALLENGE
     * @param refusedByHold      whether a CHALLENGE held for the sessions that did not answer it refuses the write
     */
    @SuppressWarnings("unchecked")
    private List<byte[]> actionScriptArgs(ZeroTrustAction action, Map<String, Object> additionalFields,
                                          boolean refusedByBlockFlag, List<ZeroTrustAction> refusing,
                                          List<ZeroTrustAction> refusingUnmarked, boolean refusedByHold) {
        RedisSerializer<Object> hashKeySerializer = (RedisSerializer<Object>) redisTemplate.getHashKeySerializer();
        RedisSerializer<Object> hashValueSerializer = (RedisSerializer<Object>) redisTemplate.getHashValueSerializer();
        List<byte[]> args = new ArrayList<>();
        args.add(serialize(hashKeySerializer, "action"));
        args.add(serialize(hashKeySerializer, "previousAction"));
        args.add(utf8(refusedByBlockFlag ? "1" : "0"));

        addStoredValues(args, refusing, hashValueSerializer);
        args.add(serialize(hashKeySerializer, TECHNICAL_CHALLENGE));
        addStoredValues(args, refusingUnmarked, hashValueSerializer);

        ZeroTrustAction[] knownActions = ZeroTrustAction.values();
        args.add(utf8(Integer.toString(knownActions.length)));
        for (ZeroTrustAction known : knownActions) {
            args.add(utf8(known.name()));
            args.add(serialize(hashValueSerializer, known.name()));
        }

        Duration ttl = ZeroTrustActionPrecedence.ttlOf(action, additionalFields, allowValidity);
        args.add(utf8(Long.toString(ttl != null ? ttl.toMillis() : 0L)));
        args.add(utf8(action.name()));
        args.add(utf8(Long.toString(LAST_VERIFIED_ACTION_TTL.toMillis())));
        Object contextBindingHash = additionalFields.get("contextBindingHash");
        args.add(utf8(contextBindingHash != null ? "1" : "0"));
        args.add(utf8(contextBindingHash != null ? contextBindingHash.toString() : ""));
        args.add(utf8(refusedByHold ? "1" : "0"));

        Map<String, Object> fields = new HashMap<>();
        fields.put("action", action.name());
        fields.put("updatedAt", Instant.now().toString());
        fields.putAll(additionalFields);
        fields.forEach((field, value) -> {
            args.add(serialize(hashKeySerializer, field));
            args.add(serialize(hashValueSerializer, canonicalizeRedisValue(value)));
        });
        return args;
    }

    /** Their count, then the plain and the serialized value of each action. */
    private static void addStoredValues(List<byte[]> args, List<ZeroTrustAction> actions,
                                        RedisSerializer<Object> hashValueSerializer) {
        args.add(utf8(Integer.toString(actions.size() * 2)));
        for (ZeroTrustAction action : actions) {
            args.add(utf8(action.name()));
            args.add(serialize(hashValueSerializer, action.name()));
        }
    }

    private static byte[] serialize(RedisSerializer<Object> serializer, Object value) {
        byte[] serialized = serializer.serialize(value);
        return serialized != null ? serialized : new byte[0];
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
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
