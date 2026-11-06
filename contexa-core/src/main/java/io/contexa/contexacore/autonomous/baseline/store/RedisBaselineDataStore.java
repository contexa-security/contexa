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
package io.contexa.contexacore.autonomous.baseline.store;

import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.connection.DataType;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.ZSetOperations;
import org.springframework.data.redis.serializer.RedisSerializer;

@Slf4j
public class RedisBaselineDataStore implements BaselineDataStore {

    private final RedisTemplate<String, Object> redisTemplate;
    /** How long a stored baseline is kept after its last save (BR-C11, DD-52). */
    private final Duration baselineTtl;
    /** The indexes of the earlier version (a set) that this process has dealt with, by key. */
    private final Set<String> earlierIndexesDealtWith = ConcurrentHashMap.newKeySet();

    /** The name of a baseline key as an application without a name keeps it; {@link #baselinePrefix()} is where this one keeps it. */
    private static final String BASELINE_NAME_PREFIX = "security:autonomous:baseline:";
    /**
     * The name of the indexes of the baselines still stored, ordered by when each expires. They are not under
     * {@link #BASELINE_NAME_PREFIX}: no name a user is given can spell the key of an index.
     */
    private static final String BASELINE_INDEX_NAME_PREFIX = "security:autonomous:baseline-index:";
    /** How many members of an index of the earlier version are moved in one step. */
    private static final int MOVE_BATCH = 500;
    /** The retention of contexa.security.zerotrust.baseline.retention when it is not set (DD-52). */
    public static final Duration DEFAULT_BASELINE_TTL = Duration.ofDays(30);

    public RedisBaselineDataStore(RedisTemplate<String, Object> redisTemplate) {
        this(redisTemplate, DEFAULT_BASELINE_TTL);
    }

    /** A store keeping each baseline for the given retention after its last save; the default without one. */
    public RedisBaselineDataStore(RedisTemplate<String, Object> redisTemplate, Duration baselineTtl) {
        this.redisTemplate = redisTemplate;
        this.baselineTtl = baselineTtl != null && !baselineTtl.isNegative() && !baselineTtl.isZero()
                ? baselineTtl : DEFAULT_BASELINE_TTL;
    }

    @Override
    public BaselineVector getUserBaseline(String userId) {
        try {
            return loadBaseline(userId, userId, userIndexKey(), userId);
        } catch (Exception e) {
            log.error("[BaselineDataStore] User baseline retrieval failed: userId={}", userId, e);
            return null;
        }
    }

    @Override
    public void saveUserBaseline(String userId, BaselineVector baseline) {
        saveUserBaselineChecked(userId, baseline);
    }

    /** Saves the baseline and tells whether it was stored; a failed save is logged and reported, not swallowed (QF-12). */
    @Override
    public boolean saveUserBaselineChecked(String userId, BaselineVector baseline) {
        try {
            moveEarlierIndexes();
            String key = baselinePrefix() + userId;
            replaceHash(key, buildBaselineHash(userId, baseline), baselineTtl, userIndexKey(), userId);
            return true;
        } catch (Exception e) {
            log.error("[BaselineDataStore] Baseline save failed: userId={}", userId, e);
            return false;
        }
    }

    @Override
    public BaselineVector getOrganizationBaseline(String organizationId) {
        try {
            return loadBaseline("org:" + organizationId, "org:" + organizationId, orgIndexKey(), organizationId);
        } catch (Exception e) {
            log.error("[BaselineDataStore] Organization baseline retrieval failed: organizationId={}", organizationId, e);
            return null;
        }
    }

    @Override
    public void saveOrganizationBaseline(String organizationId, BaselineVector baseline) {
        try {
            moveEarlierIndexes();
            String key = baselinePrefix() + "org:" + organizationId;
            replaceHash(key, buildBaselineHash("org:" + organizationId, baseline), baselineTtl, orgIndexKey(),
                    organizationId);
        } catch (Exception e) {
            log.error("[BaselineDataStore] Organization baseline save failed: organizationId={}", organizationId, e);
        }
    }

    @Override
    public BaselineRead readUserBaseline(String userId) {
        try {
            return BaselineRead.of(loadBaseline(userId, userId, userIndexKey(), userId));
        } catch (Exception e) {
            log.error("[BaselineDataStore] User baseline read failed: userId={}", userId, e);
            return BaselineRead.failed();
        }
    }

    @Override
    public BaselineRead readOrganizationBaseline(String organizationId) {
        try {
            return BaselineRead.of(loadBaseline("org:" + organizationId, "org:" + organizationId, orgIndexKey(),
                    organizationId));
        } catch (Exception e) {
            log.error("[BaselineDataStore] Organization baseline read failed: organizationId={}", organizationId, e);
            return BaselineRead.failed();
        }
    }

    /**
     * Replaces the stored hash whole in one transaction, so that no field of an earlier baseline is left beside the
     * new one (W5-8): the key is removed and written again with its time to live. The same transaction enters the baseline
     * in the index, scored by when it expires, and drops from it what has expired: the index never holds an entry for
     * long after the baseline it points to is gone.
     */
    private void replaceHash(String key, Map<String, Object> data, Duration timeToLive, String indexKey,
                             String indexMember) {
        long now = System.currentTimeMillis();
        redisTemplate.execute(new SessionCallback<List<Object>>() {
            @Override
            @SuppressWarnings("unchecked")
            public <K, V> List<Object> execute(RedisOperations<K, V> operations) {
                RedisOperations<String, Object> transaction = (RedisOperations<String, Object>) operations;
                transaction.multi();
                transaction.delete(key);
                transaction.opsForHash().putAll(key, data);
                transaction.expire(key, timeToLive);
                transaction.opsForZSet().removeRangeByScore(indexKey, Double.NEGATIVE_INFINITY, now);
                transaction.opsForZSet().add(indexKey, indexMember, now + timeToLive.toMillis());
                return transaction.exec();
            }
        });
    }

    /** Where this application keeps its baselines: behind its name when it has one. */
    private static String baselinePrefix() {
        return ApplicationNamespace.key(BASELINE_NAME_PREFIX);
    }

    /** The users whose baseline is stored, scored by when it expires. */
    private static String userIndexKey() {
        return ApplicationNamespace.key(BASELINE_INDEX_NAME_PREFIX + "user");
    }

    /** The organizations whose baseline is stored, scored by when it expires. */
    private static String orgIndexKey() {
        return ApplicationNamespace.key(BASELINE_INDEX_NAME_PREFIX + "org");
    }

    /** The index of users that earlier versions kept: a set that was added to and never trimmed. */
    private static String earlierUserIndexKey() {
        return baselinePrefix() + "user:index";
    }

    /** The index of organizations that earlier versions kept. */
    private static String earlierOrgIndexKey() {
        return baselinePrefix() + "org:index";
    }

    /**
     * The prefixes a baseline of this application may be found under: its own and, when it has a name, the one baselines
     * were kept under before it had (see {@link #carryOverFromEarlierKey}).
     */
    private static List<String> baselinePrefixes() {
        return ApplicationNamespace.isNamed()
                ? List.of(baselinePrefix(), ApplicationNamespace.withoutName(BASELINE_NAME_PREFIX)) : List.of(baselinePrefix());
    }

    /**
     * The baseline under {@code id}. An application that has a name and finds none under its own key reads the key
     * baselines had before applications were named, once, and keeps a copy under its own key: learning is not thrown
     * away by giving the application a name, and from then on only its own key is read and written. The earlier key is
     * left as it is.
     */
    private BaselineVector loadBaseline(String id, String canonicalId, String indexKey, String indexMember) {
        BaselineVector stored = loadBaselineFromHash(baselinePrefix() + id, canonicalId);
        if (stored != null || !ApplicationNamespace.isNamed()) {
            return stored;
        }
        return carryOverFromEarlierKey(id, canonicalId, indexKey, indexMember);
    }

    private BaselineVector carryOverFromEarlierKey(String id, String canonicalId, String indexKey, String indexMember) {
        String earlierKey = ApplicationNamespace.withoutName(BASELINE_NAME_PREFIX + id);
        BaselineVector earlier = loadBaselineFromHash(earlierKey, canonicalId);
        if (earlier == null) {
            return null;
        }
        Long remaining = redisTemplate.getExpire(earlierKey, TimeUnit.MILLISECONDS);
        Duration keptFor = remaining != null && remaining > 0 ? Duration.ofMillis(remaining) : baselineTtl;
        try {
            replaceHash(baselinePrefix() + id, buildBaselineHash(canonicalId, earlier), keptFor, indexKey, indexMember);
            log.debug("[BaselineDataStore] Baseline kept before this application had a name was copied under its own key: "
                    + "id={}", id);
        } catch (Exception e) {
            log.error("[BaselineDataStore] Baseline kept before this application had a name could not be copied: id={}",
                    id, e);
        }
        return earlier;
    }

    @Override
    public Iterable<BaselineVector> listOrganizationBaselines() {
        LinkedHashMap<String, BaselineVector> baselines = new LinkedHashMap<>();
        try {
            moveEarlierIndexes();
            long now = System.currentTimeMillis();
            redisTemplate.opsForZSet().removeRangeByScore(orgIndexKey(), Double.NEGATIVE_INFINITY, now);
            Set<Object> organizationIds = redisTemplate.opsForZSet()
                    .rangeByScore(orgIndexKey(), now, Double.POSITIVE_INFINITY);
            if (organizationIds == null || organizationIds.isEmpty()) {
                return List.of();
            }
            for (Object organizationId : organizationIds) {
                if (organizationId == null) {
                    continue;
                }
                String id = String.valueOf(organizationId);
                BaselineVector baseline = getOrganizationBaseline(id);
                if (baseline != null) {
                    baselines.put(id, baseline);
                } else {
                    redisTemplate.opsForZSet().remove(orgIndexKey(), id);
                }
            }
            return baselines.values();
        } catch (Exception e) {
            log.error("[BaselineDataStore] Organization baseline listing failed", e);
            return List.of();
        }
    }

    @Override
    public void deleteUserBaseline(String userId) {
        if (userId == null || userId.isBlank()) {
            return;
        }
        String userKey = ZeroTrustUserKey.person(userId);
        deleteUserBaselineKey(userKey);
        // The user's baselines under every tenant (W5-10 D9); an agent that bears the user's name ends the same way.
        Set<String> tenantKeys = new LinkedHashSet<>();
        String agentOfThatName = LearningSubject.AGENT_KEY + userKey;
        // docs/agent A3-1: the baselines of the agents acting for the user, in every tenant.
        String agentKeys = ZeroTrustRedisKeys.globLiteral(userKey) + LearningSubject.AGENT_KEY + "*";
        for (String prefix : baselinePrefixes()) {
            try (Cursor<String> cursor = redisTemplate.scan(ScanOptions.scanOptions()
                    .match(prefix + "*" + TENANT_SEPARATOR + ZeroTrustRedisKeys.globLiteral(userKey))
                    .count(500).build())) {
                cursor.forEachRemaining(key -> {
                    if (!key.endsWith(agentOfThatName)) {
                        tenantKeys.add(key.substring(prefix.length()));
                    }
                });
            }
            for (String pattern : List.of(prefix + agentKeys, prefix + "*" + TENANT_SEPARATOR + agentKeys)) {
                try (Cursor<String> cursor = redisTemplate.scan(ScanOptions.scanOptions().match(pattern).count(500).build())) {
                    cursor.forEachRemaining(key -> tenantKeys.add(key.substring(prefix.length())));
                }
            }
        }
        for (String key : tenantKeys) {
            deleteUserBaselineKey(key);
        }
    }

    @Override
    public int deleteAgentBaselines(String agentId) {
        if (agentId == null || agentId.isBlank()) {
            return 0;
        }
        Set<String> keys = new LinkedHashSet<>();
        for (String prefix : baselinePrefixes()) {
            try (Cursor<String> cursor = redisTemplate.scan(ScanOptions.scanOptions()
                    .match(prefix + "*" + LearningSubject.AGENT_KEY + ZeroTrustRedisKeys.globLiteral(agentId))
                    .count(500).build())) {
                cursor.forEachRemaining(key -> keys.add(key.substring(prefix.length())));
            }
        }
        for (String key : keys) {
            deleteUserBaselineKey(key);
        }
        return keys.size();
    }

    @Override
    public void deleteUserBaselineKey(String key) {
        if (key == null || key.isBlank()) {
            return;
        }
        // The copy of a baseline kept before the application had a name goes with it: left behind, it would be copied back.
        for (String prefix : baselinePrefixes()) {
            redisTemplate.delete(prefix + key);
        }
        redisTemplate.opsForZSet().remove(userIndexKey(), key);
    }

    /**
     * The users whose baseline is still stored: the entries of the index that have not expired. The index is scored by
     * the time each baseline expires, and what has expired is dropped from it here, as it is at every save (QF-23).
     */
    @Override
    public long countUserBaselines() {
        try {
            moveEarlierIndexes();
            long now = System.currentTimeMillis();
            ZSetOperations<String, Object> index = redisTemplate.opsForZSet();
            index.removeRangeByScore(userIndexKey(), Double.NEGATIVE_INFINITY, now);
            Long live = index.count(userIndexKey(), now, Double.POSITIVE_INFINITY);
            return live != null ? live : 0L;
        } catch (Exception e) {
            log.error("[BaselineDataStore] User baseline count failed", e);
            return 0L;
        }
    }

    /**
     * Moves the indexes the earlier versions kept (a set per kind, added to and never trimmed, so that it held every user
     * ever seen) into the indexes scored by expiry, once per process. Only a member whose baseline is still stored is
     * moved, scored by when that baseline expires at the latest, and every member read is then removed from the set, which
     * goes with its last member. Any number of servers can do it at once: a member that is already in the new index is
     * left as it is, and a server that finds no set does nothing. An index that cannot be moved now is tried again by
     * the next call, and never stops a save.
     */
    private void moveEarlierIndexes() {
        moveEarlierIndex(earlierUserIndexKey(), userIndexKey(), baselinePrefix());
        moveEarlierIndex(earlierOrgIndexKey(), orgIndexKey(), baselinePrefix() + "org:");
    }

    private void moveEarlierIndex(String earlierKey, String indexKey, String baselineKeyPrefix) {
        if (!earlierIndexesDealtWith.add(earlierKey)) {
            return;
        }
        try {
            // Nothing to move when there is no set, or when the key is the baseline of a user who is named like the index.
            if (redisTemplate.type(earlierKey) != DataType.SET) {
                return;
            }
            Set<Object> members = redisTemplate.opsForSet().members(earlierKey);
            if (members == null || members.isEmpty()) {
                return;
            }
            List<Object> batch = new ArrayList<>(MOVE_BATCH);
            for (Object member : members) {
                if (member != null) {
                    batch.add(member);
                }
                if (batch.size() == MOVE_BATCH) {
                    moveBatch(earlierKey, indexKey, baselineKeyPrefix, batch);
                    batch = new ArrayList<>(MOVE_BATCH);
                }
            }
            if (!batch.isEmpty()) {
                moveBatch(earlierKey, indexKey, baselineKeyPrefix, batch);
            }
        } catch (RuntimeException failure) {
            earlierIndexesDealtWith.remove(earlierKey);
            log.warn("[BaselineDataStore] The index {} of the earlier version could not be moved yet: {}", earlierKey,
                    failure.getMessage());
        }
    }

    private void moveBatch(String earlierKey, String indexKey, String baselineKeyPrefix, List<Object> members) {
        @SuppressWarnings("unchecked")
        RedisSerializer<String> keys = (RedisSerializer<String>) redisTemplate.getKeySerializer();
        List<Object> remaining = redisTemplate.executePipelined((RedisCallback<Object>) connection -> {
            for (Object member : members) {
                connection.keyCommands().pTtl(keys.serialize(baselineKeyPrefix + member));
            }
            return null;
        });
        long now = System.currentTimeMillis();
        Set<ZSetOperations.TypedTuple<Object>> live = new LinkedHashSet<>();
        for (int index = 0; index < members.size(); index++) {
            Object left = index < remaining.size() ? remaining.get(index) : null;
            if (!(left instanceof Long millis) || millis == -2L) {
                continue;
            }
            long expiresAt = now + (millis >= 0 ? millis : baselineTtl.toMillis());
            live.add(ZSetOperations.TypedTuple.of(members.get(index), (double) expiresAt));
        }
        if (!live.isEmpty()) {
            redisTemplate.opsForZSet().addIfAbsent(indexKey, live);
        }
        redisTemplate.opsForSet().remove(earlierKey, members.toArray());
    }

    private Map<String, Object> buildBaselineHash(String userId, BaselineVector baseline) {
        Map<String, Object> data = new HashMap<>();
        data.put("userId", userId);
        putIfNotNull(data, "avgTrustScore", baseline.getAvgTrustScore());
        putIfNotNull(data, "avgRequestCount", baseline.getAvgRequestCount());
        putIfNotNull(data, "updateCount", baseline.getUpdateCount());
        data.put("lastUpdated", baseline.getLastUpdated() != null ?
                baseline.getLastUpdated().toString() : Instant.now().toString());
        putIfNonEmpty(data, "normalIpRanges", baseline.getNormalIpRanges());
        putIfNonEmpty(data, "normalAccessHours", baseline.getNormalAccessHours());
        putIfNonEmpty(data, "normalAccessDays", baseline.getNormalAccessDays());
        putIfNonEmpty(data, "frequentPaths", baseline.getFrequentPaths());
        putIfNonEmpty(data, "normalUserAgents", baseline.getNormalUserAgents());
        putIfNonEmpty(data, "normalOperatingSystems", baseline.getNormalOperatingSystems());
        putIfNonEmpty(data, "normalBrowsers", baseline.getNormalBrowsers());
        putIfNonEmpty(data, "normalDevices", baseline.getNormalDevices());
        putIfNonEmpty(data, "normalIpBands", baseline.getNormalIpBands());
        putIfNonEmpty(data, "normalAuthenticationTypes", baseline.getNormalAuthenticationTypes());
        putIfNonEmpty(data, "frequentActionFamilies", baseline.getFrequentActionFamilies());
        putIfNonEmpty(data, "frequentResourceFamilies", baseline.getFrequentResourceFamilies());
        putIfNotNull(data, "vocabularyVersion", baseline.getVocabularyVersion());
        putIfNonEmpty(data, "learnedDates", baseline.getLearnedDates());
        putIfNotNull(data, "recentNovelty", baseline.getRecentNovelty());
        if (baseline.getElementFrequencies() != null && !baseline.getElementFrequencies().isEmpty()) {
            data.put("elementFrequencies", baseline.getElementFrequencies());
        }
        // docs/agent A3-4: when each value was last seen and which values a verification gave, for the expiry.
        if (baseline.getElementLastSeen() != null && !baseline.getElementLastSeen().isEmpty()) {
            data.put("elementLastSeen", new HashMap<>(baseline.getElementLastSeen()));
        }
        if (baseline.getVerifiedElements() != null && !baseline.getVerifiedElements().isEmpty()) {
            data.put("verifiedElements", new ArrayList<>(baseline.getVerifiedElements()));
        }
        // QF-21: the members an organization baseline's learnings come from, as digests.
        if (baseline.getLearnedMembers() != null && !baseline.getLearnedMembers().isEmpty()) {
            data.put("learnedMembers", new ArrayList<>(baseline.getLearnedMembers()));
        }
        return data;
    }

    private static void putIfNotNull(Map<String, Object> data, String field, Object value) {
        if (value != null) {
            data.put(field, value);
        }
    }

    private BaselineVector loadBaselineFromHash(String key, String canonicalUserId) {
        Map<Object, Object> data = redisTemplate.opsForHash().entries(key);
        if (data == null || data.isEmpty()) {
            return null;
        }
        return BaselineVector.builder()
                .userId(canonicalUserId)
                .avgTrustScore(parseDouble(data.get("avgTrustScore")))
                .avgRequestCount(parseLong(data.get("avgRequestCount")))
                .updateCount(parseLong(data.get("updateCount")))
                .lastUpdated(parseInstant(data.get("lastUpdated")))
                .normalIpRanges(toStringArray(data.get("normalIpRanges")))
                .normalAccessHours(toIntegerArray(data.get("normalAccessHours")))
                .normalAccessDays(toIntegerArray(data.get("normalAccessDays")))
                .frequentPaths(toStringArray(data.get("frequentPaths")))
                .normalUserAgents(toStringArray(data.get("normalUserAgents")))
                .normalOperatingSystems(toStringArray(data.get("normalOperatingSystems")))
                .normalBrowsers(toStringArray(data.get("normalBrowsers")))
                .normalDevices(toStringArray(data.get("normalDevices")))
                .normalIpBands(toStringArray(data.get("normalIpBands")))
                .normalAuthenticationTypes(toStringArray(data.get("normalAuthenticationTypes")))
                .frequentActionFamilies(toStringArray(data.get("frequentActionFamilies")))
                .frequentResourceFamilies(toStringArray(data.get("frequentResourceFamilies")))
                .elementFrequencies(toFrequencyMap(data.get("elementFrequencies")))
                .elementLastSeen(toFrequencyMap(data.get("elementLastSeen")))
                .verifiedElements(toStringSet(data.get("verifiedElements")))
                .learnedMembers(toStringSet(data.get("learnedMembers")))
                .vocabularyVersion(data.get("vocabularyVersion") != null ? data.get("vocabularyVersion").toString() : null)
                .learnedDates(toStringArray(data.get("learnedDates")))
                .recentNovelty(data.get("recentNovelty") != null ? data.get("recentNovelty").toString() : null)
                .build();
    }

    private static void putIfNonEmpty(Map<String, Object> data, String field, Object[] array) {
        if (array != null && array.length > 0) {
            data.put(field, new ArrayList<>(Arrays.asList(array)));
        }
    }

    private double parseDouble(Object value) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String s) {
            try {
                return Double.parseDouble(s);
            } catch (NumberFormatException e) {
                return 0.0;
            }
        }
        return 0.0;
    }

    private long parseLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String s) {
            try {
                return Long.parseLong(s);
            } catch (NumberFormatException e) {
                return 0L;
            }
        }
        return 0L;
    }

    private Instant parseInstant(Object value) {
        if (value instanceof String s) {
            try {
                return Instant.parse(s);
            } catch (Exception e) {
                return Instant.now();
            }
        }
        return Instant.now();
    }

    @SuppressWarnings("unchecked")
    private String[] toStringArray(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof String[] strArr) {
            return strArr;
        }
        if (value instanceof Object[] objArr) {
            return Arrays.stream(objArr).map(String::valueOf).toArray(String[]::new);
        }
        if (value instanceof List<?> list) {
            return list.stream().map(String::valueOf).toArray(String[]::new);
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Integer[] toIntegerArray(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Integer[] intArr) {
            return intArr;
        }
        if (value instanceof Object[] objArr) {
            return Arrays.stream(objArr)
                    .map(this::coerceInteger)
                    .filter(Objects::nonNull)
                    .toArray(Integer[]::new);
        }
        if (value instanceof List<?> list) {
            return list.stream()
                    .map(this::coerceInteger)
                    .filter(Objects::nonNull)
                    .toArray(Integer[]::new);
        }
        return null;
    }

    private Integer coerceInteger(Object o) {
        if (o instanceof Number n) {
            return n.intValue();
        }
        if (o instanceof String s) {
            try {
                return Integer.parseInt(s);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Set<String> toStringSet(Object value) {
        String[] values = toStringArray(value);
        return values != null ? new HashSet<>(Arrays.asList(values)) : new HashSet<>();
    }

    private Map<String, Long> toFrequencyMap(Object value) {
        if (value == null) {
            return new HashMap<>();
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Long> result = new HashMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (e.getKey() == null) {
                    continue;
                }
                Long v = null;
                if (e.getValue() instanceof Number n) {
                    v = n.longValue();
                } else if (e.getValue() instanceof String s) {
                    try {
                        v = Long.parseLong(s);
                    } catch (NumberFormatException ignored) {
                    }
                }
                if (v != null) {
                    result.put(String.valueOf(e.getKey()), v);
                }
            }
            return result;
        }
        return new HashMap<>();
    }
}
