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
package io.contexa.contexacore.hcad.store;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
public class RedisBaselineDataStore implements BaselineDataStore {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String BASELINE_KEY_PREFIX = "security:hcad:baseline:";
    private static final String USER_BASELINE_INDEX_KEY = BASELINE_KEY_PREFIX + "user:index";
    private static final String ORG_BASELINE_INDEX_KEY = BASELINE_KEY_PREFIX + "org:index";
    private static final Duration BASELINE_TTL = Duration.ofDays(30);

    @Override
    public BaselineVector getUserBaseline(String userId) {
        try {
            String key = BASELINE_KEY_PREFIX + userId;
            return loadBaselineFromHash(key, userId);
        } catch (Exception e) {
            log.error("[BaselineDataStore] User baseline retrieval failed: userId={}", userId, e);
            return null;
        }
    }

    @Override
    public void saveUserBaseline(String userId, BaselineVector baseline) {
        try {
            String key = BASELINE_KEY_PREFIX + userId;
            Map<String, Object> data = buildBaselineHash(userId, baseline);
            redisTemplate.opsForHash().putAll(key, data);
            redisTemplate.expire(key, BASELINE_TTL);
            redisTemplate.opsForSet().add(USER_BASELINE_INDEX_KEY, userId);
        } catch (Exception e) {
            log.error("[BaselineDataStore] Baseline save failed: userId={}", userId, e);
        }
    }

    @Override
    public BaselineVector getOrganizationBaseline(String organizationId) {
        try {
            String key = BASELINE_KEY_PREFIX + "org:" + organizationId;
            return loadBaselineFromHash(key, "org:" + organizationId);
        } catch (Exception e) {
            log.error("[BaselineDataStore] Organization baseline retrieval failed: organizationId={}", organizationId, e);
            return null;
        }
    }

    @Override
    public void saveOrganizationBaseline(String organizationId, BaselineVector baseline) {
        try {
            String key = BASELINE_KEY_PREFIX + "org:" + organizationId;
            Map<String, Object> data = buildBaselineHash("org:" + organizationId, baseline);
            redisTemplate.opsForHash().putAll(key, data);
            redisTemplate.expire(key, BASELINE_TTL);
            redisTemplate.opsForSet().add(ORG_BASELINE_INDEX_KEY, organizationId);
        } catch (Exception e) {
            log.error("[BaselineDataStore] Organization baseline save failed: organizationId={}", organizationId, e);
        }
    }

    @Override
    public Iterable<BaselineVector> listOrganizationBaselines() {
        LinkedHashMap<String, BaselineVector> baselines = new LinkedHashMap<>();
        try {
            Set<Object> organizationIds = redisTemplate.opsForSet().members(ORG_BASELINE_INDEX_KEY);
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
                    redisTemplate.opsForSet().remove(ORG_BASELINE_INDEX_KEY, id);
                }
            }
            return baselines.values();
        } catch (Exception e) {
            log.error("[BaselineDataStore] Organization baseline listing failed", e);
            return List.of();
        }
    }

    @Override
    public long countUserBaselines() {
        try {
            Long size = redisTemplate.opsForSet().size(USER_BASELINE_INDEX_KEY);
            return size != null ? size : 0L;
        } catch (Exception e) {
            log.error("[BaselineDataStore] User baseline count failed", e);
            return 0L;
        }
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
        putIfNonEmpty(data, "normalIpBands", baseline.getNormalIpBands());
        putIfNonEmpty(data, "normalAuthenticationTypes", baseline.getNormalAuthenticationTypes());
        putIfNonEmpty(data, "frequentActionFamilies", baseline.getFrequentActionFamilies());
        putIfNonEmpty(data, "frequentResourceFamilies", baseline.getFrequentResourceFamilies());
        if (baseline.getElementFrequencies() != null && !baseline.getElementFrequencies().isEmpty()) {
            data.put("elementFrequencies", baseline.getElementFrequencies());
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
                .normalIpBands(toStringArray(data.get("normalIpBands")))
                .normalAuthenticationTypes(toStringArray(data.get("normalAuthenticationTypes")))
                .frequentActionFamilies(toStringArray(data.get("frequentActionFamilies")))
                .frequentResourceFamilies(toStringArray(data.get("frequentResourceFamilies")))
                .elementFrequencies(toFrequencyMap(data.get("elementFrequencies")))
                .build();
    }

    private static void putIfNonEmpty(Map<String, Object> data, String field, Object[] array) {
        if (array != null && array.length > 0) {
            data.put(field, new java.util.ArrayList<>(Arrays.asList(array)));
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
                    .filter(java.util.Objects::nonNull)
                    .toArray(Integer[]::new);
        }
        if (value instanceof List<?> list) {
            return list.stream()
                    .map(this::coerceInteger)
                    .filter(java.util.Objects::nonNull)
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
