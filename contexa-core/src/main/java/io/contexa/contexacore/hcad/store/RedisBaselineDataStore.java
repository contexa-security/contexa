package io.contexa.contexacore.hcad.store;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

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
            Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

            if (data.isEmpty()) {
                return null;
            }

            return BaselineVector.builder()
                    .userId(userId)
                    .avgTrustScore(parseDouble(data.get("avgTrustScore")))
                    .avgRequestCount(parseLong(data.get("avgRequestCount")))
                    .updateCount(parseLong(data.get("updateCount")))
                    .lastUpdated(parseInstant(data.get("lastUpdated")))
                    .normalIpRanges(parseStringArray(data.get("normalIpRanges")))
                    .normalAccessHours(parseIntegerArray(data.get("normalAccessHours")))
                    .normalAccessDays(parseIntegerArray(data.get("normalAccessDays")))
                    .frequentPaths(parseStringArray(data.get("frequentPaths")))
                    .normalUserAgents(parseStringArray(data.get("normalUserAgents")))
                    .normalOperatingSystems(parseStringArray(data.get("normalOperatingSystems")))
                    .elementFrequencies(parseFrequencyMap(data.get("elementFrequencies")))
                    .build();

        } catch (Exception e) {
            log.error("[BaselineDataStore] User baseline retrieval failed: userId={}", userId, e);
            return null;
        }
    }

    @Override
    public void saveUserBaseline(String userId, BaselineVector baseline) {
        try {
            String key = BASELINE_KEY_PREFIX + userId;
            Map<String, Object> data = new HashMap<>();
            data.put("userId", userId);
            data.put("avgTrustScore", baseline.getAvgTrustScore());
            data.put("avgRequestCount", baseline.getAvgRequestCount());
            data.put("updateCount", baseline.getUpdateCount());

            data.put("lastUpdated", baseline.getLastUpdated() != null ?
                    baseline.getLastUpdated().toString() : Instant.now().toString());

            if (baseline.getNormalIpRanges() != null && baseline.getNormalIpRanges().length > 0) {
                data.put("normalIpRanges", String.join(",", baseline.getNormalIpRanges()));
            }
            if (baseline.getNormalAccessHours() != null && baseline.getNormalAccessHours().length > 0) {
                data.put("normalAccessHours", Arrays.stream(baseline.getNormalAccessHours())
                        .map(String::valueOf)
                        .collect(Collectors.joining(",")));
            }
            if (baseline.getNormalAccessDays() != null && baseline.getNormalAccessDays().length > 0) {
                data.put("normalAccessDays", Arrays.stream(baseline.getNormalAccessDays())
                        .map(String::valueOf)
                        .collect(Collectors.joining(",")));
            }
            if (baseline.getFrequentPaths() != null && baseline.getFrequentPaths().length > 0) {
                data.put("frequentPaths", String.join(",", baseline.getFrequentPaths()));
            }
            if (baseline.getNormalUserAgents() != null && baseline.getNormalUserAgents().length > 0) {
                data.put("normalUserAgents", String.join(",", baseline.getNormalUserAgents()));
            }
            if (baseline.getNormalOperatingSystems() != null && baseline.getNormalOperatingSystems().length > 0) {
                data.put("normalOperatingSystems", String.join(",", baseline.getNormalOperatingSystems()));
            }

            String serializedFrequencies = serializeFrequencyMap(baseline.getElementFrequencies());
            if (serializedFrequencies != null) {
                data.put("elementFrequencies", serializedFrequencies);
            }

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
            Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

            if (data == null || data.isEmpty()) {
                return null;
            }

            return BaselineVector.builder()
                    .userId("org:" + organizationId)
                    .avgTrustScore(parseDouble(data.get("avgTrustScore")))
                    .avgRequestCount(parseLong(data.get("avgRequestCount")))
                    .updateCount(parseLong(data.get("updateCount")))
                    .lastUpdated(parseInstant(data.get("lastUpdated")))
                    .normalIpRanges(parseStringArray(data.get("normalIpRanges")))
                    .normalAccessHours(parseIntegerArray(data.get("normalAccessHours")))
                    .normalAccessDays(parseIntegerArray(data.get("normalAccessDays")))
                    .frequentPaths(parseStringArray(data.get("frequentPaths")))
                    .normalUserAgents(parseStringArray(data.get("normalUserAgents")))
                    .normalOperatingSystems(parseStringArray(data.get("normalOperatingSystems")))
                    .elementFrequencies(parseFrequencyMap(data.get("elementFrequencies")))
                    .build();

        } catch (Exception e) {
            log.error("[BaselineDataStore] Organization baseline retrieval failed: organizationId={}", organizationId, e);
            return null;
        }
    }

    @Override
    public void saveOrganizationBaseline(String organizationId, BaselineVector baseline) {
        try {
            String key = BASELINE_KEY_PREFIX + "org:" + organizationId;
            Map<String, Object> data = new HashMap<>();
            data.put("userId", "org:" + organizationId);
            data.put("avgTrustScore", baseline.getAvgTrustScore());
            data.put("avgRequestCount", baseline.getAvgRequestCount());
            data.put("updateCount", baseline.getUpdateCount());
            data.put("lastUpdated", baseline.getLastUpdated() != null ?
                    baseline.getLastUpdated().toString() : Instant.now().toString());

            if (baseline.getNormalIpRanges() != null && baseline.getNormalIpRanges().length > 0) {
                data.put("normalIpRanges", String.join(",", baseline.getNormalIpRanges()));
            }
            if (baseline.getNormalAccessHours() != null && baseline.getNormalAccessHours().length > 0) {
                data.put("normalAccessHours", Arrays.stream(baseline.getNormalAccessHours())
                        .map(String::valueOf)
                        .collect(Collectors.joining(",")));
            }
            if (baseline.getNormalAccessDays() != null && baseline.getNormalAccessDays().length > 0) {
                data.put("normalAccessDays", Arrays.stream(baseline.getNormalAccessDays())
                        .map(String::valueOf)
                        .collect(Collectors.joining(",")));
            }
            if (baseline.getFrequentPaths() != null && baseline.getFrequentPaths().length > 0) {
                data.put("frequentPaths", String.join(",", baseline.getFrequentPaths()));
            }
            if (baseline.getNormalUserAgents() != null && baseline.getNormalUserAgents().length > 0) {
                data.put("normalUserAgents", String.join(",", baseline.getNormalUserAgents()));
            }
            if (baseline.getNormalOperatingSystems() != null && baseline.getNormalOperatingSystems().length > 0) {
                data.put("normalOperatingSystems", String.join(",", baseline.getNormalOperatingSystems()));
            }

            String serializedFrequencies = serializeFrequencyMap(baseline.getElementFrequencies());
            if (serializedFrequencies != null) {
                data.put("elementFrequencies", serializedFrequencies);
            }

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
            if (organizationIds != null && !organizationIds.isEmpty()) {
                for (Object organizationId : organizationIds) {
                    if (organizationId != null) {
                        BaselineVector baseline = getOrganizationBaseline(String.valueOf(organizationId));
                        if (baseline != null) {
                            baselines.put(String.valueOf(organizationId), baseline);
                        }
                    }
                }
                return baselines.values();
            }
            Set<String> keys = redisTemplate.keys(BASELINE_KEY_PREFIX + "org:*");
            if (keys == null || keys.isEmpty()) {
                return List.of();
            }
            for (String key : keys) {
                if (key.endsWith(":index")) {
                    continue;
                }
                String organizationId = key.substring((BASELINE_KEY_PREFIX + "org:").length());
                BaselineVector baseline = getOrganizationBaseline(organizationId);
                if (baseline != null) {
                    baselines.put(organizationId, baseline);
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
            if (size != null && size > 0) {
                return size;
            }
            Set<String> keys = redisTemplate.keys(BASELINE_KEY_PREFIX + "*");
            if (keys == null || keys.isEmpty()) {
                return 0L;
            }
            return keys.stream()
                    .filter(key -> !key.contains("org:"))
                    .filter(key -> !key.endsWith(":index"))
                    .count();
        } catch (Exception e) {
            log.error("[BaselineDataStore] User baseline count failed", e);
            return 0L;
        }
    }

    private double parseDouble(Object value) {
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        if (value instanceof String) {
            try {
                return Double.parseDouble((String) value);
            } catch (NumberFormatException e) {
                return 0.0;
            }
        }
        return 0.0;
    }

    private long parseLong(Object value) {
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        if (value instanceof String) {
            try {
                return Long.parseLong((String) value);
            } catch (NumberFormatException e) {
                return 0L;
            }
        }
        return 0L;
    }

    private Instant parseInstant(Object value) {
        if (value instanceof String) {
            try {
                return Instant.parse((String) value);
            } catch (Exception e) {
                return Instant.now();
            }
        }
        return Instant.now();
    }

    private String[] parseStringArray(Object value) {
        if (value instanceof String && !((String) value).isEmpty()) {
            String[] parts = ((String) value).split(",");
            return Arrays.stream(parts)
                    .filter(s -> !s.isEmpty())
                    .toArray(String[]::new);
        }
        return null;
    }

    private Integer[] parseIntegerArray(Object value) {
        if (value instanceof String && !((String) value).isEmpty()) {
            try {
                return Arrays.stream(((String) value).split(","))
                        .filter(s -> !s.isEmpty())
                        .map(String::trim)
                        .map(Integer::parseInt)
                        .toArray(Integer[]::new);
            } catch (NumberFormatException e) {
                log.error("[BaselineDataStore] Integer array parsing failed: {}", value);
                return null;
            }
        }
        return null;
    }

    private Map<String, Long> parseFrequencyMap(Object value) {
        if (value instanceof String && !((String) value).isEmpty()) {
            Map<String, Long> map = new HashMap<>();
            for (String entry : ((String) value).split(",")) {
                int eqIdx = entry.lastIndexOf('=');
                if (eqIdx > 0 && eqIdx < entry.length() - 1) {
                    try {
                        map.put(entry.substring(0, eqIdx), Long.parseLong(entry.substring(eqIdx + 1)));
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
            return map;
        }
        return new HashMap<>();
    }

    private String serializeFrequencyMap(Map<String, Long> frequencies) {
        if (frequencies == null || frequencies.isEmpty()) {
            return null;
        }
        return frequencies.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining(","));
    }
}
