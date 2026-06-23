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
package io.contexa.contexacore.hcad.trigger.window;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class RedisHcadObservationWindowRepository implements HcadObservationWindowRepository {

    private static final DefaultRedisScript<List> OBSERVE_SCRIPT = new DefaultRedisScript<>("""
            local windowKey = KEYS[1]
            local newWindowId = ARGV[1]
            local windowTtlMs = tonumber(ARGV[2])
            local observationKeyPrefix = ARGV[3]
            local encodedObservation = ARGV[4]
            local observationTtlMs = tonumber(ARGV[5])

            local windowId = redis.call('GET', windowKey)
            local acquired = '0'
            if not windowId or windowId == '' then
              windowId = newWindowId
              redis.call('SET', windowKey, windowId, 'PX', windowTtlMs)
              acquired = '1'
            end

            local observationKey = observationKeyPrefix .. windowId
            if encodedObservation and encodedObservation ~= '' then
              redis.call('RPUSH', observationKey, encodedObservation)
              redis.call('PEXPIRE', observationKey, observationTtlMs)
            end

            local count = redis.call('LLEN', observationKey)
            local values = redis.call('LRANGE', observationKey, 0, -1)
            local result = {acquired, windowId, tostring(count)}
            for i, value in ipairs(values) do
              table.insert(result, value)
            end
            return result
            """, List.class);

    private final StringRedisTemplate stringRedisTemplate;

    public RedisHcadObservationWindowRepository(StringRedisTemplate stringRedisTemplate) {
        this.stringRedisTemplate = stringRedisTemplate;
    }

    @Override
    public HcadObservationWindowLease observe(
            String actorSessionKey,
            HcadRequestObservation observation,
            Duration coalesceWindow,
            Duration observationTtl) {
        if (!StringUtils.hasText(actorSessionKey)) {
            return new HcadObservationWindowLease(true, actorSessionKey, UUID.randomUUID().toString(), 1,
                    families(observation), paths(observation));
        }
        Duration windowTtl = positive(coalesceWindow, Duration.ofSeconds(1));
        Duration observationExpiry = positive(observationTtl, Duration.ofSeconds(60));
        String windowKey = ZeroTrustRedisKeys.hcadObservationWindow(actorSessionKey);
        String newWindowId = UUID.randomUUID().toString();
        String encoded = encode(observation);
        List<String> result = executeObserveScript(
                windowKey,
                newWindowId,
                windowTtl,
                ZeroTrustRedisKeys.hcadObservationWindowObservationsPrefix(actorSessionKey),
                encoded,
                observationExpiry);
        boolean acquired = result.size() > 0 && "1".equals(result.get(0));
        String windowId = result.size() > 1 && StringUtils.hasText(result.get(1)) ? result.get(1) : newWindowId;
        int count = result.size() > 2 ? parsePositiveInt(result.get(2), 1) : 1;
        List<String> values = result.size() > 3 ? result.subList(3, result.size()) : List.of();
        return new HcadObservationWindowLease(
                acquired,
                actorSessionKey,
                windowId,
                count,
                extract(values, 3),
                extract(values, 2));
    }

    @Override
    public Optional<HcadObservationWindowLease> snapshot(String actorSessionKey, String windowId) {
        if (!StringUtils.hasText(actorSessionKey) || !StringUtils.hasText(windowId)) {
            return Optional.empty();
        }
        String observationKey = ZeroTrustRedisKeys.hcadObservationWindowObservations(actorSessionKey, windowId);
        List<String> values = stringRedisTemplate.opsForList().range(observationKey, 0, -1);
        if (values == null || values.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new HcadObservationWindowLease(
                false,
                actorSessionKey,
                windowId,
                values.size(),
                extract(values, 3),
                extract(values, 2)));
    }

    @Override
    public boolean tryAcquireEscalation(String actorSessionKey, String windowId, String anchorSignature) {
        if (!StringUtils.hasText(actorSessionKey)
                || !StringUtils.hasText(windowId)
                || !StringUtils.hasText(anchorSignature)) {
            return false;
        }
        String deepEvaluationKey = ZeroTrustRedisKeys.hcadObservationWindowDeepEvaluation(actorSessionKey, windowId);
        if (!Boolean.TRUE.equals(stringRedisTemplate.hasKey(deepEvaluationKey))) {
            return false;
        }
        String anchorKey = ZeroTrustRedisKeys.hcadObservationWindowAnchorSignatures(actorSessionKey, windowId);
        Long added = stringRedisTemplate.opsForSet().add(anchorKey, anchorSignature);
        if (added == null || added <= 0L) {
            return false;
        }
        Duration ttl = observationTtl(actorSessionKey, windowId);
        if (ttl != null && !ttl.isZero() && !ttl.isNegative()) {
            stringRedisTemplate.expire(anchorKey, ttl);
        }
        return true;
    }

    @Override
    public void markDeepEvaluationCompleted(String actorSessionKey, String windowId, String anchorSignature) {
        if (!StringUtils.hasText(actorSessionKey) || !StringUtils.hasText(windowId)) {
            return;
        }
        String deepEvaluationKey = ZeroTrustRedisKeys.hcadObservationWindowDeepEvaluation(actorSessionKey, windowId);
        Duration ttl = observationTtl(actorSessionKey, windowId);
        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            ttl = Duration.ofSeconds(60);
        }
        stringRedisTemplate.opsForValue().set(deepEvaluationKey, "1", ttl);
        if (StringUtils.hasText(anchorSignature)) {
            String anchorKey = ZeroTrustRedisKeys.hcadObservationWindowAnchorSignatures(actorSessionKey, windowId);
            stringRedisTemplate.opsForSet().add(anchorKey, anchorSignature);
            stringRedisTemplate.expire(anchorKey, ttl);
        }
    }

    private List<String> executeObserveScript(
            String windowKey,
            String newWindowId,
            Duration windowTtl,
            String observationKeyPrefix,
            String encodedObservation,
            Duration observationTtl) {
        List<?> raw = stringRedisTemplate.execute(
                OBSERVE_SCRIPT,
                List.of(windowKey),
                newWindowId,
                Long.toString(Math.max(1L, windowTtl.toMillis())),
                observationKeyPrefix,
                StringUtils.hasText(encodedObservation) ? encodedObservation : "",
                Long.toString(Math.max(1L, observationTtl.toMillis())));
        if (raw == null || raw.isEmpty()) {
            return List.of();
        }
        List<String> result = new ArrayList<>(raw.size());
        for (Object value : raw) {
            result.add(value == null ? "" : value.toString());
        }
        return result;
    }

    private int parsePositiveInt(String value, int fallback) {
        if (!StringUtils.hasText(value)) {
            return fallback;
        }
        try {
            return Math.max(1, Integer.parseInt(value.trim()));
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private Duration positive(Duration value, Duration fallback) {
        if (value == null || value.isZero() || value.isNegative()) {
            return fallback;
        }
        return value;
    }

    private Duration observationTtl(String actorSessionKey, String windowId) {
        if (!StringUtils.hasText(actorSessionKey) || !StringUtils.hasText(windowId)) {
            return null;
        }
        Long ttlSeconds = stringRedisTemplate.getExpire(
                ZeroTrustRedisKeys.hcadObservationWindowObservations(actorSessionKey, windowId));
        if (ttlSeconds == null || ttlSeconds <= 0L) {
            return null;
        }
        return Duration.ofSeconds(ttlSeconds);
    }

    private String encode(HcadRequestObservation observation) {
        if (observation == null) {
            return null;
        }
        return safe(observation.requestId()) + "\t"
                + safe(observation.httpMethod()) + "\t"
                + safe(observation.normalizedPath()) + "\t"
                + safe(observation.resourceFamily());
    }

    private String safe(String value) {
        return value == null ? "" : value.replace('\t', ' ').trim();
    }

    private List<String> extract(List<String> values, int index) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> extracted = new LinkedHashSet<>();
        for (String value : values) {
            String[] parts = value == null ? new String[0] : value.split("\t", -1);
            if (parts.length > index && StringUtils.hasText(parts[index])) {
                extracted.add(parts[index]);
            }
        }
        return List.copyOf(extracted);
    }

    private List<String> families(HcadRequestObservation observation) {
        if (observation == null || !StringUtils.hasText(observation.resourceFamily())) {
            return List.of();
        }
        return List.of(observation.resourceFamily());
    }

    private List<String> paths(HcadRequestObservation observation) {
        if (observation == null || !StringUtils.hasText(observation.normalizedPath())) {
            return List.of();
        }
        return List.of(observation.normalizedPath());
    }
}
