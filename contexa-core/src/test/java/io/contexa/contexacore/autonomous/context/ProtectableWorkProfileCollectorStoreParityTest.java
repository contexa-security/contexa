package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ProtectableWorkProfileCollectorStoreParityTest {

    @Test
    @DisplayName("collector emits the same work profile snapshot across in-memory and Redis-backed stores")
    void collector_emitsSameSnapshotAcrossStoreImplementations() {
        ProtectableWorkProfileSnapshot inMemorySnapshot = replayScenario(
                new DefaultProtectableWorkProfileCollector(new InMemorySecurityContextDataStore()));
        ProtectableWorkProfileSnapshot redisSnapshot = replayScenario(
                new DefaultProtectableWorkProfileCollector(redisBackedStore()));

        assertThat(redisSnapshot.getObservationCount()).isEqualTo(inMemorySnapshot.getObservationCount());
        assertThat(redisSnapshot.getWindowDays()).isEqualTo(inMemorySnapshot.getWindowDays());
        assertThat(redisSnapshot.getFrequentProtectableResources()).isEqualTo(inMemorySnapshot.getFrequentProtectableResources());
        assertThat(redisSnapshot.getFrequentActionFamilies()).isEqualTo(inMemorySnapshot.getFrequentActionFamilies());
        assertThat(redisSnapshot.getNormalAccessHours()).isEqualTo(inMemorySnapshot.getNormalAccessHours());
        assertThat(redisSnapshot.getNormalAccessDays()).isEqualTo(inMemorySnapshot.getNormalAccessDays());
        assertThat(redisSnapshot.getNormalRequestRate()).isEqualTo(inMemorySnapshot.getNormalRequestRate());
        assertThat(redisSnapshot.getProtectableInvocationDensity()).isEqualTo(inMemorySnapshot.getProtectableInvocationDensity());
        assertThat(redisSnapshot.getProtectableResourceHeatmap()).isEqualTo(inMemorySnapshot.getProtectableResourceHeatmap());
        assertThat(redisSnapshot.getFrequentSensitiveResourceCategories()).isEqualTo(inMemorySnapshot.getFrequentSensitiveResourceCategories());
        assertThat(redisSnapshot.getNormalReadWriteExportRatio()).isEqualTo(inMemorySnapshot.getNormalReadWriteExportRatio());
        assertThat(redisSnapshot.getSummary()).isEqualTo(inMemorySnapshot.getSummary());
    }

    private ProtectableWorkProfileSnapshot replayScenario(DefaultProtectableWorkProfileCollector collector) {
        collector.collect(event(
                LocalDateTime.of(2026, 3, 25, 9, 0),
                "/dashboard",
                "GET",
                "READ",
                "DASHBOARD",
                "LOW",
                false,
                true));
        collector.collect(event(
                LocalDateTime.of(2026, 3, 25, 10, 0),
                "/api/customer/list",
                "GET",
                "READ",
                "REPORT",
                "HIGH",
                true,
                true));

        return collector.collect(event(
                        LocalDateTime.of(2026, 3, 25, 11, 0),
                        "/api/customer/export",
                        "POST",
                        "EXPORT",
                        "REPORT",
                        "HIGH",
                        true,
                        true))
                .orElseThrow();
    }

    private SecurityEvent event(
            LocalDateTime timestamp,
            String requestPath,
            String httpMethod,
            String actionFamily,
            String resourceFamily,
            String sensitivity,
            boolean protectable,
            boolean granted) {
        SecurityEvent event = SecurityEvent.builder()
                .userId("alice")
                .timestamp(timestamp)
                .description(httpMethod + " " + requestPath)
                .build();
        event.addMetadata("tenantId", "tenant-acme");
        event.addMetadata("requestPath", requestPath);
        event.addMetadata("httpMethod", httpMethod);
        event.addMetadata("actionFamily", actionFamily);
        event.addMetadata("currentResourceFamily", resourceFamily);
        event.addMetadata("resourceSensitivity", sensitivity);
        event.addMetadata("isProtectable", protectable);
        event.addMetadata("granted", granted);
        if (protectable) {
            event.addMetadata("className", "io.contexa.CustomerController");
            event.addMetadata("methodName", "handle");
        }
        return event;
    }

    @SuppressWarnings("unchecked")
    private SecurityContextDataStore redisBackedStore() {
        RedisTemplate<String, Object> redisTemplate = mock(RedisTemplate.class);
        ListOperations<String, Object> listOperations = mock(ListOperations.class);
        Map<String, List<Object>> lists = new ConcurrentHashMap<>();

        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(redisTemplate.expire(anyString(), any(Duration.class))).thenReturn(true);

        when(listOperations.rightPush(anyString(), any())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            Object value = invocation.getArgument(1);
            List<Object> list = lists.computeIfAbsent(key, ignored -> new ArrayList<>());
            list.add(value);
            return (long) list.size();
        });
        when(listOperations.size(anyString())).thenAnswer(invocation -> {
            List<Object> list = lists.get(invocation.getArgument(0));
            return list == null ? 0L : (long) list.size();
        });
        when(listOperations.leftPop(anyString())).thenAnswer(invocation -> {
            List<Object> list = lists.get(invocation.getArgument(0));
            if (list == null || list.isEmpty()) {
                return null;
            }
            return list.remove(0);
        });
        when(listOperations.range(anyString(), anyLong(), anyLong())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            long start = invocation.getArgument(1);
            long end = invocation.getArgument(2);
            List<Object> list = lists.get(key);
            if (list == null || list.isEmpty()) {
                return List.of();
            }
            int resolvedStart = resolveRedisIndex(start, list.size());
            int resolvedEnd = resolveRedisIndex(end, list.size());
            resolvedStart = Math.max(0, resolvedStart);
            resolvedEnd = Math.min(list.size() - 1, resolvedEnd);
            if (resolvedStart > resolvedEnd) {
                return List.of();
            }
            return new ArrayList<>(list.subList(resolvedStart, resolvedEnd + 1));
        });

        return new RedisSecurityContextDataStore(redisTemplate);
    }

    private int resolveRedisIndex(long index, int size) {
        if (index < 0) {
            return (int) Math.max(0, size + index);
        }
        return (int) Math.min(index, size - 1L);
    }
}
