package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

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
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RoleScopeCollectorStoreParityTest {

    @Test
    @DisplayName("collector emits the same role scope snapshot across in-memory and Redis-backed stores")
    void collector_emitsSameSnapshotAcrossStoreImplementations() {
        RoleScopeSnapshot inMemorySnapshot = replayScenario(new DefaultRoleScopeCollector(new InMemorySecurityContextDataStore()));
        RoleScopeSnapshot redisSnapshot = replayScenario(new DefaultRoleScopeCollector(redisBackedStore()));

        assertThat(redisSnapshot.getExpectedResourceFamilies()).isEqualTo(inMemorySnapshot.getExpectedResourceFamilies());
        assertThat(redisSnapshot.getExpectedActionFamilies()).isEqualTo(inMemorySnapshot.getExpectedActionFamilies());
        assertThat(redisSnapshot.getForbiddenResourceFamilies()).isEqualTo(inMemorySnapshot.getForbiddenResourceFamilies());
        assertThat(redisSnapshot.getForbiddenActionFamilies()).isEqualTo(inMemorySnapshot.getForbiddenActionFamilies());
        assertThat(redisSnapshot.getResourceFamilyDrift()).isEqualTo(inMemorySnapshot.getResourceFamilyDrift());
        assertThat(redisSnapshot.getActionFamilyDrift()).isEqualTo(inMemorySnapshot.getActionFamilyDrift());
        assertThat(redisSnapshot.getRecentPermissionChanges()).isEqualTo(inMemorySnapshot.getRecentPermissionChanges());
    }

    private RoleScopeSnapshot replayScenario(DefaultRoleScopeCollector collector) {
        collector.collect(event(LocalDateTime.of(2026, 3, 26, 9, 0), List.of("ROLE_ANALYST"), List.of("customer_data"), "READ", "REPORT", true));
        collector.collect(event(LocalDateTime.of(2026, 3, 26, 9, 15), List.of("ROLE_ANALYST"), List.of("customer_data"), "DELETE", "ACCOUNT", false));

        SecurityEvent changed = event(
                LocalDateTime.of(2026, 3, 26, 9, 20),
                List.of("ROLE_ANALYST", "ROLE_EXPORT_REVIEWER"),
                List.of("customer_data", "export"),
                "EXPORT",
                "REPORT",
                true);
        changed.addMetadata("temporaryElevation", true);
        changed.addMetadata("temporaryElevationReason", "Emergency customer export review");

        return collector.collect(changed).orElseThrow();
    }

    private SecurityEvent event(
            LocalDateTime timestamp,
            List<String> effectiveRoles,
            List<String> scopeTags,
            String actionFamily,
            String resourceFamily,
            boolean granted) {
        SecurityEvent event = SecurityEvent.builder()
                .userId("alice")
                .timestamp(timestamp)
                .build();
        event.addMetadata("tenantId", "tenant-acme");
        event.addMetadata("effectiveRoles", effectiveRoles);
        event.addMetadata("scopeTags", scopeTags);
        event.addMetadata("effectivePermissions", List.of("report.read", "report.export"));
        event.addMetadata("currentActionFamily", actionFamily);
        event.addMetadata("currentResourceFamily", resourceFamily);
        event.addMetadata("policyId", "policy-1");
        event.addMetadata("policyVersion", "2026.03");
        event.addMetadata("granted", granted);
        event.addMetadata("authorizationEffect", granted ? "ALLOW" : "DENY");
        return event;
    }

    @SuppressWarnings("unchecked")
    private SecurityContextDataStore redisBackedStore() {
        RedisTemplate<String, Object> redisTemplate = mock(RedisTemplate.class);
        ListOperations<String, Object> listOperations = mock(ListOperations.class);
        ValueOperations<String, Object> valueOperations = mock(ValueOperations.class);
        Map<String, List<Object>> lists = new ConcurrentHashMap<>();
        Map<String, Object> values = new ConcurrentHashMap<>();

        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
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
        doAnswer(invocation -> {
            values.put(invocation.getArgument(0), invocation.getArgument(1));
            return null;
        }).when(valueOperations).set(anyString(), any(), any(Duration.class));
        when(valueOperations.get(anyString())).thenAnswer(invocation -> values.get(invocation.getArgument(0)));

        return new RedisSecurityContextDataStore(redisTemplate);
    }

    private int resolveRedisIndex(long index, int size) {
        if (index < 0) {
            return (int) Math.max(0, size + index);
        }
        return (int) Math.min(index, size - 1L);
    }
}
