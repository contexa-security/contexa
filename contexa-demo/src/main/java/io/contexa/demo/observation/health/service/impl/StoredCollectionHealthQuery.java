package io.contexa.demo.observation.health.service.impl;

import io.contexa.demo.observation.health.dto.CollectionHealth;
import io.contexa.demo.observation.health.dto.CollectorSnapshot;
import io.contexa.demo.observation.health.repository.CollectorStatusRepository;
import io.contexa.demo.observation.health.service.CollectionHealthQuery;
import org.springframework.dao.DataAccessException;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class StoredCollectionHealthQuery implements CollectionHealthQuery {

    private final CollectorStatusRepository statuses;
    private final Set<String> expectedSources;

    public StoredCollectionHealthQuery(CollectorStatusRepository statuses, String role) {
        this.statuses = statuses;
        expectedSources = "contexa".equals(role) ? Set.of("HTTP", "ENGINE", "MODEL") : Set.of("HTTP");
    }

    @Override
    public CollectionHealth find(UUID instanceId) {
        if (instanceId == null) {
            return result("NOT_CAPTURED", List.of());
        }
        try {
            List<CollectorSnapshot> sources = statuses.find(instanceId);
            Set<String> captured = sources.stream().map(CollectorSnapshot::source).collect(Collectors.toSet());
            boolean recognizedProvider = expectedSources.contains("MODEL")
                    && captured.equals(Set.of("HTTP", "ENGINE", "MODEL", "PROVIDER"));
            if (!captured.equals(expectedSources) && !recognizedProvider) {
                return result("UNKNOWN", sources);
            }
            if (sources.stream().anyMatch(value -> value.missingCount() > 0)) {
                return result("GAPS_REPORTED", sources);
            }
            Instant cutoff = Instant.now().minusSeconds(30);
            boolean unknown = sources.stream().anyMatch(value -> "STOPPING".equals(value.lifecycle())
                    || ("RUNNING".equals(value.lifecycle()) && value.sampledAt().isBefore(cutoff)));
            if (unknown) {
                return result("UNKNOWN", sources);
            }
            if (sources.stream().anyMatch(value -> value.pending() + value.inFlight() > 0)) {
                return result("PENDING", sources);
            }
            return result("NO_GAPS_REPORTED", sources);
        } catch (DataAccessException unavailable) {
            return result("UNAVAILABLE", List.of());
        }
    }

    private CollectionHealth result(String state, List<CollectorSnapshot> sources) {
        return new CollectionHealth(state, "COLLECTOR_INSTANCE_NOT_REQUEST_COMPLETENESS", sources);
    }
}
