package io.contexa.contexacore.verification.runtime;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

public final class OfficialVerificationPerMetricPerUserRunRepository<R> {

    private final Map<String, Map<String, CopyOnWriteArrayList<R>>> runsByMetricAndUser = new ConcurrentHashMap<>();
    private final Function<R, String> runIdExtractor;
    private final Comparator<R> sortOrder;

    public OfficialVerificationPerMetricPerUserRunRepository(Function<R, String> runIdExtractor, Comparator<R> sortOrder) {
        this.runIdExtractor = runIdExtractor;
        this.sortOrder = sortOrder;
    }

    public synchronized void add(String metricCode, String userId, R run) {
        runsByMetricAndUser
                .computeIfAbsent(metricCode, ignored -> new ConcurrentHashMap<>())
                .computeIfAbsent(userId, ignored -> new CopyOnWriteArrayList<>())
                .add(run);
    }

    public synchronized List<R> list(String metricCode, String userId) {
        return runsByMetricAndUser
                .getOrDefault(metricCode, Map.of())
                .getOrDefault(userId, new CopyOnWriteArrayList<>())
                .stream()
                .sorted(sortOrder)
                .toList();
    }

    public synchronized R find(String metricCode, String userId, String runId, String notFoundMessage) {
        return list(metricCode, userId).stream()
                .filter(item -> runIdExtractor.apply(item).equals(runId))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(notFoundMessage));
    }

    public synchronized int size(String metricCode, String userId) {
        return runsByMetricAndUser
                .getOrDefault(metricCode, Map.of())
                .getOrDefault(userId, new CopyOnWriteArrayList<>())
                .size();
    }
}