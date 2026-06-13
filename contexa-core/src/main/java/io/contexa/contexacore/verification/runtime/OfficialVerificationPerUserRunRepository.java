package io.contexa.contexacore.verification.runtime;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

final class OfficialVerificationPerUserRunRepository<R> {

    private final Map<String, CopyOnWriteArrayList<R>> runsByUser = new LinkedHashMap<>();
    private final Function<R, String> runIdExtractor;
    private final Comparator<R> sortOrder;

    OfficialVerificationPerUserRunRepository(Function<R, String> runIdExtractor, Comparator<R> sortOrder) {
        this.runIdExtractor = runIdExtractor;
        this.sortOrder = sortOrder;
    }

    synchronized void add(String userId, R run) {
        runsByUser.computeIfAbsent(userId, ignored -> new CopyOnWriteArrayList<>()).add(run);
    }

    synchronized List<R> list(String userId) {
        return runsByUser.getOrDefault(userId, new CopyOnWriteArrayList<>()).stream()
                .sorted(sortOrder)
                .toList();
    }

    synchronized R find(String userId, String runId, String notFoundMessage) {
        return list(userId).stream()
                .filter(item -> runIdExtractor.apply(item).equals(runId))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(notFoundMessage));
    }

    synchronized int size(String userId) {
        return runsByUser.getOrDefault(userId, new CopyOnWriteArrayList<>()).size();
    }
}