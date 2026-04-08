package io.contexa.contexacore.autonomous.saas.learning.release;

import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-memory release ledger storage used as the default implementation.
 */
@Component
public class InMemoryLearningArtifactReleaseLedgerStore implements LearningArtifactReleaseLedgerStore {

    private final Map<String, CopyOnWriteArrayList<LearningArtifactReleaseLedgerEntry>> entries = new ConcurrentHashMap<>();

    @Override
    public LearningArtifactReleaseLedgerEntry save(LearningArtifactReleaseLedgerEntry entry) {
        entries.computeIfAbsent(key(entry.tenantId(), entry.artifactType(), entry.artifactKey()), ignored -> new CopyOnWriteArrayList<>())
                .add(entry);
        return entry;
    }

    @Override
    public Optional<LearningArtifactReleaseLedgerEntry> findLatest(String tenantId, String artifactType, String artifactKey) {
        return findRecent(tenantId, artifactType, artifactKey, 1).stream().findFirst();
    }

    @Override
    public List<LearningArtifactReleaseLedgerEntry> findRecent(String tenantId, String artifactType, String artifactKey, int limit) {
        int safeLimit = Math.max(limit, 0);
        return entries.getOrDefault(key(tenantId, artifactType, artifactKey), new CopyOnWriteArrayList<>())
                .stream()
                .sorted(Comparator.comparing(LearningArtifactReleaseLedgerEntry::createdAt).reversed()
                        .thenComparing(LearningArtifactReleaseLedgerEntry::ledgerId, Comparator.reverseOrder()))
                .limit(safeLimit)
                .toList();
    }

    @Override
    public List<LearningArtifactReleaseLedgerEntry> findLatestByArtifact(String artifactType, String artifactKey) {
        return entries.values().stream()
                .map(list -> list.stream()
                        .filter(entry -> matches(entry, artifactType, artifactKey))
                        .max(Comparator.comparing(LearningArtifactReleaseLedgerEntry::createdAt)
                                .thenComparing(LearningArtifactReleaseLedgerEntry::ledgerId)))
                .flatMap(Optional::stream)
                .sorted(Comparator.comparing(LearningArtifactReleaseLedgerEntry::createdAt).reversed()
                        .thenComparing(LearningArtifactReleaseLedgerEntry::ledgerId, Comparator.reverseOrder()))
                .toList();
    }

    @Override
    public List<LearningArtifactReleaseLedgerEntry> findRecentByArtifact(String artifactType, String artifactKey, int limit) {
        int safeLimit = Math.max(limit, 0);
        return entries.values().stream()
                .flatMap(List::stream)
                .filter(entry -> matches(entry, artifactType, artifactKey))
                .sorted(Comparator.comparing(LearningArtifactReleaseLedgerEntry::createdAt).reversed()
                        .thenComparing(LearningArtifactReleaseLedgerEntry::ledgerId, Comparator.reverseOrder()))
                .limit(safeLimit)
                .toList();
    }

    private boolean matches(LearningArtifactReleaseLedgerEntry entry, String artifactType, String artifactKey) {
        return entry.artifactType().equals(artifactType) && entry.artifactKey().equals(artifactKey);
    }

    private String key(String tenantId, String artifactType, String artifactKey) {
        return tenantId + "|" + artifactType + "|" + artifactKey;
    }
}