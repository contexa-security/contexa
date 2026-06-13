package io.contexa.contexacore.verification.runtime;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class OfficialVerificationRunStore {

    private final Map<String, CopyOnWriteArrayList<OfficialVerificationRunRecord>> runsByUser = new ConcurrentHashMap<>();
    private final Map<String, Map<String, OfficialVerificationRunRecord>> runsByRequestId = new ConcurrentHashMap<>();
    private final Map<String, CopyOnWriteArrayList<OfficialVerificationRunView>> detailedRunsByUser = new ConcurrentHashMap<>();
    private final Map<String, CopyOnWriteArrayList<OfficialVerificationRunView>> detailedRunsByPackageId = new ConcurrentHashMap<>();

    public boolean ledgerBacked() {
        return false;
    }

    public void save(String userId, OfficialVerificationRunRecord record) {
        saveInternal(userId, record);
    }

    public void saveDetailed(String userId, OfficialVerificationRunRecord record, OfficialVerificationRunView detailedView) {
        saveInternal(userId, record);
        if (detailedView != null) {
            detailedRunsByUser.computeIfAbsent(userId, ignored -> new CopyOnWriteArrayList<>()).add(detailedView);
            String packageId = record.evidenceReferences() != null ? record.evidenceReferences().get("packageId") : null;
            if (packageId != null && !packageId.isBlank()) {
                detailedRunsByPackageId.computeIfAbsent(packageId, ignored -> new CopyOnWriteArrayList<>()).add(detailedView);
            }
        }
    }

    public List<OfficialVerificationRunRecord> list(String userId) {
        return runsByUser.getOrDefault(userId, new CopyOnWriteArrayList<>()).stream()
                .sorted(Comparator.comparing(OfficialVerificationRunRecord::requestedAt).reversed())
                .toList();
    }

    public OfficialVerificationRunRecord find(String userId, String runId) {
        return list(userId).stream()
                .filter(item -> item.runId().equals(runId))
                .findFirst()
                .orElse(null);
    }

    public OfficialVerificationRunRecord findByRequestId(String userId, String requestId) {
        if (userId == null || requestId == null || requestId.isBlank()) {
            return null;
        }
        Map<String, OfficialVerificationRunRecord> runs = runsByRequestId.get(userId);
        return runs != null ? runs.get(requestId) : null;
    }

    public List<OfficialVerificationRunView> listDetailed(String userId, String metricCode) {
        return detailedRunsByUser.getOrDefault(userId, new CopyOnWriteArrayList<>()).stream()
                .filter(run -> metricCode == null || metricCode.isBlank() || metricCode.equalsIgnoreCase(run.endpointKey()))
                .toList();
    }

    public OfficialVerificationRunView findDetailed(String userId, String metricCode, String runId) {
        return listDetailed(userId, metricCode).stream()
                .filter(run -> run.runId().equals(runId))
                .findFirst()
                .orElse(null);
    }

    public List<OfficialVerificationRunView> listDetailedByPackageId(String packageId) {
        if (packageId == null || packageId.isBlank()) {
            return List.of();
        }
        return List.copyOf(detailedRunsByPackageId.getOrDefault(packageId, new CopyOnWriteArrayList<>()));
    }

    private void saveInternal(String userId, OfficialVerificationRunRecord record) {
        Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(record, "record");
        runsByUser.computeIfAbsent(userId, ignored -> new CopyOnWriteArrayList<>()).add(record);
        String requestId = record.evidenceReferences() != null ? record.evidenceReferences().get("requestId") : null;
        if (requestId != null && !requestId.isBlank()) {
            runsByRequestId.computeIfAbsent(userId, ignored -> new ConcurrentHashMap<>()).put(requestId, record);
        }
    }
}
