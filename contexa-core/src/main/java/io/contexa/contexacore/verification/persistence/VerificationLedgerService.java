package io.contexa.contexacore.verification.persistence;

import io.contexa.contexacore.verification.runtime.OfficialVerificationRunRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class VerificationLedgerService {

    private final OfficialVerificationRunStore runStore;

    public VerificationLedgerService(OfficialVerificationRunStore runStore) {
        this.runStore = runStore;
    }

    public List<OfficialVerificationRunView> findMetricRunsByPackageId(String packageId) {
        return runStore == null ? List.of() : runStore.listDetailedByPackageId(packageId);
    }

    public OfficialVerificationRunRecord findRunRecord(String userId, String runId) {
        if (runStore == null) {
            return null;
        }
        if (userId != null && !userId.isBlank()) {
            return runStore.find(userId, runId);
        }
        OfficialVerificationRunView detailed = runStore.findDetailedByRunId(runId);
        if (detailed == null) {
            return null;
        }
        return new OfficialVerificationRunRecord(
                detailed.runId(),
                detailed.endpointKey(),
                "official-sealed-evidence",
                detailed.state(),
                textFact(detailed.rawEvidence(), "requestedBy"),
                parseInstant(detailed.startedAt()),
                parseInstant(detailed.startedAt()),
                parseInstant(detailed.completedAt()),
                detailed.message(),
                stringEvidenceReferences(detailed.rawEvidence()));
    }

    public OfficialVerificationRunView findMetricRun(String userId, String metricCode, String runId) {
        if (runStore == null) {
            return null;
        }
        if (userId != null && !userId.isBlank()) {
            return runStore.findDetailed(userId, metricCode, runId);
        }
        return runStore.findDetailedByRunId(runId);
    }

    private static Instant parseInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static String textFact(Map<String, Object> rawEvidence, String key) {
        if (rawEvidence == null || key == null) {
            return null;
        }
        Object value = rawEvidence.get(key);
        return value == null ? null : String.valueOf(value);
    }

    private static Map<String, String> stringEvidenceReferences(Map<String, Object> rawEvidence) {
        if (rawEvidence == null || rawEvidence.isEmpty()) {
            return Map.of();
        }
        Map<String, String> references = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : rawEvidence.entrySet()) {
            if (entry.getKey() != null && entry.getValue() != null) {
                references.put(entry.getKey(), String.valueOf(entry.getValue()));
            }
        }
        return references;
    }
}
