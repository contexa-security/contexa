package io.contexa.contexacore.autonomous.saas.learning.registry;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseLedgerEventType;
import io.contexa.contexacore.domain.entity.LearningArtifactRegistryRecord;
import io.contexa.contexacore.repository.LearningArtifactRegistryRecordRepository;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * JPA-backed registry store for the latest learning artifact state.
 */
public class JpaLearningArtifactRegistryStore implements LearningArtifactRegistryStore {

    private final LearningArtifactRegistryRecordRepository repository;

    public JpaLearningArtifactRegistryStore(LearningArtifactRegistryRecordRepository repository) {
        this.repository = repository;
    }

    @Override
    public LearningArtifactRegistryEntry save(LearningArtifactRegistryEntry entry) {
        LearningArtifactRegistryRecord record = repository.findFirstByTenantIdAndArtifactTypeAndArtifactKeyOrderByUpdatedAtDesc(
                        entry.tenantId(),
                        entry.artifactType(),
                        entry.artifactKey())
                .orElseGet(LearningArtifactRegistryRecord::new);
        record.setTenantId(entry.tenantId());
        record.setArtifactType(entry.artifactType());
        record.setArtifactKey(entry.artifactKey());
        record.setArtifactVersion(entry.artifactVersion());
        record.setReleaseState(entry.releaseState().name());
        record.setPolicyState(entry.policyState());
        record.setLatestEventType(entry.latestEventType().name());
        record.setKillSwitchActive(entry.killSwitchActive());
        record.setRuntimeEligible(entry.runtimeEligible());
        record.setRuntimeSuppressed(entry.runtimeSuppressed());
        record.setActor(entry.actor());
        record.setReason(entry.reason());
        record.setCanaryOutcome(entry.canaryOutcome());
        record.setRollbackTargetState(entry.rollbackTargetState() != null ? entry.rollbackTargetState().name() : null);
        record.setFacts(entry.facts());
        record.setFirstRegisteredAt(entry.firstRegisteredAt());
        record.setLastLedgerAt(entry.lastLedgerAt());
        return toEntry(repository.save(record));
    }

    @Override
    public Optional<LearningArtifactRegistryEntry> findCurrent(String tenantId, String artifactType, String artifactKey) {
        return repository.findFirstByTenantIdAndArtifactTypeAndArtifactKeyOrderByUpdatedAtDesc(tenantId, artifactType, artifactKey)
                .map(this::toEntry);
    }

    @Override
    public List<LearningArtifactRegistryEntry> findCurrentByArtifact(String artifactType, String artifactKey) {
        return repository.findByArtifactTypeAndArtifactKeyOrderByUpdatedAtDesc(artifactType, artifactKey).stream()
                .map(this::toEntry)
                .toList();
    }

    @Override
    public List<LearningArtifactRegistryEntry> findCurrentByTenant(String tenantId) {
        return repository.findByTenantIdOrderByUpdatedAtDesc(tenantId).stream()
                .map(this::toEntry)
                .toList();
    }

    private LearningArtifactRegistryEntry toEntry(LearningArtifactRegistryRecord record) {
        return new LearningArtifactRegistryEntry(
                record.getTenantId(),
                record.getArtifactType(),
                record.getArtifactKey(),
                record.getArtifactVersion(),
                parseReleaseState(record.getReleaseState()),
                record.getPolicyState(),
                LearningArtifactReleaseLedgerEventType.valueOf(record.getLatestEventType().trim().toUpperCase(Locale.ROOT)),
                record.isKillSwitchActive(),
                record.isRuntimeEligible(),
                record.isRuntimeSuppressed(),
                record.getActor(),
                record.getReason(),
                record.getCanaryOutcome(),
                parseNullableReleaseState(record.getRollbackTargetState()),
                record.getFacts(),
                record.getFirstRegisteredAt(),
                record.getLastLedgerAt(),
                record.getUpdatedAt());
    }

    private LearningArtifactReleaseState parseReleaseState(String value) {
        LearningArtifactReleaseState parsed = parseNullableReleaseState(value);
        return parsed != null ? parsed : LearningArtifactReleaseState.COLLECTING;
    }

    private LearningArtifactReleaseState parseNullableReleaseState(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return LearningArtifactReleaseState.valueOf(value.trim().toUpperCase(Locale.ROOT));
    }
}