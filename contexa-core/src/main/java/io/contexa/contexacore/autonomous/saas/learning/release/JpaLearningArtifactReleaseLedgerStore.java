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
package io.contexa.contexacore.autonomous.saas.learning.release;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.domain.entity.LearningArtifactReleaseLedgerRecord;
import io.contexa.contexacore.repository.LearningArtifactReleaseLedgerRecordRepository;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.data.domain.PageRequest;

/**
 * JPA-backed ledger store for learning artifact release history.
 */
public class JpaLearningArtifactReleaseLedgerStore implements LearningArtifactReleaseLedgerStore {

    private final LearningArtifactReleaseLedgerRecordRepository repository;

    public JpaLearningArtifactReleaseLedgerStore(LearningArtifactReleaseLedgerRecordRepository repository) {
        this.repository = repository;
    }

    @Override
    public LearningArtifactReleaseLedgerEntry save(LearningArtifactReleaseLedgerEntry entry) {
        return toEntry(repository.save(toRecord(entry)));
    }

    @Override
    public Optional<LearningArtifactReleaseLedgerEntry> findLatest(String tenantId, String artifactType, String artifactKey) {
        return repository.findFirstByTenantIdAndArtifactTypeAndArtifactKeyOrderByCreatedAtDescIdDesc(
                        tenantId,
                        artifactType,
                        artifactKey)
                .map(this::toEntry);
    }

    @Override
    public List<LearningArtifactReleaseLedgerEntry> findRecent(String tenantId, String artifactType, String artifactKey, int limit) {
        if (limit <= 0) {
            return List.of();
        }
        return repository.findByTenantIdAndArtifactTypeAndArtifactKeyOrderByCreatedAtDescIdDesc(
                        tenantId,
                        artifactType,
                        artifactKey,
                        PageRequest.of(0, limit))
                .stream()
                .map(this::toEntry)
                .toList();
    }

    @Override
    public List<LearningArtifactReleaseLedgerEntry> findLatestByArtifact(String artifactType, String artifactKey) {
        return repository.findByArtifactTypeAndArtifactKeyOrderByCreatedAtDescIdDesc(
                        artifactType,
                        artifactKey,
                        PageRequest.of(0, 1000))
                .stream()
                .map(this::toEntry)
                .collect(Collectors.toMap(
                        LearningArtifactReleaseLedgerEntry::tenantId,
                        entry -> entry,
                        (left, right) -> left,
                        LinkedHashMap::new))
                .values()
                .stream()
                .sorted(Comparator.comparing(LearningArtifactReleaseLedgerEntry::createdAt).reversed()
                        .thenComparing(LearningArtifactReleaseLedgerEntry::ledgerId, Comparator.reverseOrder()))
                .toList();
    }

    @Override
    public List<LearningArtifactReleaseLedgerEntry> findRecentByArtifact(String artifactType, String artifactKey, int limit) {
        if (limit <= 0) {
            return List.of();
        }
        return repository.findByArtifactTypeAndArtifactKeyOrderByCreatedAtDescIdDesc(
                        artifactType,
                        artifactKey,
                        PageRequest.of(0, limit))
                .stream()
                .map(this::toEntry)
                .toList();
    }

    private LearningArtifactReleaseLedgerRecord toRecord(LearningArtifactReleaseLedgerEntry entry) {
        return LearningArtifactReleaseLedgerRecord.builder()
                .ledgerId(entry.ledgerId())
                .tenantId(entry.tenantId())
                .artifactType(entry.artifactType())
                .artifactKey(entry.artifactKey())
                .artifactVersion(entry.artifactVersion())
                .eventType(entry.eventType().name())
                .releaseState(entry.releaseState().name())
                .policyState(entry.policyState())
                .actor(entry.actor())
                .reason(entry.reason())
                .canaryOutcome(entry.canaryOutcome())
                .rollbackTargetState(entry.rollbackTargetState() != null ? entry.rollbackTargetState().name() : null)
                .killSwitchActive(entry.killSwitchActive())
                .facts(entry.facts())
                .build();
    }

    private LearningArtifactReleaseLedgerEntry toEntry(LearningArtifactReleaseLedgerRecord record) {
        return new LearningArtifactReleaseLedgerEntry(
                record.getLedgerId(),
                record.getTenantId(),
                record.getArtifactType(),
                record.getArtifactKey(),
                record.getArtifactVersion(),
                LearningArtifactReleaseLedgerEventType.valueOf(record.getEventType().trim().toUpperCase(Locale.ROOT)),
                LearningArtifactReleaseState.valueOf(record.getReleaseState().trim().toUpperCase(Locale.ROOT)),
                record.getPolicyState(),
                record.getActor(),
                record.getReason(),
                record.getCanaryOutcome(),
                parseNullableReleaseState(record.getRollbackTargetState()),
                record.isKillSwitchActive(),
                castFacts(record.getFacts()),
                record.getCreatedAt());
    }

    @SuppressWarnings("unchecked")
    private List<String> castFacts(List<?> facts) {
        if (facts == null || facts.isEmpty()) {
            return List.of();
        }
        return facts.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .toList();
    }

    private LearningArtifactReleaseState parseNullableReleaseState(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return LearningArtifactReleaseState.valueOf(value.trim().toUpperCase(Locale.ROOT));
    }
}