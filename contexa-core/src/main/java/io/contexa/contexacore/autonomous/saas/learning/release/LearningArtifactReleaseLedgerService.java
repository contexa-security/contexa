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
import io.contexa.contexacore.autonomous.saas.learning.registry.LearningArtifactRegistryEntry;
import io.contexa.contexacore.autonomous.saas.learning.registry.LearningArtifactRegistryService;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Records and queries learning artifact release ledger history.
 */
@Service
public class LearningArtifactReleaseLedgerService {

    private final LearningArtifactReleaseLedgerStore store;
    private final LearningArtifactRegistryService registryService;

    public LearningArtifactReleaseLedgerService(LearningArtifactReleaseLedgerStore store) {
        this(store, null);
    }

    public LearningArtifactReleaseLedgerService(
            LearningArtifactReleaseLedgerStore store,
            LearningArtifactRegistryService registryService) {
        this.store = store;
        this.registryService = registryService;
    }

    public LearningArtifactReleaseLedgerEntry recordArtifactCreated(
            String tenantId,
            String artifactType,
            String artifactKey,
            String artifactVersion,
            String actor,
            String reason,
            LearningArtifactReleaseState releaseState,
            List<String> facts) {
        return recordEvent(
                tenantId,
                artifactType,
                artifactKey,
                artifactVersion,
                LearningArtifactReleaseLedgerEventType.ARTIFACT_CREATED,
                releaseState,
                releaseState != null ? releaseState.name() : LearningArtifactReleaseState.COLLECTING.name(),
                actor,
                normalizeReason(reason, "Learning artifact was created and registered."),
                null,
                null,
                false,
                facts);
    }

    public LearningArtifactReleaseLedgerEntry recordCanaryResult(
            String tenantId,
            String artifactType,
            String artifactKey,
            String artifactVersion,
            String actor,
            String reason,
            LearningArtifactReleaseState releaseState,
            String policyState,
            String canaryOutcome,
            List<String> facts) {
        if (!StringUtils.hasText(canaryOutcome)) {
            throw new IllegalArgumentException("canaryOutcome is required");
        }
        return recordEvent(
                tenantId,
                artifactType,
                artifactKey,
                artifactVersion,
                LearningArtifactReleaseLedgerEventType.CANARY_RESULT_RECORDED,
                releaseState,
                policyState,
                actor,
                normalizeReason(reason, "Canary result was recorded for the learning artifact."),
                canaryOutcome,
                null,
                false,
                facts);
    }

    public LearningArtifactReleaseLedgerEntry recordRollback(
            String tenantId,
            String artifactType,
            String artifactKey,
            String artifactVersion,
            String actor,
            String reason,
            LearningArtifactReleaseState releaseState,
            LearningArtifactReleaseState rollbackTargetState,
            List<String> facts) {
        if (rollbackTargetState == null) {
            throw new IllegalArgumentException("rollbackTargetState is required");
        }
        return recordEvent(
                tenantId,
                artifactType,
                artifactKey,
                artifactVersion,
                LearningArtifactReleaseLedgerEventType.ROLLBACK_RECORDED,
                releaseState,
                releaseState != null ? releaseState.name() : null,
                actor,
                normalizeReason(reason, "Rollback was recorded for the learning artifact."),
                null,
                rollbackTargetState,
                false,
                facts);
    }

    public LearningArtifactReleaseLedgerEntry recordWithdrawn(
            String tenantId,
            String artifactType,
            String artifactKey,
            String artifactVersion,
            String actor,
            String withdrawnReason,
            List<String> facts) {
        return recordEvent(
                tenantId,
                artifactType,
                artifactKey,
                artifactVersion,
                LearningArtifactReleaseLedgerEventType.WITHDRAWN,
                LearningArtifactReleaseState.WITHDRAWN,
                LearningArtifactReleaseState.WITHDRAWN.name(),
                actor,
                normalizeReason(withdrawnReason, "Learning artifact was withdrawn from runtime use."),
                null,
                null,
                false,
                facts);
    }

    public LearningArtifactReleaseLedgerEntry recordKillSwitchActivated(
            String tenantId,
            String artifactType,
            String artifactKey,
            String artifactVersion,
            String actor,
            String reason,
            List<String> facts) {
        return recordEvent(
                tenantId,
                artifactType,
                artifactKey,
                artifactVersion,
                LearningArtifactReleaseLedgerEventType.KILL_SWITCH_ACTIVATED,
                LearningArtifactReleaseState.KILL_SWITCH_ACTIVE,
                LearningArtifactReleaseState.KILL_SWITCH_ACTIVE.name(),
                actor,
                normalizeReason(reason, "Tenant kill switch was activated for the learning artifact."),
                null,
                null,
                true,
                facts);
    }

    public LearningArtifactReleaseLedgerEntry recordKillSwitchCleared(
            String tenantId,
            String artifactType,
            String artifactKey,
            String artifactVersion,
            String actor,
            String reason,
            LearningArtifactReleaseState releaseState,
            String policyState,
            List<String> facts) {
        return recordEvent(
                tenantId,
                artifactType,
                artifactKey,
                artifactVersion,
                LearningArtifactReleaseLedgerEventType.KILL_SWITCH_CLEARED,
                releaseState,
                policyState,
                actor,
                normalizeReason(reason, "Tenant kill switch was cleared for the learning artifact."),
                null,
                null,
                false,
                facts);
    }

    public Optional<LearningArtifactReleaseLedgerEntry> latest(String tenantId, String artifactType, String artifactKey) {
        validateRequired(tenantId, "tenantId");
        validateRequired(artifactType, "artifactType");
        validateRequired(artifactKey, "artifactKey");
        return store.findLatest(tenantId.trim(), artifactType.trim(), artifactKey.trim());
    }

    public List<LearningArtifactReleaseLedgerEntry> history(String tenantId, String artifactType, String artifactKey, int limit) {
        validateRequired(tenantId, "tenantId");
        validateRequired(artifactType, "artifactType");
        validateRequired(artifactKey, "artifactKey");
        return store.findRecent(tenantId.trim(), artifactType.trim(), artifactKey.trim(), Math.max(limit, 0));
    }

    public List<LearningArtifactReleaseLedgerEntry> latestByArtifact(String artifactType, String artifactKey) {
        validateRequired(artifactType, "artifactType");
        validateRequired(artifactKey, "artifactKey");
        return store.findLatestByArtifact(artifactType.trim(), artifactKey.trim());
    }

    public List<LearningArtifactReleaseLedgerEntry> artifactHistory(String artifactType, String artifactKey, int limit) {
        validateRequired(artifactType, "artifactType");
        validateRequired(artifactKey, "artifactKey");
        return store.findRecentByArtifact(artifactType.trim(), artifactKey.trim(), Math.max(limit, 0));
    }

    public long countAdoptedTenants(String artifactType, String artifactKey) {
        if (registryService != null) {
            return registryService.currentByArtifact(artifactType, artifactKey).stream()
                    .filter(LearningArtifactRegistryEntry::runtimeEligible)
                    .count();
        }
        return latestByArtifact(artifactType, artifactKey).stream()
                .filter(this::isRuntimeAdopted)
                .count();
    }

    public long countRollbacks(String artifactType, String artifactKey) {
        return artifactHistory(artifactType, artifactKey, Integer.MAX_VALUE).stream()
                .filter(entry -> entry.eventType() == LearningArtifactReleaseLedgerEventType.ROLLBACK_RECORDED)
                .count();
    }

    private boolean isRuntimeAdopted(LearningArtifactReleaseLedgerEntry entry) {
        return entry != null
                && entry.releaseState() == LearningArtifactReleaseState.PROMOTED
                && !entry.killSwitchActive();
    }

    private LearningArtifactReleaseLedgerEntry recordEvent(
            String tenantId,
            String artifactType,
            String artifactKey,
            String artifactVersion,
            LearningArtifactReleaseLedgerEventType eventType,
            LearningArtifactReleaseState releaseState,
            String policyState,
            String actor,
            String reason,
            String canaryOutcome,
            LearningArtifactReleaseState rollbackTargetState,
            boolean killSwitchActive,
            List<String> facts) {
        validateRequired(tenantId, "tenantId");
        validateRequired(artifactType, "artifactType");
        validateRequired(artifactKey, "artifactKey");
        validateRequired(actor, "actor");
        LearningArtifactReleaseLedgerEntry entry = new LearningArtifactReleaseLedgerEntry(
                UUID.randomUUID().toString(),
                tenantId.trim(),
                artifactType.trim(),
                artifactKey.trim(),
                artifactVersion,
                eventType,
                releaseState,
                policyState,
                actor.trim(),
                reason,
                canaryOutcome,
                rollbackTargetState,
                killSwitchActive,
                facts,
                LocalDateTime.now());
        LearningArtifactReleaseLedgerEntry saved = store.save(entry);
        if (registryService != null) {
            registryService.syncFromLedger(saved);
        }
        return saved;
    }

    private void validateRequired(String value, String fieldName) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
    }

    private String normalizeReason(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }
}