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
package io.contexa.contexacore.autonomous.saas.learning.registry;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;
import io.contexa.contexacore.autonomous.saas.learning.release.LearningArtifactReleaseLedgerEntry;

import java.util.List;
import java.util.Optional;

/**
 * Maintains the canonical latest-state registry for tenant-scoped learning artifacts.
 */
public class LearningArtifactRegistryService {

    private final LearningArtifactRegistryStore store;

    public LearningArtifactRegistryService(LearningArtifactRegistryStore store) {
        this.store = store;
    }

    public LearningArtifactRegistryEntry syncFromLedger(LearningArtifactReleaseLedgerEntry ledgerEntry) {
        Optional<LearningArtifactRegistryEntry> current = store.findCurrent(
                ledgerEntry.tenantId(),
                ledgerEntry.artifactType(),
                ledgerEntry.artifactKey());
        LearningArtifactReleaseState releaseState = ledgerEntry.releaseState();
        boolean runtimeSuppressed = isSuppressingState(releaseState) || ledgerEntry.killSwitchActive();
        boolean runtimeEligible = releaseState.isRuntimeEligible() && !runtimeSuppressed;
        LearningArtifactRegistryEntry next = new LearningArtifactRegistryEntry(
                ledgerEntry.tenantId(),
                ledgerEntry.artifactType(),
                ledgerEntry.artifactKey(),
                ledgerEntry.artifactVersion(),
                releaseState,
                ledgerEntry.policyState(),
                ledgerEntry.eventType(),
                ledgerEntry.killSwitchActive(),
                runtimeEligible,
                runtimeSuppressed,
                ledgerEntry.actor(),
                ledgerEntry.reason(),
                ledgerEntry.canaryOutcome(),
                ledgerEntry.rollbackTargetState(),
                ledgerEntry.facts(),
                current.map(LearningArtifactRegistryEntry::firstRegisteredAt).orElse(ledgerEntry.createdAt()),
                ledgerEntry.createdAt(),
                ledgerEntry.createdAt());
        return store.save(next);
    }

    public Optional<LearningArtifactRegistryEntry> current(String tenantId, String artifactType, String artifactKey) {
        return store.findCurrent(tenantId.trim(), artifactType.trim(), artifactKey.trim());
    }

    public List<LearningArtifactRegistryEntry> currentByArtifact(String artifactType, String artifactKey) {
        return store.findCurrentByArtifact(artifactType.trim(), artifactKey.trim());
    }

    public List<LearningArtifactRegistryEntry> currentByTenant(String tenantId) {
        return store.findCurrentByTenant(tenantId.trim());
    }

    public boolean isRuntimeSuppressed(String tenantId, String artifactType, String artifactKey) {
        return current(tenantId, artifactType, artifactKey)
                .map(LearningArtifactRegistryEntry::runtimeSuppressed)
                .orElse(false);
    }

    private boolean isSuppressingState(LearningArtifactReleaseState state) {
        return state == LearningArtifactReleaseState.REVIEW_ONLY
                || state == LearningArtifactReleaseState.WITHDRAWN
                || state == LearningArtifactReleaseState.KILL_SWITCH_ACTIVE;
    }
}