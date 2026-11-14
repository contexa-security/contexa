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
package io.contexa.contexaiam.admin.promptquality.governance;

import java.time.LocalDateTime;

import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import org.springframework.lang.Nullable;

/**
 * The rollback's writes through the JPA repositories of the two tables. Each one is flushed at once: the rollback reads
 * the registry with JDBC right after it changes a state, and must see the change.
 */
public final class JpaPromptGovernanceStatusWriter implements PromptGovernanceStatusWriter {

    @Nullable
    private final PromptGovernanceRegistryRepository registry;
    @Nullable
    private final PromptGovernanceRollbackRecordRepository rollbacks;

    public JpaPromptGovernanceStatusWriter(@Nullable PromptGovernanceRegistryRepository registry,
                                           @Nullable PromptGovernanceRollbackRecordRepository rollbacks) {
        this.registry = registry;
        this.rollbacks = rollbacks;
    }

    @Override
    public void releaseStatus(String registryScope, String promptKey, String promptVersion, String status,
                              LocalDateTime at) {
        PromptGovernanceRegistryRepository repository = required(registry, "PromptGovernanceRegistryRepository");
        repository.findByRegistryScopeAndPromptKeyOrderByUpdatedAtDesc(registryScope, promptKey).stream()
                .filter(record -> promptVersion.equals(record.getPromptVersion()))
                .forEach(record -> {
                    record.setReleaseStatus(status);
                    record.setUpdatedAt(at);
                    repository.saveAndFlush(record);
                });
    }

    @Override
    public void rollbackReadiness(long rollbackId, String readiness, LocalDateTime at) {
        PromptGovernanceRollbackRecordRepository repository = required(rollbacks, "PromptGovernanceRollbackRecordRepository");
        repository.findById(rollbackId).ifPresent(record -> {
            record.setRollbackReadinessState(readiness);
            record.setUpdatedAt(at);
            repository.saveAndFlush(record);
        });
    }

    private static <T> T required(@Nullable T repository, String name) {
        if (repository == null) {
            throw new IllegalStateException(name + " is not available: the prompt bundle rollback cannot change a state");
        }
        return repository;
    }
}
