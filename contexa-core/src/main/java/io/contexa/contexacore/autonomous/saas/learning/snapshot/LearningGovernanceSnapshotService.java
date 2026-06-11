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
package io.contexa.contexacore.autonomous.saas.learning.snapshot;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Shared JSON persistence service for governance-only learning snapshots.
 */
public class LearningGovernanceSnapshotService {

    private final LearningGovernanceSnapshotStore store;
    private final ObjectMapper objectMapper;

    public LearningGovernanceSnapshotService(
            LearningGovernanceSnapshotStore store,
            ObjectMapper objectMapper) {
        this.store = store;
        this.objectMapper = objectMapper;
    }

    public <T> Optional<T> load(String tenantId, String artifactType, Class<T> snapshotType) {
        if (!StringUtils.hasText(tenantId) || !StringUtils.hasText(artifactType) || snapshotType == null) {
            return Optional.empty();
        }
        return store.find(tenantId.trim(), artifactType.trim())
                .flatMap(entry -> deserialize(entry.snapshotJson(), snapshotType));
    }

    public <T> T loadOrRefresh(
            String tenantId,
            String artifactType,
            Class<T> snapshotType,
            Supplier<T> refreshSupplier,
            Function<T, LocalDateTime> generatedAtResolver) {
        return load(tenantId, artifactType, snapshotType)
                .orElseGet(() -> persist(tenantId, artifactType, refreshSupplier.get(), generatedAtResolver));
    }

    public <T> T persist(
            String tenantId,
            String artifactType,
            T snapshot,
            Function<T, LocalDateTime> generatedAtResolver) {
        if (!StringUtils.hasText(tenantId) || !StringUtils.hasText(artifactType) || snapshot == null) {
            throw new IllegalArgumentException("tenantId, artifactType and snapshot are required.");
        }
        store.save(new LearningGovernanceSnapshotEntry(
                tenantId.trim(),
                artifactType.trim(),
                serialize(snapshot),
                generatedAtResolver == null ? null : generatedAtResolver.apply(snapshot),
                LocalDateTime.now()));
        return snapshot;
    }

    private String serialize(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Failed to serialize governance snapshot.", exception);
        }
    }

    private <T> Optional<T> deserialize(String snapshotJson, Class<T> snapshotType) {
        if (!StringUtils.hasText(snapshotJson)) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(objectMapper.readValue(snapshotJson, snapshotType));
        } catch (JsonProcessingException exception) {
            return Optional.empty();
        }
    }
}