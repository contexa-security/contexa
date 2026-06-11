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

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory fallback registry store used when persistent storage is unavailable.
 */
public class InMemoryLearningArtifactRegistryStore implements LearningArtifactRegistryStore {

    private final Map<String, LearningArtifactRegistryEntry> entries = new ConcurrentHashMap<>();

    @Override
    public LearningArtifactRegistryEntry save(LearningArtifactRegistryEntry entry) {
        entries.put(key(entry.tenantId(), entry.artifactType(), entry.artifactKey()), entry);
        return entry;
    }

    @Override
    public Optional<LearningArtifactRegistryEntry> findCurrent(String tenantId, String artifactType, String artifactKey) {
        return Optional.ofNullable(entries.get(key(tenantId, artifactType, artifactKey)));
    }

    @Override
    public List<LearningArtifactRegistryEntry> findCurrentByArtifact(String artifactType, String artifactKey) {
        return entries.values().stream()
                .filter(entry -> entry.artifactType().equals(artifactType) && entry.artifactKey().equals(artifactKey))
                .sorted(Comparator.comparing(LearningArtifactRegistryEntry::updatedAt).reversed()
                        .thenComparing(LearningArtifactRegistryEntry::tenantId))
                .toList();
    }

    @Override
    public List<LearningArtifactRegistryEntry> findCurrentByTenant(String tenantId) {
        return entries.values().stream()
                .filter(entry -> entry.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(LearningArtifactRegistryEntry::updatedAt).reversed()
                        .thenComparing(LearningArtifactRegistryEntry::artifactType)
                        .thenComparing(LearningArtifactRegistryEntry::artifactKey))
                .toList();
    }

    private String key(String tenantId, String artifactType, String artifactKey) {
        return tenantId + "|" + artifactType + "|" + artifactKey;
    }
}