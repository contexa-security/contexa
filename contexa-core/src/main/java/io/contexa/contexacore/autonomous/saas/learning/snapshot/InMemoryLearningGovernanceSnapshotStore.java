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

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class InMemoryLearningGovernanceSnapshotStore implements LearningGovernanceSnapshotStore {

    private final ConcurrentMap<String, LearningGovernanceSnapshotEntry> entries = new ConcurrentHashMap<>();

    @Override
    public Optional<LearningGovernanceSnapshotEntry> find(String tenantId, String artifactType) {
        return Optional.ofNullable(entries.get(key(tenantId, artifactType)));
    }

    @Override
    public LearningGovernanceSnapshotEntry save(LearningGovernanceSnapshotEntry entry) {
        entries.put(key(entry.tenantId(), entry.artifactType()), entry);
        return entry;
    }

    private String key(String tenantId, String artifactType) {
        return tenantId.trim() + "|" + artifactType.trim();
    }
}