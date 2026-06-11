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
package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.LearningArtifactReleaseLedgerRecord;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface LearningArtifactReleaseLedgerRecordRepository extends JpaRepository<LearningArtifactReleaseLedgerRecord, Long> {

    Optional<LearningArtifactReleaseLedgerRecord> findFirstByTenantIdAndArtifactTypeAndArtifactKeyOrderByCreatedAtDescIdDesc(
            String tenantId,
            String artifactType,
            String artifactKey);

    List<LearningArtifactReleaseLedgerRecord> findByTenantIdAndArtifactTypeAndArtifactKeyOrderByCreatedAtDescIdDesc(
            String tenantId,
            String artifactType,
            String artifactKey,
            Pageable pageable);

    List<LearningArtifactReleaseLedgerRecord> findByArtifactTypeAndArtifactKeyOrderByCreatedAtDescIdDesc(
            String artifactType,
            String artifactKey,
            Pageable pageable);
}