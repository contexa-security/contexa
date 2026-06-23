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
package io.contexa.contexacore.hcad.semantic;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;

public record HcadSemanticEvidenceEntry(
        HcadSemanticEvidenceKey key,
        HcadSemanticEvidenceCacheStatus status,
        String sourceVersion,
        String evidenceVersion,
        String embeddingModel,
        Integer dimension,
        Double similarityToNormal,
        Double similarityToRisk,
        Double mismatchScore,
        String summaryJson,
        List<String> evidenceGapCodes,
        Instant createdAt,
        Instant expiresAt) {

    public HcadSemanticEvidenceEntry {
        key = Objects.requireNonNull(key, "key must not be null");
        status = Objects.requireNonNull(status, "status must not be null");
        evidenceGapCodes = evidenceGapCodes == null ? List.of() : List.copyOf(evidenceGapCodes);
    }

    public boolean usableForScoring() {
        return status.usableForScoring() && !expired();
    }

    public boolean expired() {
        return expiresAt != null && !expiresAt.isAfter(Instant.now());
    }

    public HcadSemanticEvidenceEntry forRequestedKey(HcadSemanticEvidenceKey requestedKey) {
        if (requestedKey == null || Objects.equals(key, requestedKey)) {
            return this;
        }
        if (!Objects.equals(dimension, requestedKey.dimension())
                || !Objects.equals(key.dimension(), requestedKey.dimension())) {
            return withStatus(HcadSemanticEvidenceCacheStatus.DIMENSION_MISMATCH, "DIMENSION_MISMATCH");
        }
        if (!Objects.equals(embeddingModel, requestedKey.embeddingModel())
                || !Objects.equals(evidenceVersion, requestedKey.evidenceVersion())
                || !Objects.equals(key.embeddingModel(), requestedKey.embeddingModel())
                || !Objects.equals(key.evidenceVersion(), requestedKey.evidenceVersion())
                || !Objects.equals(key.policyVersion(), requestedKey.policyVersion())
                || !Objects.equals(key.promptTemplateVersion(), requestedKey.promptTemplateVersion())
                || !Objects.equals(key.baselineVersion(), requestedKey.baselineVersion())
                || !Objects.equals(key.flowVersion(), requestedKey.flowVersion())) {
            return withStatus(HcadSemanticEvidenceCacheStatus.VERSION_MISMATCH, "VERSION_MISMATCH");
        }
        return this;
    }

    public HcadSemanticEvidenceEntry withStatus(
            HcadSemanticEvidenceCacheStatus nextStatus,
            String evidenceGapCode) {
        List<String> gaps = appendGap(evidenceGapCodes, evidenceGapCode);
        return new HcadSemanticEvidenceEntry(
                key,
                nextStatus == null ? status : nextStatus,
                sourceVersion,
                evidenceVersion,
                embeddingModel,
                dimension,
                similarityToNormal,
                similarityToRisk,
                mismatchScore,
                summaryJson,
                gaps,
                createdAt,
                expiresAt);
    }

    private static List<String> appendGap(List<String> existing, String gapCode) {
        LinkedHashSet<String> gaps = new LinkedHashSet<>();
        if (existing != null) {
            gaps.addAll(existing);
        }
        if (gapCode != null && !gapCode.isBlank()) {
            gaps.add(gapCode.trim());
        }
        return List.copyOf(gaps);
    }
}
