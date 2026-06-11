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
package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.Map;

public record PromptFieldStateRecord(
        String fieldKey,
        String sourceType,
        String sourceFieldPath,
        String sourceClass,
        PromptFieldState fieldState,
        String valueType,
        String valueHash,
        int valueLength,
        String valuePreview,
        String requiredPolicy,
        String applicabilityRule,
        String applicabilityEvidence,
        String projectionPolicy,
        String promptPresenceState,
        String sealedEvidencePresenceState,
        String producerStatus,
        String absenceReasonCode,
        String absenceReasonText,
        String metricImpactPolicy,
        String blockingPolicy,
        String promptSection,
        String promptLabel) {

    public Map<String, Object> toMetadataMap() {
        PromptFieldPolicy policy = PromptFieldPolicyCatalog.resolve(
                fieldKey,
                sourceType,
                sourceFieldPath,
                promptLabel);
        boolean rawBlocking = fieldState.blockingCandidate();
        boolean officialBlocking = rawBlocking && policy.officialContractField();
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("fieldKey", fieldKey);
        metadata.put("sourceType", sourceType);
        metadata.put("sourceFieldPath", sourceFieldPath);
        metadata.put("sourceClass", sourceClass);
        metadata.put("fieldState", fieldState.name());
        metadata.put("valueType", valueType);
        metadata.put("valueHash", valueHash);
        metadata.put("valueLength", valueLength);
        metadata.put("valuePreview", valuePreview);
        metadata.put("requiredPolicy", firstNonBlank(requiredPolicy, policy.requiredPolicy()));
        metadata.put("applicabilityRule", firstNonBlank(applicabilityRule, policy.applicabilityRule()));
        metadata.put("applicabilityEvidence", applicabilityEvidence);
        metadata.put("projectionPolicy", firstNonBlank(projectionPolicy, policy.projectionPolicy()));
        metadata.put("promptPresenceState", promptPresenceState);
        metadata.put("sealedEvidencePresenceState", sealedEvidencePresenceState);
        metadata.put("producerStatus", producerStatus);
        metadata.put("absenceReasonCode", absenceReasonCode);
        metadata.put("absenceReasonText", absenceReasonText);
        metadata.put("metricImpactPolicy", firstNonBlank(metricImpactPolicy, String.join(",", policy.metricCodes())));
        metadata.put("blockingPolicy", firstNonBlank(blockingPolicy, officialBlocking ? "OFFICIAL_BLOCKING" : "NON_BLOCKING"));
        metadata.put("blockingCandidate", rawBlocking);
        metadata.put("rawBlockingCandidate", rawBlocking);
        metadata.put("officialBlockingCandidate", officialBlocking);
        metadata.put("qualityRelevance", policy.qualityRelevance());
        metadata.put("metricCodes", policy.metricCodes());
        metadata.put("remediationOwner", policy.remediationOwner());
        metadata.put("notApplicableRule", policy.notApplicableRule());
        metadata.put("promptSection", promptSection);
        metadata.put("promptLabel", promptLabel);
        return metadata;
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return "";
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return "";
    }
}
