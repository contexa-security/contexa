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

import java.util.Objects;

public record HcadSemanticEvidenceKey(
        HcadSemanticEvidenceType type,
        String tenantId,
        String userId,
        String sessionId,
        String contextBindingHash,
        String resourceId,
        String policyVersion,
        String promptTemplateVersion,
        String baselineVersion,
        String flowVersion,
        String embeddingModel,
        Integer dimension,
        String evidenceVersion) {

    public HcadSemanticEvidenceKey {
        type = Objects.requireNonNull(type, "type must not be null");
        tenantId = clean(tenantId);
        userId = clean(userId);
        sessionId = clean(sessionId);
        contextBindingHash = clean(contextBindingHash);
        resourceId = clean(resourceId);
        policyVersion = clean(policyVersion);
        promptTemplateVersion = clean(promptTemplateVersion);
        baselineVersion = clean(baselineVersion);
        flowVersion = clean(flowVersion);
        embeddingModel = clean(embeddingModel);
        evidenceVersion = clean(evidenceVersion);
        if (dimension != null && dimension <= 0) {
            throw new IllegalArgumentException("dimension must be positive");
        }
    }

    public static HcadSemanticEvidenceKey userNormalBaseline(
            String tenantId,
            String userId,
            String baselineVersion,
            String embeddingModel,
            int dimension,
            String evidenceVersion) {
        return new HcadSemanticEvidenceKey(
                HcadSemanticEvidenceType.USER_NORMAL_BASELINE,
                tenantId,
                userId,
                null,
                null,
                null,
                null,
                null,
                baselineVersion,
                null,
                embeddingModel,
                dimension,
                evidenceVersion);
    }

    public static HcadSemanticEvidenceKey sessionRecentFlow(
            String tenantId,
            String userId,
            String sessionId,
            String contextBindingHash,
            String flowVersion,
            String embeddingModel,
            int dimension,
            String evidenceVersion) {
        return new HcadSemanticEvidenceKey(
                HcadSemanticEvidenceType.SESSION_RECENT_FLOW,
                tenantId,
                userId,
                sessionId,
                contextBindingHash,
                null,
                null,
                null,
                null,
                flowVersion,
                embeddingModel,
                dimension,
                evidenceVersion);
    }

    public static HcadSemanticEvidenceKey resourceDecisionSummary(
            String tenantId,
            String resourceId,
            String policyVersion,
            String promptTemplateVersion,
            String embeddingModel,
            int dimension,
            String evidenceVersion) {
        return new HcadSemanticEvidenceKey(
                HcadSemanticEvidenceType.RESOURCE_LLM_DECISION_SUMMARY,
                tenantId,
                null,
                null,
                null,
                resourceId,
                policyVersion,
                promptTemplateVersion,
                null,
                null,
                embeddingModel,
                dimension,
                evidenceVersion);
    }

    public static HcadSemanticEvidenceKey policyPromptSnapshot(
            String tenantId,
            String resourceId,
            String policyVersion,
            String promptTemplateVersion,
            String evidenceVersion) {
        return new HcadSemanticEvidenceKey(
                HcadSemanticEvidenceType.POLICY_PROMPT_VERSION_SNAPSHOT,
                tenantId,
                null,
                null,
                null,
                resourceId,
                policyVersion,
                promptTemplateVersion,
                null,
                null,
                null,
                null,
                evidenceVersion);
    }

    public static HcadSemanticEvidenceKey normalRequestSimilarity(
            String tenantId,
            String userId,
            String resourceId,
            String baselineVersion,
            String embeddingModel,
            int dimension,
            String evidenceVersion) {
        return new HcadSemanticEvidenceKey(
                HcadSemanticEvidenceType.NORMAL_REQUEST_SIMILARITY,
                tenantId,
                userId,
                null,
                null,
                resourceId,
                null,
                null,
                baselineVersion,
                null,
                embeddingModel,
                dimension,
                evidenceVersion);
    }

    public static HcadSemanticEvidenceKey riskRequestSimilarity(
            String tenantId,
            String userId,
            String resourceId,
            String policyVersion,
            String promptTemplateVersion,
            String embeddingModel,
            int dimension,
            String evidenceVersion) {
        return new HcadSemanticEvidenceKey(
                HcadSemanticEvidenceType.RISK_REQUEST_SIMILARITY,
                tenantId,
                userId,
                null,
                null,
                resourceId,
                policyVersion,
                promptTemplateVersion,
                null,
                null,
                embeddingModel,
                dimension,
                evidenceVersion);
    }

    private static String clean(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
