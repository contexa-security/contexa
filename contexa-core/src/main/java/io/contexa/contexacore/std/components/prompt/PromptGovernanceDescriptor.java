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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public record PromptGovernanceDescriptor(
        String promptKey,
        String templateKey,
        String promptVersion,
        String contractVersion,
        PromptReleaseStatus releaseStatus,
        String owner,
        String releaseApprovalReference,
        String evaluationBaselineReference,
        String rollbackPromptVersion,
        String changeSummary,
        List<String> supportedModelProfiles,
        String templateClassName) {

    public PromptGovernanceDescriptor {
        promptKey = requireText(promptKey, "promptKey");
        templateKey = requireText(templateKey, "templateKey");
        promptVersion = requireText(promptVersion, "promptVersion");
        contractVersion = requireText(contractVersion, "contractVersion");
        releaseStatus = Objects.requireNonNull(releaseStatus, "releaseStatus");
        owner = requireText(owner, "owner");
        releaseApprovalReference = requireText(releaseApprovalReference, "releaseApprovalReference");
        evaluationBaselineReference = requireText(evaluationBaselineReference, "evaluationBaselineReference");
        rollbackPromptVersion = requireText(rollbackPromptVersion, "rollbackPromptVersion");
        changeSummary = requireText(changeSummary, "changeSummary");
        supportedModelProfiles = supportedModelProfiles == null ? List.of() : List.copyOf(supportedModelProfiles);
        templateClassName = requireText(templateClassName, "templateClassName");
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("promptKey", promptKey);
        metadata.put("templateKey", templateKey);
        metadata.put("promptVersion", promptVersion);
        metadata.put("contractVersion", contractVersion);
        metadata.put("promptReleaseStatus", releaseStatus.name());
        metadata.put("releaseStatus", releaseStatus.name());
        metadata.put("promptOwner", owner);
        metadata.put("promptReleaseApprovalReference", releaseApprovalReference);
        metadata.put("releaseApprovalReference", releaseApprovalReference);
        metadata.put("promptEvaluationBaselineReference", evaluationBaselineReference);
        metadata.put("promptRollbackVersion", rollbackPromptVersion);
        metadata.put("promptChangeSummary", changeSummary);
        metadata.put("promptSupportedModelProfiles", supportedModelProfiles);
        metadata.put("promptTemplateClass", templateClassName);
        metadata.put("promptArtifactHashSha256", artifactHashSha256());
        return metadata;
    }

    public String artifactHashSha256() {
        return sha256(String.join("|",
                promptKey,
                templateKey,
                promptVersion,
                contractVersion,
                releaseStatus.name(),
                owner,
                releaseApprovalReference,
                evaluationBaselineReference,
                rollbackPromptVersion,
                changeSummary,
                String.join(",", supportedModelProfiles),
                templateClassName));
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte item : hash) {
                builder.append(String.format("%02x", item & 0xff));
            }
            return builder.toString();
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 algorithm is not available.", exception);
        }
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
