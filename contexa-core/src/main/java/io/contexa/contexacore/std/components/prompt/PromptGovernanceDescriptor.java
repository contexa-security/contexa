package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

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
        metadata.put("promptOwner", owner);
        metadata.put("promptReleaseApprovalReference", releaseApprovalReference);
        metadata.put("promptEvaluationBaselineReference", evaluationBaselineReference);
        metadata.put("promptRollbackVersion", rollbackPromptVersion);
        metadata.put("promptChangeSummary", changeSummary);
        metadata.put("promptSupportedModelProfiles", supportedModelProfiles);
        metadata.put("promptTemplateClass", templateClassName);
        return metadata;
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
