package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record PromptExecutionMetadata(
        PromptGovernanceDescriptor governanceDescriptor,
        PromptBudgetProfile budgetProfile,
        List<String> sectionSet,
        List<String> omittedSections,
        List<PromptOmissionRecord> omissionLedger,
        PromptEvidenceCompleteness promptEvidenceCompleteness,
        String promptHash,
        String systemPromptHash,
        String userPromptHash,
        int systemPromptLength,
        int userPromptLength,
        int totalPromptLength,
        long generatedAtEpochMs) {

    public PromptExecutionMetadata {
        governanceDescriptor = Objects.requireNonNull(governanceDescriptor, "governanceDescriptor");
        budgetProfile = Objects.requireNonNull(budgetProfile, "budgetProfile");
        sectionSet = sectionSet == null ? List.of() : List.copyOf(sectionSet);
        omittedSections = omittedSections == null ? List.of() : List.copyOf(omittedSections);
        omissionLedger = omissionLedger == null ? List.of() : List.copyOf(omissionLedger);
        promptEvidenceCompleteness = Objects.requireNonNull(promptEvidenceCompleteness, "promptEvidenceCompleteness");
        promptHash = requireText(promptHash, "promptHash");
        systemPromptHash = requireText(systemPromptHash, "systemPromptHash");
        userPromptHash = requireText(userPromptHash, "userPromptHash");
        if (systemPromptLength < 0 || userPromptLength < 0 || totalPromptLength < 0) {
            throw new IllegalArgumentException("Prompt lengths must not be negative");
        }
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>(governanceDescriptor.toMetadataMap());
        metadata.putAll(budgetProfile.toMetadataMap());
        metadata.put("promptSectionSet", sectionSet);
        metadata.put("omittedSections", omittedSections);
        metadata.put("omissionLedger", omissionLedger.stream().map(PromptOmissionRecord::toMetadataMap).toList());
        metadata.put("promptEvidenceCompleteness", promptEvidenceCompleteness.name());
        metadata.put("promptOmissionCount", omissionLedger.size());
        metadata.put("promptHash", promptHash);
        metadata.put("systemPromptHash", systemPromptHash);
        metadata.put("userPromptHash", userPromptHash);
        metadata.put("systemPromptLength", systemPromptLength);
        metadata.put("userPromptLength", userPromptLength);
        metadata.put("totalPromptLength", totalPromptLength);
        metadata.put("promptGeneratedAtEpochMs", generatedAtEpochMs);
        return metadata;
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
