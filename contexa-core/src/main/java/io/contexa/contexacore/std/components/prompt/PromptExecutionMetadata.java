package io.contexa.contexacore.std.components.prompt;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record PromptExecutionMetadata(
        PromptGovernanceDescriptor governanceDescriptor,
        PromptBudgetProfile budgetProfile,
        PromptTokenEstimate promptTokenEstimate,
        PromptCompressionLedger promptCompressionLedger,
        List<String> sectionSet,
        List<String> omittedSections,
        List<PromptOmissionRecord> omissionLedger,
        List<PromptDuplicationRecord> duplicationInventory,
        PromptEvidenceCompleteness promptEvidenceCompleteness,
        String promptHash,
        String systemPromptHash,
        String userPromptHash,
        String rawPromptHash,
        String rawSystemPromptHash,
        String rawUserPromptHash,
        int systemPromptLength,
        int userPromptLength,
        int totalPromptLength,
        int rawSystemPromptLength,
        int rawUserPromptLength,
        int rawTotalPromptLength,
        long generatedAtEpochMs,
        Map<String, Object> supplementalMetadata) {

    public PromptExecutionMetadata {
        governanceDescriptor = Objects.requireNonNull(governanceDescriptor, "governanceDescriptor");
        budgetProfile = Objects.requireNonNull(budgetProfile, "budgetProfile");
        promptTokenEstimate = Objects.requireNonNull(promptTokenEstimate, "promptTokenEstimate");
        promptCompressionLedger = Objects.requireNonNull(promptCompressionLedger, "promptCompressionLedger");
        sectionSet = sectionSet == null ? List.of() : List.copyOf(sectionSet);
        omittedSections = omittedSections == null ? List.of() : List.copyOf(omittedSections);
        omissionLedger = omissionLedger == null ? List.of() : List.copyOf(omissionLedger);
        duplicationInventory = duplicationInventory == null ? List.of() : List.copyOf(duplicationInventory);
        promptEvidenceCompleteness = Objects.requireNonNull(promptEvidenceCompleteness, "promptEvidenceCompleteness");
        promptHash = requireText(promptHash, "promptHash");
        systemPromptHash = requireText(systemPromptHash, "systemPromptHash");
        userPromptHash = requireText(userPromptHash, "userPromptHash");
        rawPromptHash = requireText(rawPromptHash, "rawPromptHash");
        rawSystemPromptHash = requireText(rawSystemPromptHash, "rawSystemPromptHash");
        rawUserPromptHash = requireText(rawUserPromptHash, "rawUserPromptHash");
        if (systemPromptLength < 0
                || userPromptLength < 0
                || totalPromptLength < 0
                || rawSystemPromptLength < 0
                || rawUserPromptLength < 0
                || rawTotalPromptLength < 0) {
            throw new IllegalArgumentException("Prompt lengths must not be negative");
        }
        supplementalMetadata = supplementalMetadata == null ? Map.of() : Map.copyOf(supplementalMetadata);
    }

    public Map<String, Object> toMetadataMap() {
        Map<String, Object> metadata = new LinkedHashMap<>(governanceDescriptor.toMetadataMap());
        metadata.putAll(budgetProfile.toMetadataMap());
        metadata.putAll(promptTokenEstimate.toMetadataMap());
        metadata.putAll(promptCompressionLedger.toMetadataMap());
        metadata.put("promptSectionSet", sectionSet);
        metadata.put("omittedSections", omittedSections);
        metadata.put("omissionLedger", omissionLedger.stream().map(PromptOmissionRecord::toMetadataMap).toList());
        metadata.put("promptDuplicationInventoryVersion", "P1-SECTION-DUPLICATION-V1");
        metadata.put("promptDuplicationInventory", duplicationInventory.stream().map(PromptDuplicationRecord::toMetadataMap).toList());
        metadata.put("promptDuplicationInventoryCount", duplicationInventory.size());
        metadata.put("promptEvidenceCompleteness", promptEvidenceCompleteness.name());
        metadata.put("promptOmissionCount", omissionLedger.size());
        metadata.put("promptHash", promptHash);
        metadata.put("systemPromptHash", systemPromptHash);
        metadata.put("userPromptHash", userPromptHash);
        metadata.put("staticPromptPrefixHash", systemPromptHash);
        metadata.put("promptCacheEligible", true);
        metadata.put("rawPromptHash", rawPromptHash);
        metadata.put("rawSystemPromptHash", rawSystemPromptHash);
        metadata.put("rawUserPromptHash", rawUserPromptHash);
        metadata.put("systemPromptLength", systemPromptLength);
        metadata.put("userPromptLength", userPromptLength);
        metadata.put("totalPromptLength", totalPromptLength);
        metadata.put("rawSystemPromptLength", rawSystemPromptLength);
        metadata.put("rawUserPromptLength", rawUserPromptLength);
        metadata.put("rawTotalPromptLength", rawTotalPromptLength);
        metadata.put("promptGeneratedAtEpochMs", generatedAtEpochMs);
        metadata.putAll(supplementalMetadata);
        return metadata;
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
