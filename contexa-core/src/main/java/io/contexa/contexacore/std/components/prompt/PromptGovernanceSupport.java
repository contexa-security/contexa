package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public final class PromptGovernanceSupport {

    private static final PromptTokenEstimatorRegistry PROMPT_TOKEN_ESTIMATOR_REGISTRY =
            PromptTokenEstimatorRegistry.defaultRegistry();

    private PromptGovernanceSupport() {
    }

    public static PromptExecutionMetadata buildExecutionMetadata(
            PromptGovernanceDescriptor descriptor,
            String systemPrompt,
            String userPrompt) {
        return buildExecutionMetadata(
                descriptor,
                null,
                systemPrompt,
                userPrompt);
    }

    public static PromptExecutionMetadata buildExecutionMetadata(
            PromptGovernanceDescriptor descriptor,
            String modelHint,
            String systemPrompt,
            String userPrompt) {
        return buildExecutionMetadata(
                descriptor,
                PromptBudgetProfile.CORTEX_L1_STANDARD,
                java.util.List.of(),
                java.util.List.of(),
                java.util.List.of(),
                java.util.List.of(),
                PromptEvidenceCompleteness.SUFFICIENT,
                modelHint,
                systemPrompt,
                userPrompt,
                systemPrompt,
                userPrompt,
                PromptCompressionLedger.identity(systemPrompt, userPrompt),
                java.util.Map.of());
    }

    public static PromptExecutionMetadata buildExecutionMetadata(
            PromptGovernanceDescriptor descriptor,
            PromptBudgetProfile budgetProfile,
            java.util.List<String> sectionSet,
            java.util.List<String> omittedSections,
            java.util.List<PromptOmissionRecord> omissionLedger,
            java.util.List<PromptDuplicationRecord> duplicationInventory,
            PromptEvidenceCompleteness promptEvidenceCompleteness,
            String systemPrompt,
            String userPrompt) {
        return buildExecutionMetadata(
                descriptor,
                budgetProfile,
                sectionSet,
                omittedSections,
                omissionLedger,
                duplicationInventory,
                promptEvidenceCompleteness,
                null,
                systemPrompt,
                userPrompt);
    }

    public static PromptExecutionMetadata buildExecutionMetadata(
            PromptGovernanceDescriptor descriptor,
            PromptBudgetProfile budgetProfile,
            java.util.List<String> sectionSet,
            java.util.List<String> omittedSections,
            java.util.List<PromptOmissionRecord> omissionLedger,
            java.util.List<PromptDuplicationRecord> duplicationInventory,
            PromptEvidenceCompleteness promptEvidenceCompleteness,
            String modelHint,
            String systemPrompt,
            String userPrompt) {
        return buildExecutionMetadata(
                descriptor,
                budgetProfile,
                sectionSet,
                omittedSections,
                omissionLedger,
                duplicationInventory,
                promptEvidenceCompleteness,
                modelHint,
                systemPrompt,
                userPrompt,
                systemPrompt,
                userPrompt,
                PromptCompressionLedger.identity(systemPrompt, userPrompt),
                java.util.Map.of());
    }

    public static PromptExecutionMetadata buildExecutionMetadata(
            PromptGovernanceDescriptor descriptor,
            PromptBudgetProfile budgetProfile,
            java.util.List<String> sectionSet,
            java.util.List<String> omittedSections,
            java.util.List<PromptOmissionRecord> omissionLedger,
            java.util.List<PromptDuplicationRecord> duplicationInventory,
            PromptEvidenceCompleteness promptEvidenceCompleteness,
            String modelHint,
            String systemPrompt,
            String userPrompt,
            String rawSystemPrompt,
            String rawUserPrompt,
            PromptCompressionLedger promptCompressionLedger) {
        return buildExecutionMetadata(
                descriptor,
                budgetProfile,
                sectionSet,
                omittedSections,
                omissionLedger,
                duplicationInventory,
                promptEvidenceCompleteness,
                modelHint,
                systemPrompt,
                userPrompt,
                rawSystemPrompt,
                rawUserPrompt,
                promptCompressionLedger,
                java.util.Map.of());
    }

    public static PromptExecutionMetadata buildExecutionMetadata(
            PromptGovernanceDescriptor descriptor,
            PromptBudgetProfile budgetProfile,
            java.util.List<String> sectionSet,
            java.util.List<String> omittedSections,
            java.util.List<PromptOmissionRecord> omissionLedger,
            java.util.List<PromptDuplicationRecord> duplicationInventory,
            PromptEvidenceCompleteness promptEvidenceCompleteness,
            String modelHint,
            String systemPrompt,
            String userPrompt,
            String rawSystemPrompt,
            String rawUserPrompt,
            PromptCompressionLedger promptCompressionLedger,
            java.util.Map<String, Object> supplementalMetadata) {
        String normalizedSystemPrompt = systemPrompt != null ? systemPrompt : "";
        String normalizedUserPrompt = userPrompt != null ? userPrompt : "";
        String normalizedRawSystemPrompt = rawSystemPrompt != null ? rawSystemPrompt : "";
        String normalizedRawUserPrompt = rawUserPrompt != null ? rawUserPrompt : "";
        String combinedPrompt = normalizedSystemPrompt + "\n---\n" + normalizedUserPrompt;
        String combinedRawPrompt = normalizedRawSystemPrompt + "\n---\n" + normalizedRawUserPrompt;
        PromptTokenEstimator promptTokenEstimator = PROMPT_TOKEN_ESTIMATOR_REGISTRY.resolve(modelHint);
        PromptTokenEstimate estimated =
                promptTokenEstimator.estimate(modelHint, normalizedSystemPrompt, normalizedUserPrompt, budgetProfile);
        PromptCompressionLedger effectiveCompressionLedger = promptCompressionLedger != null
                ? promptCompressionLedger
                : PromptCompressionLedger.identity(normalizedRawSystemPrompt, normalizedRawUserPrompt);
        String enforcementMode = effectiveCompressionLedger.compressionApplied()
                ? "LLM_VIEW_ENFORCED"
                : estimated.budgetEnforcementMode();
        PromptTokenEstimate promptTokenEstimate = new PromptTokenEstimate(
                estimated.estimatorKey(),
                estimated.estimatedSystemTokens(),
                estimated.estimatedUserTokens(),
                estimated.estimatedTotalTokens(),
                estimated.budgetRemainingTokens(),
                estimated.budgetUtilizationRate(),
                estimated.budgetExceeded(),
                enforcementMode,
                effectiveCompressionLedger.compressionApplied());

        return new PromptExecutionMetadata(
                descriptor,
                budgetProfile,
                promptTokenEstimate,
                effectiveCompressionLedger,
                sectionSet,
                omittedSections,
                omissionLedger,
                duplicationInventory,
                promptEvidenceCompleteness,
                sha256(combinedPrompt),
                sha256(normalizedSystemPrompt),
                sha256(normalizedUserPrompt),
                sha256(combinedRawPrompt),
                sha256(normalizedRawSystemPrompt),
                sha256(normalizedRawUserPrompt),
                normalizedSystemPrompt.length(),
                normalizedUserPrompt.length(),
                normalizedSystemPrompt.length() + normalizedUserPrompt.length(),
                normalizedRawSystemPrompt.length(),
                normalizedRawUserPrompt.length(),
                normalizedRawSystemPrompt.length() + normalizedRawUserPrompt.length(),
                System.currentTimeMillis(),
                supplementalMetadata);
    }

    public static String resolveRequestedModelHint(AIRequest<? extends DomainContext> request) {
        if (request == null || request.getParameters() == null || request.getParameters().isEmpty()) {
            return null;
        }
        for (String key : List.of(
                "requestedModelId",
                "preferredModel",
                "runtimeModelId",
                "officialVerificationPinnedModelId")) {
            Object value = request.getParameter(key, Object.class);
            if (value instanceof String text && !text.isBlank()) {
                return text.trim();
            }
            if (value != null) {
                String text = String.valueOf(value).trim();
                if (!text.isEmpty()) {
                    return text;
                }
            }
        }
        return null;
    }

    public static PromptGovernanceDescriptor buildDefaultDescriptor(String templateKey, Class<?> templateClass) {
        String normalizedTemplateKey = templateKey != null && !templateKey.isBlank()
                ? templateKey
                : templateClass.getSimpleName();
        return new PromptGovernanceDescriptor(
                normalizedTemplateKey,
                normalizedTemplateKey,
                "UNVERSIONED",
                "UNSPECIFIED",
                PromptReleaseStatus.DRAFT,
                "unassigned",
                "unapproved",
                "unevaluated",
                "none",
                "Default prompt governance descriptor",
                java.util.List.of(),
                templateClass.getName());
    }

    public static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder encoded = new StringBuilder("sha256:");
            for (byte item : hash) {
                encoded.append(String.format("%02x", item));
            }
            return encoded.toString();
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 digest unavailable", ex);
        }
    }
}
