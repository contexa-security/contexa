package io.contexa.contexacore.std.components.prompt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class PromptGovernanceSupport {

    private static final PromptTokenEstimator DEFAULT_PROMPT_TOKEN_ESTIMATOR = new HeuristicPromptTokenEstimator();

    private PromptGovernanceSupport() {
    }

    public static PromptExecutionMetadata buildExecutionMetadata(
            PromptGovernanceDescriptor descriptor,
            String systemPrompt,
            String userPrompt) {
        return buildExecutionMetadata(
                descriptor,
                PromptBudgetProfile.CORTEX_L1_STANDARD,
                java.util.List.of(),
                java.util.List.of(),
                java.util.List.of(),
                PromptEvidenceCompleteness.SUFFICIENT,
                systemPrompt,
                userPrompt,
                systemPrompt,
                userPrompt,
                PromptCompressionLedger.identity(systemPrompt, userPrompt));
    }

    public static PromptExecutionMetadata buildExecutionMetadata(
            PromptGovernanceDescriptor descriptor,
            PromptBudgetProfile budgetProfile,
            java.util.List<String> sectionSet,
            java.util.List<String> omittedSections,
            java.util.List<PromptOmissionRecord> omissionLedger,
            PromptEvidenceCompleteness promptEvidenceCompleteness,
            String systemPrompt,
            String userPrompt) {
        return buildExecutionMetadata(
                descriptor,
                budgetProfile,
                sectionSet,
                omittedSections,
                omissionLedger,
                promptEvidenceCompleteness,
                systemPrompt,
                userPrompt,
                systemPrompt,
                userPrompt,
                PromptCompressionLedger.identity(systemPrompt, userPrompt));
    }

    public static PromptExecutionMetadata buildExecutionMetadata(
            PromptGovernanceDescriptor descriptor,
            PromptBudgetProfile budgetProfile,
            java.util.List<String> sectionSet,
            java.util.List<String> omittedSections,
            java.util.List<PromptOmissionRecord> omissionLedger,
            PromptEvidenceCompleteness promptEvidenceCompleteness,
            String systemPrompt,
            String userPrompt,
            String rawSystemPrompt,
            String rawUserPrompt,
            PromptCompressionLedger promptCompressionLedger) {
        String normalizedSystemPrompt = systemPrompt != null ? systemPrompt : "";
        String normalizedUserPrompt = userPrompt != null ? userPrompt : "";
        String normalizedRawSystemPrompt = rawSystemPrompt != null ? rawSystemPrompt : "";
        String normalizedRawUserPrompt = rawUserPrompt != null ? rawUserPrompt : "";
        String combinedPrompt = normalizedSystemPrompt + "\n---\n" + normalizedUserPrompt;
        String combinedRawPrompt = normalizedRawSystemPrompt + "\n---\n" + normalizedRawUserPrompt;
        PromptTokenEstimate estimated =
                DEFAULT_PROMPT_TOKEN_ESTIMATOR.estimate(normalizedSystemPrompt, normalizedUserPrompt, budgetProfile);
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
                System.currentTimeMillis());
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
