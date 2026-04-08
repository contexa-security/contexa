package io.contexa.contexacore.autonomous.saas.learning.prompt;

import java.util.List;

/**
 * Structural prompt presentation fingerprint derived from whitelisted formatting metadata only.
 */
public record PromptPresentationPatternProfile(
        String patternKey,
        String promptKey,
        String templateKey,
        String promptVersion,
        String transformationMode,
        boolean compressionApplied,
        String evidenceCompleteness,
        List<String> sectionSet,
        List<String> omittedSections) {

    public PromptPresentationPatternProfile {
        patternKey = normalize(patternKey);
        promptKey = normalize(promptKey);
        templateKey = normalize(templateKey);
        promptVersion = normalize(promptVersion);
        transformationMode = normalize(transformationMode);
        evidenceCompleteness = normalize(evidenceCompleteness);
        sectionSet = sectionSet == null ? List.of() : List.copyOf(sectionSet);
        omittedSections = omittedSections == null ? List.of() : List.copyOf(omittedSections);
    }

    public boolean isClassified() {
        return patternKey != null;
    }

    public static PromptPresentationPatternProfile unclassified() {
        return new PromptPresentationPatternProfile(null, null, null, null, null, false, null, List.of(), List.of());
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}