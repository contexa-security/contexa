package io.contexa.contexacore.verification.prompt;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds normalized replay prompt contexts from sealed evidence and rebuilt context sections.
 */
public class VerificationPromptReplayBuilder {

    public VerificationPromptReplayContext buildSealedPromptContext(SealedEvidencePackage pkg) {
        if (pkg == null) {
            throw new IllegalArgumentException("Sealed evidence package is required");
        }
        return buildContext(pkg, firstText(pkg.getUserPromptText(), pkg.getRawUserPrompt()), false, false);
    }

    public VerificationPromptReplayContext buildDeterministicReplayContext(
            SealedEvidencePackage pkg,
            String rebuiltContextSections
    ) {
        if (pkg == null) {
            throw new IllegalArgumentException("Sealed evidence package is required");
        }
        return buildContext(pkg, firstText(pkg.getUserPromptText(), pkg.getRawUserPrompt()), hasText(rebuiltContextSections), false);
    }

    public VerificationPromptReplayContext buildScenarioExperimentContext(
            SealedEvidencePackage pkg,
            String rebuiltUserPrompt,
            boolean fullPromptRebuilt
    ) {
        if (pkg == null) {
            throw new IllegalArgumentException("Sealed evidence package is required");
        }
        return buildContext(pkg, rebuiltUserPrompt, hasText(rebuiltUserPrompt), fullPromptRebuilt);
    }

    public VerificationPromptReplayContext buildSingleContextMutation(
            SealedEvidencePackage pkg,
            String originalContextSections,
            String mutatedContextSections
    ) {
        if (pkg == null) {
            throw new IllegalArgumentException("Sealed evidence package is required");
        }
        if (!hasText(originalContextSections) || !hasText(mutatedContextSections)) {
            throw new IllegalArgumentException("Original and mutated context sections are required");
        }
        if (originalContextSections.equals(mutatedContextSections)) {
            throw new IllegalStateException("Context mutation did not change the composed context");
        }
        String originalUserPrompt = firstText(pkg.getUserPromptText(), pkg.getRawUserPrompt());
        if (!hasText(originalUserPrompt)) {
            throw new IllegalStateException("Original user prompt is required for a context mutation");
        }
        int firstIndex = originalUserPrompt.indexOf(originalContextSections);
        if (firstIndex < 0) {
            throw new IllegalStateException("Original canonical context section is not present in the user prompt");
        }
        if (originalUserPrompt.indexOf(originalContextSections, firstIndex + originalContextSections.length()) >= 0) {
            throw new IllegalStateException("Original canonical context section is ambiguous in the user prompt");
        }
        String rebuiltUserPrompt = originalUserPrompt.substring(0, firstIndex)
                + mutatedContextSections
                + originalUserPrompt.substring(firstIndex + originalContextSections.length());
        return buildContext(pkg, rebuiltUserPrompt, true, true);
    }

    private VerificationPromptReplayContext buildContext(
            SealedEvidencePackage pkg,
            String selectedUserPrompt,
            boolean rebuiltFromCanonicalContext,
            boolean fullPromptRebuilt
    ) {
        String systemPrompt = firstText(pkg.getSystemPromptText(), pkg.getRawSystemPrompt());
        String userPrompt = firstText(selectedUserPrompt, pkg.getUserPromptText(), pkg.getRawUserPrompt());

        VerificationPromptFidelityReport report = buildFidelityReport(
                pkg,
                rebuiltFromCanonicalContext,
                fullPromptRebuilt,
                userPrompt
        );
        return new VerificationPromptReplayContext(
                systemPrompt,
                userPrompt,
                pkg.getRawSystemPrompt(),
                pkg.getRawUserPrompt(),
                pkg.getPromptHash(),
                report
        );
    }

    private VerificationPromptFidelityReport buildFidelityReport(
            SealedEvidencePackage pkg,
            boolean rebuiltFromCanonicalContext,
            boolean fullPromptRebuilt,
            String userPrompt
    ) {
        boolean rawPromptPresent = hasText(pkg.getRawSystemPrompt()) && hasText(pkg.getRawUserPrompt());
        boolean llmViewPromptPresent = hasText(pkg.getSystemPromptText()) && hasText(pkg.getUserPromptText());
        boolean promptHashPresent = hasText(pkg.getPromptHash());

        List<String> findings = new ArrayList<>();
        if (!rawPromptPresent) {
            findings.add("RAW_PROMPT_MISSING");
        }
        if (!llmViewPromptPresent) {
            findings.add("LLM_VIEW_PROMPT_MISSING");
        }
        if (!promptHashPresent) {
            findings.add("PROMPT_HASH_MISSING");
        }
        if (!rebuiltFromCanonicalContext) {
            findings.add("CANONICAL_CONTEXT_REBUILD_NOT_AVAILABLE");
        }
        if (rebuiltFromCanonicalContext && !fullPromptRebuilt) {
            findings.add("FULL_PROMPT_REBUILD_NOT_CONFIRMED");
        }

        VerificationPromptFidelityLevel level = resolveLevel(
                rawPromptPresent,
                llmViewPromptPresent,
                promptHashPresent,
                rebuiltFromCanonicalContext,
                fullPromptRebuilt,
                hasText(userPrompt)
        );

        return new VerificationPromptFidelityReport(
                level,
                rawPromptPresent,
                llmViewPromptPresent,
                promptHashPresent,
                rebuiltFromCanonicalContext,
                fullPromptRebuilt,
                findings
        );
    }

    private VerificationPromptFidelityLevel resolveLevel(
            boolean rawPromptPresent,
            boolean llmViewPromptPresent,
            boolean promptHashPresent,
            boolean rebuiltFromCanonicalContext,
            boolean fullPromptRebuilt,
            boolean userPromptAvailable
    ) {
        if (rawPromptPresent && llmViewPromptPresent && promptHashPresent && rebuiltFromCanonicalContext && fullPromptRebuilt) {
            return VerificationPromptFidelityLevel.FULL_REBUILT;
        }
        if ((rawPromptPresent || llmViewPromptPresent) && userPromptAvailable && rebuiltFromCanonicalContext) {
            return VerificationPromptFidelityLevel.PARTIAL_REBUILT;
        }
        if (rawPromptPresent || llmViewPromptPresent || userPromptAvailable) {
            return VerificationPromptFidelityLevel.EVIDENCE_ONLY;
        }
        return VerificationPromptFidelityLevel.UNVERIFIABLE;
    }

    private boolean hasText(String value) {
        return StringUtils.hasText(value);
    }

    private String firstText(String... candidates) {
        for (String candidate : candidates) {
            if (StringUtils.hasText(candidate)) {
                return candidate;
            }
        }
        return null;
    }
}
