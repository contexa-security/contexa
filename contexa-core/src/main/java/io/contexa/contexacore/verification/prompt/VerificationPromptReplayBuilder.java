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
