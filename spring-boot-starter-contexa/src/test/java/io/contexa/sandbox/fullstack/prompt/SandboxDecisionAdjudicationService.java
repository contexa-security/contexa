package io.contexa.sandbox.fullstack.prompt;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class SandboxDecisionAdjudicationService {

    private final SandboxDecisionClaimExtractor claimExtractor = new SandboxDecisionClaimExtractor();

    public SandboxDecisionAdjudication adjudicate(
            SandboxPromptReplayRound round,
            SandboxDecisionGoldCase goldCase,
            String reasoning) {
        List<String> claims = claimExtractor.extract(reasoning);
        Map<String, Object> eventMetadata = round.snapshot() != null && round.snapshot().event() != null
                ? round.snapshot().event().getMetadata()
                : Map.of();
        String prompt = round.snapshot() != null && round.snapshot().userPrompt() != null
                ? round.snapshot().userPrompt()
                : "";

        List<SandboxDecisionClaimAssessment> assessments = new ArrayList<>();
        int grounded = 0;
        int unsupported = 0;
        int contradicted = 0;
        for (String claim : claims) {
            SandboxDecisionClaimAssessment assessment = assessClaim(claim, eventMetadata, prompt);
            assessments.add(assessment);
            switch (assessment.verdict()) {
                case GROUNDED -> grounded++;
                case UNSUPPORTED -> unsupported++;
                case CONTRADICTED -> contradicted++;
            }
        }

        int total = assessments.size();
        double groundedPrecision = total == 0 ? 100.0d : percentage(grounded, total);
        double unsupportedRate = total == 0 ? 0.0d : percentage(unsupported, total);
        double contradictedRate = total == 0 ? 0.0d : percentage(contradicted, total);
        boolean uncertaintyLanguagePresent = claimExtractor.containsUncertaintyLanguage(reasoning);
        boolean requiredEvidenceCovered = goldCase.requiredEvidenceTokens().isEmpty()
                || coversRequiredEvidence(reasoning, prompt, goldCase.requiredEvidenceTokens());

        return new SandboxDecisionAdjudication(
                assessments,
                grounded,
                unsupported,
                contradicted,
                groundedPrecision,
                unsupportedRate,
                contradictedRate,
                uncertaintyLanguagePresent,
                requiredEvidenceCovered,
                SandboxDecisionBenchmarkSettings.adjudicationVersion());
    }

    private SandboxDecisionClaimAssessment assessClaim(
            String claim,
            Map<String, Object> eventMetadata,
            String prompt) {
        String normalized = claim.toLowerCase(Locale.ROOT);

        if (normalized.contains("new user")) {
            return booleanFactClaim(claim, eventMetadata.get("isNewUser"), true, "event.isNewUser");
        }
        if (normalized.contains("new device")) {
            return booleanFactClaim(claim, eventMetadata.get("isNewDevice"), true, "event.isNewDevice");
        }
        if (normalized.contains("new session")) {
            return booleanFactClaim(claim, eventMetadata.get("isNewSession"), true, "event.isNewSession");
        }
        if (normalized.contains("mfa")) {
            boolean expectTrue = !normalized.contains("not verified") && !normalized.contains("without mfa");
            return booleanFactClaim(claim, eventMetadata.get("mfaVerified"), expectTrue, "event.mfaVerified");
        }
        if (normalized.contains("high sensitivity")) {
            String actualSensitivity = eventMetadata.get("resourceSensitivity") == null
                    ? null
                    : String.valueOf(eventMetadata.get("resourceSensitivity")).trim();
            boolean grounded = actualSensitivity != null
                    && (actualSensitivity.equalsIgnoreCase("HIGH")
                    || actualSensitivity.equalsIgnoreCase("CRITICAL")
                    || actualSensitivity.equalsIgnoreCase("SECRET")
                    || actualSensitivity.equalsIgnoreCase("RESTRICTED"));
            return grounded
                    ? new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.GROUNDED, "event.resourceSensitivity matched high-sensitivity band")
                    : new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.CONTRADICTED, "event.resourceSensitivity contradicted");
        }
        if (normalized.contains("allow")) {
            return stringFactClaim(claim, eventMetadata.get("authorizationEffect"), "ALLOW", "event.authorizationEffect");
        }
        if (normalized.contains("baseline")) {
            boolean grounded = prompt.toLowerCase(Locale.ROOT).contains("baseline")
                    || prompt.toLowerCase(Locale.ROOT).contains("work profile");
            return grounded
                    ? new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.GROUNDED, "Prompt contains baseline/work-profile evidence.")
                    : new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.UNSUPPORTED, "Prompt does not expose baseline evidence.");
        }
        if (normalized.contains("history")) {
            boolean grounded = containsAny(
                    prompt.toLowerCase(Locale.ROOT),
                    prompt.toLowerCase(Locale.ROOT),
                    "history",
                    "historical",
                    "similar past events",
                    "observed work pattern",
                    "work profile");
            return grounded
                    ? new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.GROUNDED, "Prompt exposes history evidence.")
                    : new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.UNSUPPORTED, "Prompt does not expose history evidence.");
        }
        if (normalized.contains("session")) {
            boolean grounded = containsAny(
                    prompt.toLowerCase(Locale.ROOT),
                    prompt.toLowerCase(Locale.ROOT),
                    "session narrative",
                    "session age",
                    "previous path",
                    "session");
            return grounded
                    ? new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.GROUNDED, "Prompt exposes session evidence.")
                    : new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.UNSUPPORTED, "Prompt does not expose session evidence.");
        }
        if (normalized.contains("scope")) {
            boolean grounded = prompt.toLowerCase(Locale.ROOT).contains("scope");
            return grounded
                    ? new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.GROUNDED, "Prompt exposes scope evidence.")
                    : new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.UNSUPPORTED, "Prompt does not expose scope evidence.");
        }
        if (normalized.contains("previous")) {
            boolean grounded = prompt.toLowerCase(Locale.ROOT).contains("previouspath:");
            return grounded
                    ? new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.GROUNDED, "Prompt exposes previous-path evidence.")
                    : new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.UNSUPPORTED, "Prompt does not expose previous-path evidence.");
        }

        return new SandboxDecisionClaimAssessment(
                claim,
                SandboxDecisionClaimVerdict.UNSUPPORTED,
                "No explicit grounding rule matched this claim.");
    }

    private SandboxDecisionClaimAssessment booleanFactClaim(
            String claim,
            Object actualValue,
            boolean expectedValue,
            String factKey) {
        if (!(actualValue instanceof Boolean actual)) {
            return new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.UNSUPPORTED, factKey + " missing");
        }
        if (actual == expectedValue) {
            return new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.GROUNDED, factKey + " matched");
        }
        return new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.CONTRADICTED, factKey + " contradicted");
    }

    private SandboxDecisionClaimAssessment stringFactClaim(
            String claim,
            Object actualValue,
            String expectedValue,
            String factKey) {
        String actual = actualValue == null ? null : String.valueOf(actualValue).trim();
        if (actual == null || actual.isBlank()) {
            return new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.UNSUPPORTED, factKey + " missing");
        }
        if (expectedValue.equalsIgnoreCase(actual)) {
            return new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.GROUNDED, factKey + " matched");
        }
        return new SandboxDecisionClaimAssessment(claim, SandboxDecisionClaimVerdict.CONTRADICTED, factKey + " contradicted");
    }

    private boolean coversRequiredEvidence(String reasoning, String prompt, List<String> requiredEvidenceTokens) {
        String normalizedReasoning = normalizeEvidenceText(reasoning);
        String normalizedPrompt = normalizeEvidenceText(prompt);
        for (String token : requiredEvidenceTokens) {
            if (!containsEvidenceToken(normalizedReasoning, normalizedPrompt, token)) {
                return false;
            }
        }
        return true;
    }

    private boolean containsEvidenceToken(String normalizedReasoning, String normalizedPrompt, String token) {
        String normalizedToken = token == null ? "" : token.trim().toLowerCase(Locale.ROOT);
        if (normalizedToken.isBlank()) {
            return true;
        }
        return switch (normalizedToken) {
            case "previous path" -> containsAny(normalizedReasoning, normalizedPrompt, "previous path", "previouspath");
            case "high sensitivity" -> containsAny(normalizedReasoning, normalizedPrompt, "high sensitivity", "sensitivity high", "sensitivity: high");
            case "scope" -> containsAny(normalizedReasoning, normalizedPrompt, "scope", "role scope", "scopesummary", "scope summary");
            case "baseline" -> containsAny(normalizedReasoning, normalizedPrompt, "baseline", "work profile", "provisional baseline");
            case "history" -> containsAny(normalizedReasoning, normalizedPrompt, "history", "historical", "similar past events", "observed work pattern");
            case "session" -> containsAny(normalizedReasoning, normalizedPrompt, "session", "session narrative");
            case "sensitivity" -> containsAny(normalizedReasoning, normalizedPrompt, "sensitivity", "high sensitivity", "sensitivity high");
            default -> normalizedReasoning.contains(normalizedToken) || normalizedPrompt.contains(normalizedToken);
        };
    }

    private boolean containsAny(String reasoning, String prompt, String... candidates) {
        for (String candidate : candidates) {
            if ((reasoning != null && reasoning.contains(candidate)) || (prompt != null && prompt.contains(candidate))) {
                return true;
            }
        }
        return false;
    }

    private String normalizeEvidenceText(String text) {
        if (text == null || text.isBlank()) {
            return "";
        }
        return text.toLowerCase(Locale.ROOT)
                .replace("previouspath", "previous path")
                .replace("scopesummary", "scope summary")
                .replace("workprofilesummary", "work profile summary")
                .replace("sessionnarrative", "session narrative")
                .replace('\r', '\n');
    }

    private double percentage(int numerator, int denominator) {
        return denominator == 0 ? 0.0d : (numerator * 100.0d) / denominator;
    }
}
