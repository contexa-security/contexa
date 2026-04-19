package io.contexa.contexacore.std.pipeline.processor;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;

import java.util.Locale;

public class SecurityDecisionResponseProcessor implements DomainResponseProcessor {

    private static final int MAX_REASONING_WORDS = 40;

    @Override
    public boolean supports(String templateKey) {
        return SecurityDecisionRequest.TEMPLATE_TYPE.name().equals(templateKey);
    }

    @Override
    public boolean supportsType(Class<?> responseType) {
        return SecurityDecisionResponseLite.class.equals(responseType);
    }

    @Override
    public Object wrapResponse(Object parsedData, PipelineExecutionContext context) {
        if (parsedData instanceof SecurityDecisionResponse fullResponse) {
            return fullResponse;
        }
        if (!(parsedData instanceof SecurityDecisionResponseLite liteResponse)) {
            throw new IllegalArgumentException(
                    "Expected SecurityDecisionResponseLite but got: "
                            + (parsedData != null ? parsedData.getClass().getName() : "null"));
        }
        return SecurityDecisionResponse.fromLite(normalizeAndValidate(liteResponse));
    }

    @Override
    public int getOrder() {
        return 15;
    }

    private SecurityDecisionResponseLite normalizeAndValidate(SecurityDecisionResponseLite lite) {
        SecurityDecisionResponseLite normalized = new SecurityDecisionResponseLite();
        Double normalizedRiskScore = normalizeNumericScore(lite.getRiskScore(), "riskScore");
        Double normalizedConfidence = normalizeNumericScore(lite.getConfidence(), "confidence");
        String normalizedAction = normalizeAction(lite.getAction());
        normalized.setRiskScore(normalizedRiskScore);
        normalized.setConfidence(normalizedConfidence);
        normalized.setAction(normalizedAction);
        normalized.setReasoning(normalizeReasoning(lite.getReasoning()));
        normalized.setMitre(normalizeMitre(lite.getMitre()));
        validateSemanticConsistency(normalizedAction, normalizedRiskScore);
        return normalized;
    }

    private Double normalizeNumericScore(Double score, String fieldName) {
        if (score == null || !Double.isFinite(score)) {
            throw new IllegalArgumentException("Security decision field is missing or invalid: " + fieldName);
        }
        return Math.max(0.0d, Math.min(1.0d, score));
    }

    private String normalizeAction(String action) {
        if (action == null || action.isBlank()) {
            throw new IllegalArgumentException("Security decision field is missing: action");
        }
        String normalized = action.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "ALLOW", "CHALLENGE", "BLOCK", "ESCALATE" -> normalized;
            case "DENY", "DENIED", "REJECT", "REJECTED" -> "BLOCK";
            case "REVIEW" -> "ESCALATE";
            default -> throw new IllegalArgumentException("Security decision action is invalid: " + action);
        };
    }

    private String normalizeReasoning(String reasoning) {
        if (reasoning == null || reasoning.isBlank()) {
            throw new IllegalArgumentException("Security decision field is missing: reasoning");
        }
        String normalized = reasoning.replaceAll("\\s+", " ").trim();
        if (containsMultipleSentences(normalized)) {
            throw new IllegalArgumentException("Security decision reasoning must be exactly one sentence.");
        }
        if (countWords(normalized) > MAX_REASONING_WORDS) {
            throw new IllegalArgumentException("Security decision reasoning exceeds " + MAX_REASONING_WORDS + " words.");
        }
        return normalized.length() > 280 ? normalized.substring(0, 280).trim() : normalized;
    }

    private String normalizeMitre(String mitre) {
        if (mitre == null || mitre.isBlank()) {
            throw new IllegalArgumentException("Security decision field is missing: mitre");
        }
        return mitre.trim();
    }

    private void validateSemanticConsistency(String action, Double riskScore) {
        if ("ALLOW".equals(action) && riskScore != null && riskScore >= 0.95d) {
            throw new IllegalArgumentException("Security decision action ALLOW is inconsistent with an extreme risk score.");
        }
    }

    private boolean containsMultipleSentences(String reasoning) {
        String trimmed = reasoning != null ? reasoning.trim() : "";
        if (trimmed.isEmpty()) {
            return false;
        }
        String normalized = trimmed.replaceAll("[!?]+", ".").replaceAll("\\.+", ".");
        if (!normalized.contains(".")) {
            return false;
        }
        String[] sentences = normalized.split("\\.\\s+");
        return sentences.length > 1;
    }

    private int countWords(String reasoning) {
        if (reasoning == null || reasoning.isBlank()) {
            return 0;
        }
        return reasoning.trim().split("\\s+").length;
    }
}
