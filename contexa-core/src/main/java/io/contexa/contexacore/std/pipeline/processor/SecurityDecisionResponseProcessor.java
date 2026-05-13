package io.contexa.contexacore.std.pipeline.processor;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class SecurityDecisionResponseProcessor implements DomainResponseProcessor {

    private static final int MAX_REASONING_WORDS = 40;
    private static final int MAX_REASONING_CHARS = 280;
    private static final String DEFAULT_MITRE = "UNKNOWN";

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
        SecurityDecisionResponseLite liteResponse = toLiteResponse(parsedData);
        if (liteResponse == null) {
            throw new IllegalArgumentException(
                    "Expected SecurityDecisionResponseLite but got: "
                            + (parsedData != null ? parsedData.getClass().getName() : "null"));
        }
        return SecurityDecisionResponse.fromLite(normalizeAndValidate(liteResponse, context));
    }

    @Override
    public int getOrder() {
        return 15;
    }

    private SecurityDecisionResponseLite normalizeAndValidate(SecurityDecisionResponseLite lite, PipelineExecutionContext context) {
        SecurityDecisionResponseLite normalized = new SecurityDecisionResponseLite();
        List<String> repairedFields = new ArrayList<>();
        String normalizedAction = normalizeAction(lite.getAction());
        Double normalizedRiskScore = normalizeNumericScore(lite.getRiskScore(), "riskScore", normalizedAction, repairedFields);
        Double normalizedConfidence = normalizeNumericScore(lite.getConfidence(), "confidence", normalizedAction, repairedFields);
        normalized.setRiskScore(normalizedRiskScore);
        normalized.setConfidence(normalizedConfidence);
        normalized.setAction(normalizedAction);
        normalized.setReasoning(normalizeReasoning(lite.getReasoning(), normalizedAction, repairedFields));
        normalized.setMitre(normalizeMitre(lite.getMitre(), repairedFields));
        recordSemanticConsistency(context, normalizedAction, normalizedRiskScore);
        recordRepairMetadata(context, repairedFields);
        return normalized;
    }

    private SecurityDecisionResponseLite toLiteResponse(Object parsedData) {
        if (parsedData instanceof SecurityDecisionResponseLite liteResponse) {
            return liteResponse;
        }
        if (!(parsedData instanceof Map<?, ?> map)) {
            return null;
        }
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setAction(asString(map.get("action")));
        lite.setReasoning(asString(map.get("reasoning")));
        lite.setMitre(asString(map.get("mitre")));
        lite.setRiskScore(asDouble(map.get("riskScore")));
        lite.setConfidence(asDouble(map.get("confidence")));
        return lite;
    }

    private String asString(Object value) {
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isBlank() ? null : text;
    }

    private Double asDouble(Object value) {
        if (value instanceof Number number) {
            double candidate = number.doubleValue();
            return Double.isFinite(candidate) ? candidate : null;
        }
        if (value instanceof String text) {
            String normalized = text.trim();
            if (normalized.isBlank()) {
                return null;
            }
            try {
                double candidate = Double.parseDouble(normalized);
                return Double.isFinite(candidate) ? candidate : null;
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private Double normalizeNumericScore(Double score, String fieldName, String action, List<String> repairedFields) {
        if (score == null || !Double.isFinite(score)) {
            repairedFields.add(fieldName);
            return defaultNumericScore(fieldName, action);
        }
        return Math.max(0.0d, Math.min(1.0d, score));
    }

    private Double defaultNumericScore(String fieldName, String action) {
        return switch (fieldName) {
            case "riskScore" -> switch (action) {
                case "ALLOW" -> 0.20d;
                case "CHALLENGE" -> 0.55d;
                case "ESCALATE" -> 0.75d;
                case "BLOCK" -> 0.90d;
                default -> 0.60d;
            };
            case "confidence" -> switch (action) {
                case "ALLOW", "BLOCK" -> 0.70d;
                case "CHALLENGE" -> 0.60d;
                case "ESCALATE" -> 0.55d;
                default -> 0.55d;
            };
            default -> throw new IllegalArgumentException("Unknown security decision numeric field: " + fieldName);
        };
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

    private String normalizeReasoning(String reasoning, String action, List<String> repairedFields) {
        if (reasoning == null || reasoning.isBlank()) {
            repairedFields.add("reasoning");
            return defaultReasoning(action);
        }
        String normalized = reasoning.replaceAll("\\s+", " ").trim();
        if (containsMultipleSentences(normalized)) {
            repairedFields.add("reasoning");
            normalized = firstSentence(normalized);
        }
        if (countWords(normalized) > MAX_REASONING_WORDS) {
            repairedFields.add("reasoning");
            normalized = firstWords(normalized, MAX_REASONING_WORDS);
        }
        if (normalized.length() > MAX_REASONING_CHARS) {
            repairedFields.add("reasoning");
            normalized = normalized.substring(0, MAX_REASONING_CHARS).trim();
        }
        return normalized.isBlank() ? defaultReasoning(action) : normalized;
    }

    private String normalizeMitre(String mitre, List<String> repairedFields) {
        if (mitre == null || mitre.isBlank()) {
            repairedFields.add("mitre");
            return DEFAULT_MITRE;
        }
        return mitre.trim();
    }

    private void recordSemanticConsistency(PipelineExecutionContext context, String action, Double riskScore) {
        if ("ALLOW".equals(action) && riskScore != null && riskScore >= 0.95d) {
            if (context != null) {
                context.addMetadata("securityDecisionSemanticWarning", "ALLOW_WITH_EXTREME_RISK_SCORE");
            }
        }
    }

    private void recordRepairMetadata(PipelineExecutionContext context, List<String> repairedFields) {
        if (context == null || repairedFields.isEmpty()) {
            return;
        }
        context.addMetadata("securityDecisionPostprocessingRepairApplied", true);
        context.addMetadata("securityDecisionPostprocessingRepairFields", List.copyOf(repairedFields));
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

    private String firstSentence(String reasoning) {
        String normalized = reasoning.replaceAll("[!?]+", ".").replaceAll("\\.+", ".");
        int end = normalized.indexOf(". ");
        if (end < 0 && normalized.endsWith(".")) {
            end = normalized.length() - 1;
        }
        if (end <= 0) {
            return reasoning;
        }
        return normalized.substring(0, end).trim();
    }

    private String firstWords(String reasoning, int maxWords) {
        if (reasoning == null || reasoning.isBlank()) {
            return "";
        }
        String[] words = reasoning.trim().split("\\s+");
        if (words.length <= maxWords) {
            return reasoning.trim();
        }
        return String.join(" ", java.util.Arrays.copyOf(words, maxWords));
    }

    private String defaultReasoning(String action) {
        return switch (action) {
            case "ALLOW" -> "Decision metadata was incomplete; action remained ALLOW.";
            case "CHALLENGE" -> "Decision metadata was incomplete; challenge remains required.";
            case "ESCALATE" -> "Decision metadata was incomplete; escalation remains required.";
            case "BLOCK" -> "Decision metadata was incomplete; block remains required.";
            default -> "Decision metadata was incomplete.";
        };
    }

    private int countWords(String reasoning) {
        if (reasoning == null || reasoning.isBlank()) {
            return 0;
        }
        return reasoning.trim().split("\\s+").length;
    }
}
