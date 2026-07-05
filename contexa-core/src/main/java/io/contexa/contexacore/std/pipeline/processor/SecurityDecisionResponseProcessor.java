/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.pipeline.processor;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponse;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

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
        if (!(parsedData instanceof SecurityDecisionResponseLite liteResponse)) {
            throw new IllegalArgumentException(
                    "Expected SecurityDecisionResponseLite but got: "
                            + (parsedData != null ? parsedData.getClass().getName() : "null"));
        }
        SecurityDecisionResponseLite normalized = normalizeAndValidate(liteResponse, context);
        SecurityDecisionResponse response = SecurityDecisionResponse.fromLite(normalized);
        if (normalized.getEvidenceRefs() != null && !normalized.getEvidenceRefs().isEmpty()) {
            response.withMetadata("evidenceRefs", normalized.getEvidenceRefs());
        }
        return response;
    }

    @Override
    public int getOrder() {
        return 15;
    }

    private SecurityDecisionResponseLite normalizeAndValidate(SecurityDecisionResponseLite lite, PipelineExecutionContext context) {
        SecurityDecisionResponseLite normalized = new SecurityDecisionResponseLite();
        List<String> repairedFields = new ArrayList<>();
        String normalizedAction = normalizeAction(lite.getAction(), repairedFields, context);
        Double normalizedRiskScore = normalizeNumericScore(lite.getRiskScore(), "riskScore", normalizedAction, repairedFields);
        Double normalizedConfidence = normalizeNumericScore(lite.getConfidence(), "confidence", normalizedAction, repairedFields);
        normalized.setRiskScore(normalizedRiskScore);
        normalized.setConfidence(normalizedConfidence);
        normalized.setAction(normalizedAction);
        String normalizedReasoning = normalizeReasoning(lite.getReasoning(), normalizedAction, repairedFields);
        normalized.setReasoning(normalizedReasoning);
        normalized.setMitre(normalizeMitre(lite.getMitre(), repairedFields));
        normalized.setEvidenceRefs(normalizeEvidenceRefs(lite.getEvidenceRefs(), normalizedReasoning, repairedFields));
        recordSemanticConsistency(context, normalizedAction, normalizedRiskScore);
        recordRepairMetadata(context, repairedFields);
        return normalized;
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

    private String normalizeAction(String action, List<String> repairedFields, PipelineExecutionContext context) {
        if (action == null || action.isBlank()) {
            repairedFields.add("action");
            recordActionFallback(context, "MISSING_ACTION");
            return "CHALLENGE";
        }
        String normalized = action.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "ALLOW", "CHALLENGE", "BLOCK", "ESCALATE" -> normalized;
            case "DENY", "DENIED", "REJECT", "REJECTED" -> "BLOCK";
            case "REVIEW" -> "ESCALATE";
            default -> {
                repairedFields.add("action");
                recordActionFallback(context, "INVALID_ACTION");
                yield "CHALLENGE";
            }
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

    private List<String> normalizeEvidenceRefs(List<String> evidenceRefs, String reasoning, List<String> repairedFields) {
        List<String> normalized = new ArrayList<>();
        if (evidenceRefs != null) {
            for (String ref : evidenceRefs) {
                if (ref == null || ref.isBlank()) {
                    continue;
                }
                String canonical = canonicalEvidenceRef(ref);
                if (canonical != null && !normalized.contains(canonical)) {
                    normalized.add(canonical);
                }
            }
        }
        if (mentionsSensitivityEvidence(reasoning) && !normalized.contains("sensitivity")) {
            normalized.add("sensitivity");
        }
        if (mentionsBaselineEvidence(reasoning) && !normalized.contains("baseline")) {
            normalized.add("baseline");
        }
        if (normalized.isEmpty()) {
            repairedFields.add("evidenceRefs");
        }
        return normalized;
    }

    private String canonicalEvidenceRef(String ref) {
        String normalized = ref.trim().toLowerCase(Locale.ROOT)
                .replace('_', '-')
                .replace(' ', '-');
        return switch (normalized) {
            case "baseline", "work-profile", "history", "normal-behavior" -> "baseline";
            case "sensitivity", "high-sensitivity", "resource-sensitivity", "critical-sensitivity", "business-impact" -> "sensitivity";
            case "authorization", "authz", "auth", "authorization-effect", "permission", "permissions", "mfa" -> "authorization";
            case "resource", "session", "device", "location", "rag", "threat", "approval", "delegation" -> normalized;
            default -> null;
        };
    }

    private boolean mentionsSensitivityEvidence(String reasoning) {
        if (reasoning == null || reasoning.isBlank()) {
            return false;
        }
        String lower = reasoning.toLowerCase(Locale.ROOT);
        return lower.contains("high-sensitivity")
                || lower.contains("high sensitivity")
                || lower.contains("sensitive-resource")
                || lower.contains("sensitive resource")
                || lower.contains("sensitive res")
                || lower.contains("resource sensitivity")
                || lower.contains("critical resource")
                || lower.contains("critical sensitivity")
                || lower.contains("business impact");
    }

    private boolean mentionsBaselineEvidence(String reasoning) {
        if (reasoning == null || reasoning.isBlank()) {
            return false;
        }
        String lower = reasoning.toLowerCase(Locale.ROOT);
        return lower.contains("limited baseline")
                || lower.contains("baseline")
                || lower.contains("work profile")
                || lower.contains("work-profile")
                || lower.contains("history")
                || lower.contains("historical");
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

    private void recordActionFallback(PipelineExecutionContext context, String reason) {
        if (context == null) {
            return;
        }
        context.addMetadata("securityDecisionParsingFallbackApplied", true);
        context.addMetadata("securityDecisionFallbackApplied", true);
        context.addMetadata("securityDecisionFallbackAction", "CHALLENGE");
        context.addMetadata("securityDecisionFallbackReason", reason);
        context.addMetadata("syntheticSecurityDecisionApplied", true);
        context.addMetadata("llmDecisionPresent", false);
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
        return String.join(" ", Arrays.copyOf(words, maxWords));
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
