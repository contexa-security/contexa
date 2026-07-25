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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class SecurityDecisionResponseProcessor implements DomainResponseProcessor {

    private static final int MAX_REASONING_WORDS = 40;
    private static final int MAX_REASONING_CHARS = 280;

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
            SecurityDecisionResponseLite normalized = normalizeAndValidate(toLite(fullResponse), context);
            applyNormalized(fullResponse, normalized);
            Map<String, String> fieldProvenance = buildFieldProvenance(normalized);
            fullResponse.setFieldProvenance(fieldProvenance);
            fullResponse.withMetadata("securityDecisionFieldProvenance", fieldProvenance);
            return fullResponse;
        }
        if (!(parsedData instanceof SecurityDecisionResponseLite liteResponse)) {
            throw new IllegalArgumentException(
                    "Expected SecurityDecisionResponseLite but got: "
                            + (parsedData != null ? parsedData.getClass().getName() : "null"));
        }
        SecurityDecisionResponseLite normalized = normalizeAndValidate(liteResponse, context);
        SecurityDecisionResponse response = SecurityDecisionResponse.fromLite(normalized);
        Map<String, String> fieldProvenance = buildFieldProvenance(normalized);
        response.setFieldProvenance(fieldProvenance);
        response.withMetadata("securityDecisionFieldProvenance", fieldProvenance);
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
        Double normalizedRiskScore = normalizeNumericScore(lite.getRiskScore(), "riskScore", repairedFields);
        Double normalizedConfidence = normalizeNumericScore(lite.getConfidence(), "confidence", repairedFields);
        normalized.setRiskScore(normalizedRiskScore);
        normalized.setConfidence(normalizedConfidence);
        normalized.setAction(normalizedAction);
        String normalizedReasoning = normalizeReasoning(lite.getReasoning(), repairedFields);
        normalized.setReasoning(normalizedReasoning);
        normalized.setMitre(normalizeMitre(lite.getMitre(), repairedFields));
        normalized.setEvidenceRefs(normalizeEvidenceRefs(lite.getEvidenceRefs(), repairedFields));
        recordSemanticConsistency(context, normalizedAction, normalizedRiskScore);
        recordRepairMetadata(context, repairedFields);
        return normalized;
    }

    private Map<String, String> buildFieldProvenance(SecurityDecisionResponseLite response) {
        Map<String, String> provenance = new LinkedHashMap<>();
        provenance.put("riskScore", response.getRiskScore() == null ? "ABSENT" : "MODEL");
        provenance.put("confidence", response.getConfidence() == null ? "ABSENT" : "MODEL");
        provenance.put("reasoning", response.getReasoning() == null ? "ABSENT" : "MODEL");
        provenance.put("mitre", response.getMitre() == null ? "ABSENT" : "MODEL");
        provenance.put("evidenceRefs", response.getEvidenceRefs() == null || response.getEvidenceRefs().isEmpty()
                ? "ABSENT"
                : "MODEL");
        return Map.copyOf(provenance);
    }

    private SecurityDecisionResponseLite toLite(SecurityDecisionResponse response) {
        SecurityDecisionResponseLite lite = new SecurityDecisionResponseLite();
        lite.setRiskScore(response.getRiskScore());
        lite.setConfidence(response.getConfidence());
        lite.setAction(response.getAction());
        lite.setReasoning(response.getReasoning());
        lite.setMitre(response.getMitre());
        lite.setEvidenceRefs(response.getEvidenceRefs());
        return lite;
    }

    private void applyNormalized(SecurityDecisionResponse response, SecurityDecisionResponseLite normalized) {
        response.setRiskScore(normalized.getRiskScore());
        response.setConfidence(normalized.getConfidence());
        response.setAction(normalized.getAction());
        response.setReasoning(normalized.getReasoning());
        response.setMitre(normalized.getMitre());
        response.setEvidenceRefs(normalized.getEvidenceRefs());
    }

    private Double normalizeNumericScore(Double score, String fieldName, List<String> repairedFields) {
        if (score == null) {
            return null;
        }
        if (!Double.isFinite(score)) {
            repairedFields.add(fieldName);
            return null;
        }
        double normalized = Math.max(0.0d, Math.min(1.0d, score));
        if (Double.compare(normalized, score) != 0) {
            repairedFields.add(fieldName);
        }
        return normalized;
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

    private String normalizeReasoning(String reasoning, List<String> repairedFields) {
        if (reasoning == null || reasoning.isBlank()) {
            return null;
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
        return normalized.isBlank() ? null : normalized;
    }

    private List<String> normalizeEvidenceRefs(List<String> evidenceRefs, List<String> repairedFields) {
        if (evidenceRefs == null || evidenceRefs.isEmpty()) {
            return List.of();
        }
        List<String> normalized = new ArrayList<>();
        for (String ref : evidenceRefs) {
            if (ref == null || ref.isBlank()) {
                continue;
            }
            String canonical = canonicalEvidenceRef(ref);
            if (canonical != null && !normalized.contains(canonical)) {
                normalized.add(canonical);
            }
        }
        if (normalized.size() != evidenceRefs.size()) {
            repairedFields.add("evidenceRefs");
        }
        return List.copyOf(normalized);
    }

    private String canonicalEvidenceRef(String ref) {
        String raw = ref.trim().toLowerCase(Locale.ROOT);
        if (raw.contains(".") || raw.contains("_")) {
            String detailed = raw
                    .replace(' ', '.')
                    .replace('-', '.');
            if (detailed.matches("[a-z0-9]+([._][a-z0-9]+)+")) {
                return detailed;
            }
        }
        String normalized = raw
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

    private String normalizeMitre(String mitre, List<String> repairedFields) {
        if (mitre == null || mitre.isBlank()) {
            return null;
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

    private int countWords(String reasoning) {
        if (reasoning == null || reasoning.isBlank()) {
            return 0;
        }
        return reasoning.trim().split("\\s+").length;
    }
}
