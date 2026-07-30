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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecurityDecisionOutputParser {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {
    };
    private static final Pattern ACTION_LINE = Pattern.compile("(?im)^\\s*action\\s*[:=]\\s*([A-Za-z_-]+)\\s*$");
    private static final Pattern REASONING_LINE = Pattern.compile("(?im)^\\s*reasoning\\s*[:=]\\s*(.+?)\\s*$");
    private static final Pattern MITRE_LINE = Pattern.compile("(?im)^\\s*mitre\\s*[:=]\\s*(.+?)\\s*$");
    private static final Pattern RISK_LINE = Pattern.compile("(?im)^\\s*riskScore\\s*[:=]\\s*([0-9.]+)\\s*$");
    private static final Pattern CONFIDENCE_LINE = Pattern.compile("(?im)^\\s*confidence\\s*[:=]\\s*([0-9.]+)\\s*$");
    private static final Pattern CANONICAL_ACTION_TOKEN =
            Pattern.compile("(?i)(?<![A-Z])(?:ALLOW|CHALLENGE|BLOCK|ESCALATE)(?![A-Z])");
    private static final String FALLBACK_ACTION = "CHALLENGE";

    public SecurityDecisionResponseLite parse(String rawResponse, PipelineExecutionContext context) {
        String raw = rawResponse != null ? rawResponse : "";
        Set<String> repairedFields = new LinkedHashSet<>();
        Set<String> syntheticDefaultFields = new LinkedHashSet<>();
        String parseFailureCategory = firstNonBlank(
                context != null ? context.getMetadata("securityDecisionParseFailureCategory", String.class) : null,
                "NONE");
        boolean fallbackActionApplied = false;

        addMetadata(context, "securityDecisionParsingMode", "RAW_GUARDED");
        addMetadata(context, "securityDecisionRawOutputHash", sha256(raw));
        addMetadata(context, "securityDecisionRawOutputLength", raw.length());

        if (raw.isBlank()) {
            if ("NONE".equals(parseFailureCategory)) {
                parseFailureCategory = "EMPTY_RESPONSE";
            }
            fallbackActionApplied = true;
            repairedFields.add("action");
            SecurityDecisionResponseLite fallback = buildResponse(
                    FALLBACK_ACTION,
                    null,
                    null,
                    null,
                    null,
                    List.of());
            recordMetadata(
                    context,
                    false,
                    fallbackActionApplied,
                    repairedFields,
                    syntheticDefaultFields,
                    parseFailureCategory,
                    FALLBACK_ACTION);
            return fallback;
        }

        String jsonCandidate = extractJsonCandidate(raw);
        Map<String, Object> fields = readJsonObject(jsonCandidate);
        if (fields == null && raw.contains("{")) {
            parseFailureCategory = looksTruncated(jsonCandidate) ? "TRUNCATED_JSON" : "MALFORMED_JSON";
        }

        String extractedAction = firstNonBlank(
                asString(getCaseInsensitive(fields, "action")),
                extractQuotedField(raw, "action"),
                extractLine(ACTION_LINE, raw));
        addMetadata(context, "securityDecisionActionCandidate", summarizeActionCandidate(extractedAction));
        ActionResult actionResult = normalizeAction(extractedAction);
        if (actionResult.repaired()) {
            fallbackActionApplied = actionResult.fallbackApplied();
            repairedFields.add("action");
            if (fallbackActionApplied && "NONE".equals(parseFailureCategory)) {
                parseFailureCategory = actionResult.fallbackCategory();
            }
        }

        String extractedReasoning = firstNonBlank(
                asString(getCaseInsensitive(fields, "reasoning")),
                extractQuotedField(raw, "reasoning"),
                extractLine(REASONING_LINE, raw));
        String reasoning = normalizeReasoning(extractedReasoning);

        Double riskScore = firstNonNull(
                asDouble(getCaseInsensitive(fields, "riskScore")),
                extractNumberField(raw, "riskScore"),
                extractLineNumber(RISK_LINE, raw));
        if (riskScore != null) {
            riskScore = clamp(riskScore);
        }

        Double confidence = firstNonNull(
                asDouble(getCaseInsensitive(fields, "confidence")),
                extractNumberField(raw, "confidence"),
                extractLineNumber(CONFIDENCE_LINE, raw));
        if (confidence != null) {
            confidence = clamp(confidence);
        }

        String mitre = firstNonBlank(
                asString(getCaseInsensitive(fields, "mitre")),
                extractQuotedField(raw, "mitre"),
                extractLine(MITRE_LINE, raw));
        List<String> rawEvidenceRefs = firstNonNull(
                asStringList(getCaseInsensitive(fields, "evidenceRefs")),
                asStringList(getCaseInsensitive(fields, "evidenceReferences")),
                extractJsonStringArray(raw, "evidenceRefs"));
        List<String> evidenceRefs = normalizeEvidenceRefs(rawEvidenceRefs);

        boolean coreFieldsPresent = !actionResult.fallbackApplied();
        SecurityDecisionResponseLite parsed = buildResponse(actionResult.action(), reasoning, riskScore, confidence, mitre, evidenceRefs);
        recordMetadata(
                context,
                coreFieldsPresent,
                fallbackActionApplied,
                repairedFields,
                syntheticDefaultFields,
                parseFailureCategory,
                actionResult.fallbackApplied() ? actionResult.action() : null);
        return parsed;
    }

    private SecurityDecisionResponseLite buildResponse(
            String action,
            String reasoning,
            Double riskScore,
            Double confidence,
            String mitre,
            List<String> evidenceRefs) {
        SecurityDecisionResponseLite response = new SecurityDecisionResponseLite();
        response.setAction(action);
        response.setReasoning(reasoning);
        response.setRiskScore(riskScore);
        response.setConfidence(confidence);
        response.setMitre(mitre);
        response.setEvidenceRefs(evidenceRefs == null ? List.of() : List.copyOf(evidenceRefs));
        return response;
    }

    private void recordMetadata(
            PipelineExecutionContext context,
            boolean coreFieldsPresent,
            boolean fallbackActionApplied,
            Set<String> repairedFields,
            Set<String> syntheticDefaultFields,
            String parseFailureCategory,
            String fallbackAction) {
        addMetadata(context, "securityDecisionCoreFieldsPresent", coreFieldsPresent);
        addMetadata(context, "securityDecisionParsingFallbackApplied", fallbackActionApplied);
        addMetadata(context, "syntheticSecurityDecisionApplied", fallbackActionApplied);
        addMetadata(context, "llmDecisionPresent", !fallbackActionApplied);
        addMetadata(context, "securityDecisionFallbackApplied", fallbackActionApplied);
        addMetadata(context, "securityDecisionOutputRepairApplied", !repairedFields.isEmpty());
        addMetadata(context, "securityDecisionOutputRepairFields", new ArrayList<>(repairedFields));
        addMetadata(
                context,
                "securityDecisionSyntheticDefaultFields",
                new ArrayList<>(syntheticDefaultFields));
        addMetadata(context, "securityDecisionEvidenceRefsPresent", !repairedFields.contains("evidenceRefs"));
        addMetadata(context, "securityDecisionParseFailureCategory", parseFailureCategory);
        if (fallbackAction != null) {
            addMetadata(context, "securityDecisionFallbackAction", fallbackAction);
            addMetadata(context, "securityDecisionFallbackReason", parseFailureCategory);
        }
        if (!"NONE".equals(parseFailureCategory)) {
            addMetadata(context, "structuredOutputFailureCategory", parseFailureCategory);
        }
    }

    private Map<String, Object> readJsonObject(String candidate) {
        if (candidate == null || candidate.isBlank() || !candidate.trim().startsWith("{")) {
            return null;
        }
        try {
            return OBJECT_MAPPER.readValue(candidate, MAP_TYPE);
        } catch (Exception ignored) {
            return null;
        }
    }

    private List<String> asStringList(Object value) {
        if (value == null) {
            return null;
        }
        List<String> refs = new ArrayList<>();
        if (value instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                String text = asString(item);
                if (text != null) {
                    refs.add(text);
                }
            }
            return refs;
        }
        String text = asString(value);
        if (text == null) {
            return null;
        }
        if (text.contains(",")) {
            for (String token : text.split(",")) {
                String trimmed = firstNonBlank(token);
                if (trimmed != null) {
                    refs.add(trimmed);
                }
            }
        } else {
            refs.add(text);
        }
        return refs;
    }

    private List<String> extractJsonStringArray(String raw, String fieldName) {
        if (raw == null || fieldName == null) {
            return null;
        }
        Pattern pattern = Pattern.compile("(?is)\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*(\\[[^\\]]*\\])");
        Matcher matcher = pattern.matcher(raw);
        if (!matcher.find()) {
            return null;
        }
        try {
            return OBJECT_MAPPER.readValue(matcher.group(1), new TypeReference<List<String>>() {
            });
        } catch (Exception ignored) {
            return null;
        }
    }

    private List<String> normalizeEvidenceRefs(List<String> refs) {
        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        if (refs != null) {
            for (String ref : refs) {
                String text = firstNonBlank(ref);
                if (text == null) {
                    continue;
                }
                String canonical = canonicalEvidenceRef(text);
                if (canonical != null) {
                    normalized.add(canonical);
                }
            }
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

    private String extractJsonCandidate(String raw) {
        String cleaned = stripCodeFence(raw);
        int start = cleaned.indexOf('{');
        if (start < 0) {
            return cleaned;
        }
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = start; i < cleaned.length(); i++) {
            char ch = cleaned.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == '"') {
                inString = !inString;
                continue;
            }
            if (inString) {
                continue;
            }
            if (ch == '{') {
                depth++;
            } else if (ch == '}') {
                depth--;
                if (depth == 0) {
                    return cleaned.substring(start, i + 1);
                }
            }
        }
        return cleaned.substring(start);
    }

    private String stripCodeFence(String raw) {
        String cleaned = raw != null ? raw.trim() : "";
        if (cleaned.startsWith("```json")) {
            cleaned = cleaned.substring("```json".length()).trim();
        } else if (cleaned.startsWith("```")) {
            cleaned = cleaned.substring(3).trim();
            int firstNewline = cleaned.indexOf('\n');
            if (firstNewline > 0 && firstNewline < 20) {
                String firstLine = cleaned.substring(0, firstNewline).trim();
                if (firstLine.matches("^[a-zA-Z]+$")) {
                    cleaned = cleaned.substring(firstNewline + 1).trim();
                }
            }
        }
        if (cleaned.endsWith("```")) {
            cleaned = cleaned.substring(0, cleaned.length() - 3).trim();
        }
        return cleaned;
    }

    private boolean looksTruncated(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return false;
        }
        String trimmed = candidate.trim();
        return trimmed.startsWith("{") && !trimmed.endsWith("}");
    }

    private Object getCaseInsensitive(Map<String, Object> fields, String name) {
        if (fields == null || name == null) {
            return null;
        }
        for (Map.Entry<String, Object> entry : fields.entrySet()) {
            if (name.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue();
            }
        }
        return null;
    }

    private String extractQuotedField(String raw, String fieldName) {
        Pattern closed = Pattern.compile("(?is)\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
        Matcher closedMatcher = closed.matcher(raw);
        if (closedMatcher.find()) {
            return unescapeJsonString(closedMatcher.group(1));
        }
        Pattern partial = Pattern.compile("(?is)\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\"([^\"\\r\\n]*)");
        Matcher partialMatcher = partial.matcher(raw);
        if (partialMatcher.find()) {
            return unescapeJsonString(partialMatcher.group(1));
        }
        return null;
    }

    private Double extractNumberField(String raw, String fieldName) {
        String value = extractQuotedField(raw, fieldName);
        if (value == null) {
            Pattern numeric = Pattern.compile("(?is)\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*(-?[0-9]+(?:\\.[0-9]+)?)");
            Matcher matcher = numeric.matcher(raw);
            if (matcher.find()) {
                value = matcher.group(1);
            }
        }
        return parseDouble(value);
    }

    private String extractLine(Pattern pattern, String raw) {
        Matcher matcher = pattern.matcher(raw);
        return matcher.find() ? firstNonBlank(matcher.group(1)) : null;
    }

    private Double extractLineNumber(Pattern pattern, String raw) {
        return parseDouble(extractLine(pattern, raw));
    }

    private String unescapeJsonString(String value) {
        if (value == null) {
            return null;
        }
        try {
            return OBJECT_MAPPER.readValue("\"" + value.replace("\"", "\\\"") + "\"", String.class);
        } catch (Exception ignored) {
            return value;
        }
    }

    private ActionResult normalizeAction(String action) {
        if (action == null || action.isBlank()) {
            return new ActionResult(FALLBACK_ACTION, true, true, "ACTION_MISSING");
        }
        String normalized = action.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "ALLOW", "CHALLENGE", "BLOCK", "ESCALATE" ->
                    new ActionResult(normalized, false, false, null);
            case "DENY", "DENIED", "REJECT", "REJECTED" ->
                    new ActionResult("BLOCK", true, false, null);
            case "REVIEW" -> new ActionResult("ESCALATE", true, false, null);
            default -> normalizeDecoratedAction(normalized);
        };
    }

    private ActionResult normalizeDecoratedAction(String action) {
        Matcher matcher = CANONICAL_ACTION_TOKEN.matcher(action);
        Set<String> candidates = new LinkedHashSet<>();
        while (matcher.find()) {
            candidates.add(matcher.group().toUpperCase(Locale.ROOT));
        }
        if (candidates.size() == 1) {
            return new ActionResult(candidates.iterator().next(), true, false, null);
        }
        return new ActionResult(FALLBACK_ACTION, true, true, "ACTION_FORMAT_INVALID");
    }

    private String summarizeActionCandidate(String action) {
        String normalized = normalizeReasoning(action);
        if (normalized == null || normalized.length() <= 64) {
            return normalized;
        }
        return normalized.substring(0, 64);
    }

    private Double asDouble(Object value) {
        if (value instanceof Number number) {
            double candidate = number.doubleValue();
            return Double.isFinite(candidate) ? candidate : null;
        }
        return parseDouble(asString(value));
    }

    private Double parseDouble(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            double parsed = Double.parseDouble(value.trim());
            return Double.isFinite(parsed) ? parsed : null;
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private String asString(Object value) {
        if (value == null) {
            return null;
        }
        return firstNonBlank(String.valueOf(value));
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.trim().isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    @SafeVarargs
    private final <T> T firstNonNull(T... values) {
        if (values == null) {
            return null;
        }
        for (T value : values) {
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private String normalizeReasoning(String reasoning) {
        if (reasoning == null) {
            return null;
        }
        return reasoning.replaceAll("\\s+", " ").trim();
    }

    private Double clamp(Double value) {
        if (value == null) {
            return null;
        }
        return Math.max(0.0d, Math.min(1.0d, value));
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((value != null ? value : "").getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder("sha256:");
            for (byte b : hash) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (Exception ignored) {
            return "sha256:unavailable";
        }
    }

    private void addMetadata(PipelineExecutionContext context, String key, Object value) {
        if (context != null) {
            context.addMetadata(key, value);
        }
    }

    private record ActionResult(
            String action,
            boolean repaired,
            boolean fallbackApplied,
            String fallbackCategory) {
    }
}
