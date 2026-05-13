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
    private static final String FALLBACK_ACTION = "CHALLENGE";
    private static final String DEFAULT_MITRE = "UNKNOWN";

    public SecurityDecisionResponseLite parse(String rawResponse, PipelineExecutionContext context) {
        String raw = rawResponse != null ? rawResponse : "";
        Set<String> repairedFields = new LinkedHashSet<>();
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
            repairedFields.addAll(List.of("action", "reasoning", "riskScore", "confidence", "mitre"));
            SecurityDecisionResponseLite fallback = buildResponse(
                    FALLBACK_ACTION,
                    defaultReasoning(FALLBACK_ACTION),
                    defaultNumericScore("riskScore", FALLBACK_ACTION),
                    defaultNumericScore("confidence", FALLBACK_ACTION),
                    DEFAULT_MITRE);
            recordMetadata(context, false, fallbackActionApplied, repairedFields, parseFailureCategory, FALLBACK_ACTION);
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
        ActionResult actionResult = normalizeAction(extractedAction);
        if (actionResult.repaired()) {
            fallbackActionApplied = actionResult.fallbackApplied();
            repairedFields.add("action");
            if (fallbackActionApplied && "NONE".equals(parseFailureCategory)) {
                parseFailureCategory = "MISSING_ACTION";
            }
        }

        String extractedReasoning = firstNonBlank(
                asString(getCaseInsensitive(fields, "reasoning")),
                extractQuotedField(raw, "reasoning"),
                extractLine(REASONING_LINE, raw));
        boolean reasoningPresent = extractedReasoning != null;
        String reasoning = extractedReasoning;
        if (reasoning == null) {
            repairedFields.add("reasoning");
            reasoning = defaultReasoning(actionResult.action());
        }
        reasoning = normalizeReasoning(reasoning);

        Double riskScore = firstNonNull(
                asDouble(getCaseInsensitive(fields, "riskScore")),
                extractNumberField(raw, "riskScore"),
                extractLineNumber(RISK_LINE, raw));
        if (riskScore == null) {
            repairedFields.add("riskScore");
            riskScore = defaultNumericScore("riskScore", actionResult.action());
        } else {
            riskScore = clamp(riskScore);
        }

        Double confidence = firstNonNull(
                asDouble(getCaseInsensitive(fields, "confidence")),
                extractNumberField(raw, "confidence"),
                extractLineNumber(CONFIDENCE_LINE, raw));
        if (confidence == null) {
            repairedFields.add("confidence");
            confidence = defaultNumericScore("confidence", actionResult.action());
        } else {
            confidence = clamp(confidence);
        }

        String mitre = firstNonBlank(
                asString(getCaseInsensitive(fields, "mitre")),
                extractQuotedField(raw, "mitre"),
                extractLine(MITRE_LINE, raw));
        if (mitre == null) {
            repairedFields.add("mitre");
            mitre = DEFAULT_MITRE;
        }

        boolean coreFieldsPresent = !actionResult.fallbackApplied() && reasoningPresent;
        SecurityDecisionResponseLite parsed = buildResponse(actionResult.action(), reasoning, riskScore, confidence, mitre);
        recordMetadata(context, coreFieldsPresent, fallbackActionApplied, repairedFields, parseFailureCategory, actionResult.fallbackApplied() ? actionResult.action() : null);
        return parsed;
    }

    private SecurityDecisionResponseLite buildResponse(
            String action,
            String reasoning,
            Double riskScore,
            Double confidence,
            String mitre) {
        SecurityDecisionResponseLite response = new SecurityDecisionResponseLite();
        response.setAction(action);
        response.setReasoning(reasoning);
        response.setRiskScore(riskScore);
        response.setConfidence(confidence);
        response.setMitre(mitre);
        return response;
    }

    private void recordMetadata(
            PipelineExecutionContext context,
            boolean coreFieldsPresent,
            boolean fallbackActionApplied,
            Set<String> repairedFields,
            String parseFailureCategory,
            String fallbackAction) {
        addMetadata(context, "securityDecisionCoreFieldsPresent", coreFieldsPresent);
        addMetadata(context, "securityDecisionParsingFallbackApplied", fallbackActionApplied);
        addMetadata(context, "syntheticSecurityDecisionApplied", fallbackActionApplied);
        addMetadata(context, "llmDecisionPresent", !fallbackActionApplied);
        addMetadata(context, "securityDecisionFallbackApplied", fallbackActionApplied);
        addMetadata(context, "securityDecisionOutputRepairApplied", !repairedFields.isEmpty());
        addMetadata(context, "securityDecisionOutputRepairFields", new ArrayList<>(repairedFields));
        addMetadata(context, "securityDecisionParseFailureCategory", parseFailureCategory);
        if (fallbackAction != null) {
            addMetadata(context, "securityDecisionFallbackAction", fallbackAction);
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
            return new ActionResult(FALLBACK_ACTION, true, true);
        }
        String normalized = action.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "ALLOW", "CHALLENGE", "BLOCK", "ESCALATE" -> new ActionResult(normalized, false, false);
            case "DENY", "DENIED", "REJECT", "REJECTED" -> new ActionResult("BLOCK", true, false);
            case "REVIEW" -> new ActionResult("ESCALATE", true, false);
            default -> new ActionResult(FALLBACK_ACTION, true, true);
        };
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
            default -> 0.55d;
        };
    }

    private String defaultReasoning(String action) {
        return switch (action) {
            case "ALLOW" -> "Decision metadata was incomplete; action remained ALLOW.";
            case "ESCALATE" -> "Decision metadata was incomplete; escalation remains required.";
            case "BLOCK" -> "Decision metadata was incomplete; block remains required.";
            default -> "Model output was incomplete; challenge is required.";
        };
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

    private record ActionResult(String action, boolean repaired, boolean fallbackApplied) {
    }
}
