package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class PromptComparisonValueInterpreter {

    private static final Set<String> ACTUAL_PROBLEM_STATES = Set.of(
            "PROMPT_MISSING",
            "FACT_MISSING",
            "VALUE_MISMATCH",
            "CONTRACT_MISMATCH",
            "REQUIRED_MISSING",
            "CONDITIONAL_REQUIRED_MISSING",
            "UNKNOWN_WITHOUT_REASON",
            "PROMPT_COMPACTED_SIGNAL",
            "PRODUCER_NOT_AVAILABLE",
            "PROVISIONAL_EVIDENCE",
            "NO_DIRECT_COMPARABLE",
            "BASELINE_MISMATCH_SIGNAL");

    private final PromptQualityMessageResolver messageResolver;

    public PromptComparisonValueInterpreter(PromptQualityMessageResolver messageResolver) {
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    public String promptProblemState(Map<?, ?> row) {
        String explicit = firstNonBlank(value(row.get("problemType")), "");
        if (StringUtils.hasText(explicit)) {
            return normalized(explicit);
        }
        String fieldState = normalized(value(row.get("fieldState")));
        return actualProblemState(fieldState) ? fieldState : comparisonStateFromFieldState(fieldState);
    }

    public boolean actualProblemState(String state) {
        return ACTUAL_PROBLEM_STATES.contains(normalized(state));
    }

    public List<String> metricCodes(Map<?, ?> row) {
        return stringList(row.get("metricCodes"));
    }

    public String projectionState(String projectionState, String requiredLevel) {
        String level = normalized(requiredLevel);
        String state = normalized(projectionState);
        if (!"P0_REQUIRED".equals(level)
                && Set.of("MISSING_IN_PROMPT", "MISSING_IN_EVIDENCE", "MISSING_IN_BOTH", "DECLARED_ABSENCE")
                .contains(state)) {
            return "NOT_APPLICABLE";
        }
        return switch (state) {
            case "PRESENT" -> "MATCH";
            case "MISSING_IN_PROMPT" -> "PROMPT_MISSING";
            case "MISSING_IN_EVIDENCE" -> "FACT_MISSING";
            case "MISSING_IN_BOTH", "DECLARED_ABSENCE" -> "NOT_APPLICABLE";
            case "VALUE_MISMATCH" -> "VALUE_MISMATCH";
            default -> "VALUE_MISMATCH";
        };
    }

    public String evidenceSource(Map<?, ?> row) {
        String section = value(row.get("evidenceSection"));
        String path = value(row.get("evidencePath"));
        if (!StringUtils.hasText(section)) {
            return path;
        }
        String normalizedSection = section.toLowerCase(Locale.ROOT).replace('_', '.');
        return StringUtils.hasText(path)
                ? "sealedEvidence." + normalizedSection + "." + path
                : "sealedEvidence." + normalizedSection;
    }

    public String promptLocation(Map<?, ?> row) {
        String explicit = firstNonBlank(value(row.get("promptLocation")), value(row.get("promptSection")));
        if (StringUtils.hasText(explicit)) {
            return explicit;
        }
        String evidenceSection = normalized(value(row.get("evidenceSection")));
        return switch (evidenceSection) {
            case "REQUEST_FACTS", "AUTH_STATE", "DECISION" -> "userPrompt.requestContext";
            case "BASELINE_SNAPSHOT", "CANONICAL_CONTEXT" -> "userPrompt.baseline";
            case "RAG_RESULTS" -> "userPrompt.rag";
            case "PROMPT_EXECUTION_METADATA" -> "promptExecutionMetadata";
            default -> "userPrompt";
        };
    }

    public List<String> stringList(Object raw) {
        if (raw instanceof List<?> values) {
            return values.stream()
                    .map(this::value)
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList();
        }
        String single = value(raw);
        return StringUtils.hasText(single) ? List.of(single) : List.of();
    }

    public String value(Object raw) {
        return raw == null ? "" : String.valueOf(raw).trim();
    }

    public String stateLabel(String state) {
        return switch (normalized(state)) {
            case "MATCH" -> message("enterprise.pqa.officialRun.comparison.state.match");
            case "PROMPT_MISSING" -> message("enterprise.pqa.officialRun.comparison.state.promptMissing");
            case "FACT_MISSING" -> message("enterprise.pqa.officialRun.comparison.state.factMissing");
            case "VALUE_MISMATCH" -> message("enterprise.pqa.officialRun.comparison.state.valueMismatch");
            case "CONTRACT_MISMATCH" -> message("enterprise.pqa.officialRun.comparison.state.contractMismatch");
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" -> message("enterprise.pqa.officialRun.comparison.state.requiredMissing");
            case "UNKNOWN_WITHOUT_REASON" -> message("enterprise.pqa.officialRun.comparison.state.unknownWithoutReason");
            case "PROMPT_COMPACTED_SIGNAL" -> message("enterprise.pqa.officialRun.comparison.state.compactedSignal");
            case "PRODUCER_NOT_AVAILABLE" -> message("enterprise.pqa.officialRun.comparison.state.producerUnavailable");
            case "PROVISIONAL_EVIDENCE" -> message("enterprise.pqa.officialRun.comparison.state.provisionalEvidence");
            case "NO_DIRECT_COMPARABLE" -> message("enterprise.pqa.officialRun.comparison.state.noComparable");
            case "BASELINE_MISMATCH_SIGNAL" -> message("enterprise.pqa.officialRun.comparison.state.baselineMismatch");
            case "NOT_APPLICABLE" -> message("enterprise.pqa.officialRun.comparison.state.notApplicable");
            default -> message("enterprise.pqa.officialRun.comparison.state.unknown");
        };
    }

    public String meaning(String state) {
        return switch (normalized(state)) {
            case "MATCH" -> message("enterprise.pqa.officialRun.comparison.meaning.match");
            case "PROMPT_MISSING" -> message("enterprise.pqa.officialRun.comparison.meaning.promptMissing");
            case "FACT_MISSING" -> message("enterprise.pqa.officialRun.comparison.meaning.factMissing");
            case "VALUE_MISMATCH" -> message("enterprise.pqa.officialRun.comparison.meaning.valueMismatch");
            case "CONTRACT_MISMATCH" -> "The final prompt, raw prompt, and sealed evidence contract are not synchronized.";
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" ->
                    "A required prompt evidence field is missing or lacks an allowed absence reason.";
            case "UNKNOWN_WITHOUT_REASON" -> "The prompt contains an unknown state without a recorded reason.";
            case "PROMPT_COMPACTED_SIGNAL" -> "Prompt compaction changed or removed a field without a complete field-level lineage.";
            case "PRODUCER_NOT_AVAILABLE" -> "A required context producer did not provide this field.";
            case "PROVISIONAL_EVIDENCE" -> "Provisional evidence is present and must not be treated as confirmed evidence.";
            case "NO_DIRECT_COMPARABLE" -> "The prompt lacks direct comparable history for this field.";
            case "BASELINE_MISMATCH_SIGNAL" -> "The prompt contains a baseline mismatch signal that must be explained and linked.";
            case "NOT_APPLICABLE" -> message("enterprise.pqa.officialRun.comparison.meaning.notApplicable");
            default -> message("enterprise.pqa.officialRun.comparison.meaning.default");
        };
    }

    public String fieldLabel(String key, String fallback) {
        String messageKey = "enterprise.pqa.officialRun.field." + key;
        String resolved = messageResolver.resolve(messageKey);
        return StringUtils.hasText(resolved) && !messageKey.equals(resolved)
                ? resolved
                : firstNonBlank(fallback, key);
    }

    public String dedupeKey(String fieldKey, String state) {
        return value(fieldKey) + "|" + normalized(firstNonBlank(state, "MATCH"));
    }

    private String comparisonStateFromFieldState(String fieldState) {
        return switch (normalized(fieldState)) {
            case "" -> "MATCH";
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" -> "PROMPT_MISSING";
            case "UNKNOWN_WITHOUT_REASON", "CONTRACT_MISMATCH" -> "VALUE_MISMATCH";
            default -> "VALUE_MISMATCH";
        };
    }

    private String normalized(String value) {
        return StringUtils.hasText(value) ? value.trim().toUpperCase(Locale.ROOT) : "";
    }

    private String firstNonBlank(String... values) {
        if (values != null) {
            for (String value : values) {
                if (StringUtils.hasText(value)) {
                    return value.trim();
                }
            }
        }
        return "";
    }

    private String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }
}