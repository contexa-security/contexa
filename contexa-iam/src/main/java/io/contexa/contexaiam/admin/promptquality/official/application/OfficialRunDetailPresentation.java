package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunCheckDetail;
import org.springframework.util.StringUtils;

import java.util.Locale;
import java.util.Objects;
import java.util.Set;

final class OfficialRunDetailPresentation {

    private static final Set<String> PASS_STATES = Set.of("SUCCESS", "PASS", "PASSED");

    private final PromptQualityMessageResolver messageResolver;

    OfficialRunDetailPresentation(PromptQualityMessageResolver messageResolver) {
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    String groupName(String category) {
        return switch (clean(category)) {
            case "IMPLEMENTATION_ALIGNMENT" -> message("enterprise.pqa.runtimeVerification.metric.group.implementationAlignment");
            case "RAG_AND_BASELINE" -> message("enterprise.pqa.runtimeVerification.metric.group.ragAndBaseline");
            case "BEHAVIORAL_CONTEXT" -> message("enterprise.pqa.runtimeVerification.metric.group.behavioralContext");
            case "LLM_DECISION" -> message("enterprise.pqa.runtimeVerification.metric.group.llmDecision");
            case "RESOURCE_ELIGIBILITY" -> message("enterprise.pqa.runtimeVerification.metric.group.resourceEligibility");
            default -> message("enterprise.pqa.runtimeVerification.metric.group.other");
        };
    }

    String stateLabel(String state) {
        String normalized = normalize(state);
        if ("NOT_APPLICABLE".equals(normalized)) {
            return message("enterprise.pqa.runtimeVerification.metric.state.notApplicable");
        }
        return PASS_STATES.contains(normalized)
                ? message("enterprise.pqa.runtimeVerification.metric.state.passed")
                : message("enterprise.pqa.runtimeVerification.metric.state.blocked");
    }

    String officialStateLabel(String state) {
        return switch (normalize(state)) {
            case "CERTIFIABLE" -> message("enterprise.pqa.runtimeVerification.runDetail.state.certifiable");
            case "BLOCKED" -> message("enterprise.pqa.runtimeVerification.runDetail.state.blocked");
            default -> message("enterprise.pqa.runtimeVerification.runDetail.state.review");
        };
    }

    String sourceMeaning(String source) {
        String normalized = normalize(source);
        if (!StringUtils.hasText(source) || "MISSING_SOURCE".equals(normalized)) {
            return message("enterprise.pqa.officialRun.source.missing");
        }
        if (normalized.contains("COREEVIDENCEREPLAY")) {
            return message("enterprise.pqa.officialRun.source.coreEvidenceReplay");
        }
        if (normalized.contains("PROMPT")) {
            return message("enterprise.pqa.officialRun.source.prompt");
        }
        if (normalized.contains("EVIDENCE")) {
            return message("enterprise.pqa.officialRun.source.evidence");
        }
        return message("enterprise.pqa.officialRun.source.ledger");
    }

    String remediationHint(String label, String source) {
        String text = (clean(label) + " " + clean(source)).toLowerCase(Locale.ROOT);
        if (text.contains("mfa")) {
            return message("enterprise.pqa.officialRun.remediation.mfa");
        }
        if (text.contains("prompt") && text.contains("hash")) {
            return message("enterprise.pqa.officialRun.remediation.promptHash");
        }
        if (text.contains("prompt") || text.contains("context")) {
            return message("enterprise.pqa.officialRun.remediation.promptContext");
        }
        if (text.contains("resource") || text.contains("requestpath") || text.contains("request path")) {
            return message("enterprise.pqa.officialRun.remediation.resource");
        }
        if (text.contains("authorization") || text.contains("role") || text.contains("permission")) {
            return message("enterprise.pqa.officialRun.remediation.authorization");
        }
        return message("enterprise.pqa.officialRun.remediation.default");
    }

    String reverifyCriterion(String label) {
        return StringUtils.hasText(label)
                ? message("enterprise.pqa.officialRun.reverifyCriterionTpl", label.trim())
                : message("enterprise.pqa.officialRun.reverifyCriterion.default");
    }

    String rootCause(OfficialRunCheckDetail check) {
        return message(
                "enterprise.pqa.officialRun.rootCauseTpl",
                display(check.label()),
                display(check.expectedValue()),
                display(check.actualValue()),
                display(check.source()));
    }

    String comparisonLabel(String state) {
        return switch (state) {
            case "MATCH" -> message("enterprise.pqa.officialRun.comparison.state.match");
            case "PROMPT_MISSING" -> message("enterprise.pqa.officialRun.comparison.state.promptMissing");
            case "FACT_MISSING" -> message("enterprise.pqa.officialRun.comparison.state.factMissing");
            case "VALUE_MISMATCH" -> message("enterprise.pqa.officialRun.comparison.state.valueMismatch");
            case "NOT_APPLICABLE" -> message("enterprise.pqa.officialRun.comparison.state.notApplicable");
            default -> message("enterprise.pqa.officialRun.comparison.state.unknown");
        };
    }

    String comparisonMeaning(String label, String state) {
        return switch (state) {
            case "MATCH" -> message("enterprise.pqa.officialRun.comparison.meaning.matchTpl", label);
            case "PROMPT_MISSING" -> message("enterprise.pqa.officialRun.comparison.meaning.promptMissingTpl", label);
            case "FACT_MISSING" -> message("enterprise.pqa.officialRun.comparison.meaning.factMissingTpl", label);
            case "VALUE_MISMATCH" -> message("enterprise.pqa.officialRun.comparison.meaning.valueMismatchTpl", label);
            case "NOT_APPLICABLE" -> message("enterprise.pqa.officialRun.comparison.meaning.notApplicableTpl", label);
            default -> message("enterprise.pqa.officialRun.comparison.meaning.defaultTpl", label);
        };
    }

    String promptLocation(String key) {
        String normalized = clean(key).toLowerCase(Locale.ROOT);
        if (normalized.contains("systemprompt")) {
            return "systemPrompt";
        }
        if (normalized.contains("hash") || normalized.contains("version") || normalized.contains("model")) {
            return "promptExecutionMetadata";
        }
        if (normalized.contains("baseline")) {
            return "userPrompt.baseline";
        }
        if (normalized.contains("rag")) {
            return "userPrompt.rag";
        }
        return "userPrompt.requestContext";
    }

    String evidenceSource(String key) {
        String normalized = clean(key).toLowerCase(Locale.ROOT);
        if (normalized.contains("auth") || normalized.contains("mfa") || normalized.contains("role") || normalized.contains("permission")) {
            return "sealedEvidence.authState";
        }
        if (normalized.contains("prompt") || normalized.contains("model")) {
            return "sealedEvidence.promptExecutionMetadata";
        }
        if (normalized.contains("baseline")) {
            return "sealedEvidence.baselineSnapshot";
        }
        if (normalized.contains("rag")) {
            return "sealedEvidence.ragResults";
        }
        if (normalized.contains("decision")) {
            return "sealedEvidence.decision";
        }
        return "sealedEvidence.requestFacts";
    }

    String recommendedOwner(String key) {
        String normalized = clean(key).toLowerCase(Locale.ROOT);
        if (normalized.contains("auth") || normalized.contains("mfa") || normalized.contains("role") || normalized.contains("permission")) {
            return "CONTEXT_SOURCE_MAPPING";
        }
        if (normalized.contains("prompt") || normalized.contains("model")) {
            return "PROMPT_GOVERNANCE";
        }
        if (normalized.contains("baseline") || normalized.contains("rag")) {
            return "LEARNING_CONTEXT";
        }
        if (normalized.contains("resource") || normalized.contains("requestpath") || normalized.contains("httpmethod")) {
            return "RESOURCE_SCOPE";
        }
        return "CONTEXT_PROJECTION";
    }

    private String display(String value) {
        return StringUtils.hasText(value) ? value.trim() : message("enterprise.pqa.common.value.notRecorded");
    }

    private String clean(String value) {
        return value == null ? "" : value.trim();
    }

    private String normalize(String value) {
        return clean(value).toUpperCase(Locale.ROOT);
    }

    private String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }
}
