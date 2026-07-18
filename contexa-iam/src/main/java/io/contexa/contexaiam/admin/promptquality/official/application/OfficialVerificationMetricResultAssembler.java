package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationGateCode;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public final class OfficialVerificationMetricResultAssembler {

    private final PromptQualityOfficialMetricCatalog metricCatalog;
    private final PromptQualityMessageResolver messageResolver;
    private final OfficialPromptQualityNarrativeCatalog narrativeCatalog = new OfficialPromptQualityNarrativeCatalog();

    public OfficialVerificationMetricResultAssembler(
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityMessageResolver messageResolver) {
        this.metricCatalog = Objects.requireNonNull(metricCatalog, "metricCatalog");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    public List<RuntimeEvidenceMetricResult> assemble(
            List<? extends OfficialVerificationRunView> runs,
            List<OfficialVerificationPromptComparison> promptComparisons,
            String packageId) {
        Map<String, OfficialVerificationRunView> runsByMetric = runsByMetric(runs);
        Map<String, List<OfficialVerificationPromptComparison>> comparisonsByMetric =
                comparisonsByMetric(promptComparisons);
        Map<String, OfficialVerificationMetricDefinition> definitionsByMetric = definitionsByMetric();
        Set<String> metricCodes = new LinkedHashSet<>(runsByMetric.keySet());
        metricCodes.addAll(comparisonsByMetric.keySet());
        List<RuntimeEvidenceMetricResult> results = new ArrayList<>();
        for (String candidate : metricCodes) {
            String metricCode = normalized(candidate);
            if (!StringUtils.hasText(metricCode)) {
                continue;
            }
            results.add(assembleMetric(
                    metricCode,
                    runsByMetric.get(metricCode),
                    definitionsByMetric.get(metricCode),
                    comparisonsByMetric.getOrDefault(metricCode, List.of()),
                    packageId));
        }
        return List.copyOf(results);
    }

    private RuntimeEvidenceMetricResult assembleMetric(
            String metricCode,
            OfficialVerificationRunView run,
            OfficialVerificationMetricDefinition definition,
            List<OfficialVerificationPromptComparison> comparisons,
            String packageId) {
        List<RuntimeEvidenceCheckResult> checks = checks(metricCode, run, comparisons, packageId);
        List<RuntimeEvidenceCheckResult> evaluated = checks.stream()
                .filter(check -> !notApplicable(check))
                .toList();
        int total = evaluated.size();
        int passed = (int) evaluated.stream().filter(RuntimeEvidenceCheckResult::pass).count();
        boolean notApplicable = "not_applicable".equalsIgnoreCase(run == null ? null : run.state())
                || (!checks.isEmpty() && checks.stream().allMatch(this::notApplicable));
        boolean metricPassed = !notApplicable && passed == total;
        String state = notApplicable ? "NOT_APPLICABLE" : metricPassed ? "SUCCESS" : "threshold_failed";
        double score = total == 0 ? 100.0d : Math.round(((double) passed / total) * 1000.0d) / 10.0d;
        return new RuntimeEvidenceMetricResult(
                metricCode,
                run == null ? null : run.runId(),
                narrativeCatalog.metricName(metricCode),
                groupName(definition == null ? null : definition.category()),
                score,
                state,
                stateLabel(notApplicable, metricPassed),
                passed,
                total,
                List.copyOf(checks));
    }

    private List<RuntimeEvidenceCheckResult> checks(
            String metricCode,
            OfficialVerificationRunView run,
            List<OfficialVerificationPromptComparison> comparisons,
            String packageId) {
        List<RuntimeEvidenceCheckResult> checks = new ArrayList<>();
        if (run != null) {
            for (OfficialVerificationCheckResultView check : run.checks() == null
                    ? List.<OfficialVerificationCheckResultView>of()
                    : run.checks()) {
                if (OfficialVerificationMetricClassifier.officialFinalPromptCheck(check)) {
                    checks.add(runtimeCheck(metricCode, check));
                }
            }
        }
        if (run == null || run.checks() == null || run.checks().isEmpty()) {
            comparisons.stream()
                    .filter(OfficialVerificationMetricClassifier::blockingPromptComparison)
                    .map(comparison -> promptComparisonCheck(metricCode, comparison, packageId))
                    .forEach(checks::add);
        }
        return checks;
    }

    private RuntimeEvidenceCheckResult runtimeCheck(
            String metricCode,
            OfficialVerificationCheckResultView check) {
        return new RuntimeEvidenceCheckResult(
                metricCode,
                check.checkCode(),
                check.label(),
                check.expectedValue(),
                check.actualValue(),
                check.pass(),
                check.source(),
                check.pass() ? "INFO" : check.severity(),
                check.pass() ? "" : check.failureType(),
                check.remediationOwner(),
                check.operatorReason(),
                check.nextAction(),
                check.reverifyCriterion(),
                check.issueKey(),
                check.customerVisible(),
                OfficialVerificationMetricClassifier.readinessScope(check),
                check.purposeVersion(),
                check.inputReadinessState(),
                check.purposeResult(),
                check.detectedSignalsJson(),
                check.interpretationLinksJson(),
                check.decisionUtility(),
                check.whyItMatters(),
                OfficialVerificationGateCode.UNCLASSIFIED);
    }

    private RuntimeEvidenceCheckResult promptComparisonCheck(
            String metricCode,
            OfficialVerificationPromptComparison comparison,
            String packageId) {
        String label = firstNonBlank(comparison.fieldLabel(), comparison.fieldKey(), "Prompt field");
        String state = firstNonBlank(comparison.state(), "MATCH");
        boolean pass = !OfficialVerificationMetricClassifier.blockingPromptComparison(comparison);
        return new RuntimeEvidenceCheckResult(
                metricCode,
                promptCheckId(pass, packageId, comparison.fieldKey(), state),
                label,
                expectedValue(comparison),
                pass ? firstNonBlank(comparison.meaning(), "The field satisfies the prompt evidence contract.")
                        : actualValue(comparison),
                pass,
                firstNonBlank(comparison.promptLocation(), comparison.evidenceSource(), comparison.fieldKey()),
                pass ? "INFO" : "BLOCKING",
                pass ? "" : state,
                firstNonBlank(comparison.recommendedOwner(), "PROMPT_ASSEMBLER"),
                firstNonBlank(comparison.meaning(), label + " field did not satisfy the prompt evidence contract."),
                pass ? "No action is required for this field."
                        : "Fix the source that creates this prompt field, collect new sealed evidence, and rerun official inspection.",
                pass ? "The same prompt field remains synchronized in the next official inspection."
                        : "The same prompt field must be recorded as matched or non-blocking in the next official inspection.",
                firstNonBlank(comparison.fieldKey(), comparison.promptLocation(), label),
                true,
                "CUSTOMER_PROMPT_QUALITY",
                "",
                "READY",
                pass ? "PURPOSE_PASSED" : "PURPOSE_FAILED",
                "[]", "[]", "", "",
                OfficialVerificationGateCode.UNCLASSIFIED);
    }

    private Map<String, OfficialVerificationRunView> runsByMetric(
            List<? extends OfficialVerificationRunView> runs) {
        return (runs == null ? List.<OfficialVerificationRunView>of() : runs).stream()
                .filter(run -> run != null && StringUtils.hasText(run.endpointKey()))
                .collect(Collectors.toMap(
                        run -> normalized(run.endpointKey()),
                        run -> run,
                        (left, right) -> left,
                        LinkedHashMap::new));
    }

    private Map<String, OfficialVerificationMetricDefinition> definitionsByMetric() {
        return metricCatalog.promptQualityMetrics().stream()
                .filter(metric -> metric != null && StringUtils.hasText(metric.code()))
                .collect(Collectors.toMap(
                        metric -> normalized(metric.code()),
                        metric -> metric,
                        (left, right) -> left,
                        LinkedHashMap::new));
    }

    private Map<String, List<OfficialVerificationPromptComparison>> comparisonsByMetric(
            List<OfficialVerificationPromptComparison> comparisons) {
        Map<String, List<OfficialVerificationPromptComparison>> result = new LinkedHashMap<>();
        for (OfficialVerificationPromptComparison comparison :
                comparisons == null ? List.<OfficialVerificationPromptComparison>of() : comparisons) {
            if (comparison == null) {
                continue;
            }
            List<String> metricCodes = metricCodes(comparison);
            assertBound(comparison, metricCodes);
            for (String metricCode : metricCodes) {
                result.computeIfAbsent(metricCode, ignored -> new ArrayList<>()).add(comparison);
            }
        }
        return result;
    }

    private void assertBound(
            OfficialVerificationPromptComparison comparison,
            List<String> metricCodes) {
        if (!OfficialVerificationMetricClassifier.blockingPromptComparison(comparison)) {
            return;
        }
        if (metricCodes.isEmpty()) {
            throw new IllegalStateException("Actual prompt problem is not bound to a 12-metric code. fieldKey="
                    + firstNonBlank(comparison.fieldKey(), "unknown")
                    + ", state=" + firstNonBlank(comparison.state(), "unknown"));
        }
        if (!StringUtils.hasText(comparison.recommendedOwner())) {
            throw new IllegalStateException("Actual prompt problem is not bound to a remediation owner. fieldKey="
                    + firstNonBlank(comparison.fieldKey(), "unknown")
                    + ", state=" + firstNonBlank(comparison.state(), "unknown"));
        }
    }

    private List<String> metricCodes(OfficialVerificationPromptComparison comparison) {
        Set<String> result = new LinkedHashSet<>();
        if (comparison.metricCodes() != null) {
            comparison.metricCodes().stream()
                    .filter(StringUtils::hasText)
                    .map(this::normalized)
                    .forEach(result::add);
        }
        return List.copyOf(result);
    }

    private String expectedValue(OfficialVerificationPromptComparison comparison) {
        return switch (normalized(comparison == null ? null : comparison.state())) {
            case "PROMPT_MISSING" -> "The sealed evidence value must be visible in the final LLM user prompt.";
            case "FACT_MISSING" -> "The final LLM user prompt field must also be stored in the sealed evidence package.";
            case "VALUE_MISMATCH", "CONTRACT_MISMATCH" -> "The final LLM user prompt value and the sealed evidence value must match.";
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" -> "The required prompt evidence field must be present or have an allowed absence policy.";
            case "UNKNOWN_WITHOUT_REASON" -> "Unknown prompt evidence must include a recorded reason and remediation owner.";
            case "PROMPT_COMPACTED_SIGNAL" -> "Prompt compaction must preserve full source lineage and field-level diff evidence.";
            case "PRODUCER_NOT_AVAILABLE" -> "The required context producer must record its unavailable state and reason.";
            case "PROVISIONAL_EVIDENCE" -> "Provisional evidence must be explicitly labeled and not represented as confirmed evidence.";
            case "NO_DIRECT_COMPARABLE" -> "Comparable-history absence must be recorded as a bounded evidence limitation.";
            case "BASELINE_MISMATCH_SIGNAL" -> "Baseline mismatch signals must be visible and linked to the final prompt evidence.";
            default -> "The actual prompt field must satisfy the sealed evidence contract.";
        };
    }

    private String actualValue(OfficialVerificationPromptComparison comparison) {
        if (comparison == null) {
            return "An actual prompt problem was recorded.";
        }
        return switch (normalized(comparison.state())) {
            case "PROMPT_MISSING" -> "The final user prompt does not contain this value. sealedEvidenceValue="
                    + firstNonBlank(comparison.sealedEvidenceValue(), "unavailable");
            case "FACT_MISSING" -> "The sealed evidence package does not contain this value. finalPromptValue="
                    + firstNonBlank(comparison.promptValue(), "unavailable");
            case "VALUE_MISMATCH", "CONTRACT_MISMATCH" -> "The values do not match. finalPromptValue="
                    + firstNonBlank(comparison.promptValue(), "unavailable")
                    + " / sealedEvidenceValue=" + firstNonBlank(comparison.sealedEvidenceValue(), "unavailable");
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" -> "A required prompt evidence field was recorded as missing.";
            case "UNKNOWN_WITHOUT_REASON" -> "The field is unknown and no reason was recorded.";
            case "PROMPT_COMPACTED_SIGNAL" -> "The prompt was compacted or changed without complete field-level lineage.";
            case "PRODUCER_NOT_AVAILABLE" -> "The context producer did not provide the required field.";
            case "PROVISIONAL_EVIDENCE" -> "The field is provisional and must remain explicitly bounded.";
            case "NO_DIRECT_COMPARABLE" -> "No direct comparable history was recorded for the field.";
            case "BASELINE_MISMATCH_SIGNAL" -> "The field carries a baseline mismatch signal that requires explanation.";
            default -> firstNonBlank(comparison.meaning(), "The actual prompt problem must be reviewed.");
        };
    }

    private String promptCheckId(boolean pass, String packageId, String fieldKey, String state) {
        String seed = firstNonBlank(packageId, "") + "|" + firstNonBlank(fieldKey, "") + "|" + firstNonBlank(state, "");
        return (pass ? "apc-" : "app-") + UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8));
    }

    private boolean notApplicable(RuntimeEvidenceCheckResult check) {
        return check != null && "NOT_APPLICABLE".equalsIgnoreCase(check.purposeResult());
    }

    private String stateLabel(boolean notApplicable, boolean passed) {
        if (notApplicable) {
            return message("enterprise.pqa.runtimeVerification.metric.state.notApplicable");
        }
        return passed
                ? message("enterprise.pqa.runtimeVerification.metric.state.passed")
                : message("enterprise.pqa.runtimeVerification.metric.state.blocked");
    }

    private String groupName(String category) {
        return switch (normalized(category)) {
            case "IMPLEMENTATION_ALIGNMENT" -> message("enterprise.pqa.runtimeVerification.metric.group.implementationAlignment");
            case "RAG_AND_BASELINE" -> message("enterprise.pqa.runtimeVerification.metric.group.ragAndBaseline");
            case "BEHAVIORAL_CONTEXT" -> message("enterprise.pqa.runtimeVerification.metric.group.behavioralContext");
            case "LLM_DECISION", "LLM_DECISION_GATE" -> message("enterprise.pqa.runtimeVerification.metric.group.llmDecision");
            case "RESOURCE_ELIGIBILITY" -> message("enterprise.pqa.runtimeVerification.metric.group.resourceEligibility");
            default -> message("enterprise.pqa.runtimeVerification.metric.group.other");
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