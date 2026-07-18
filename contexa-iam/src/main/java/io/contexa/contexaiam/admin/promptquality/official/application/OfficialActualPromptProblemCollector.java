package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricCheckContract;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContract;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

final class OfficialActualPromptProblemCollector {

    private static final Set<String> PASS_STATES =
            Set.of("SUCCESS", "PASS", "PASSED", "VERIFIED", "COMPLETED");

    private final OfficialFinalPromptMetricContractRegistry contractRegistry;
    private final OfficialMetricPurposeNarrative purposeNarrative;
    private final OfficialRuntimeEvidenceCheckInterpreter checkInterpreter;
    private final OfficialActualPromptProblemNarrative problemNarrative;

    OfficialActualPromptProblemCollector(
            OfficialFinalPromptMetricContractRegistry contractRegistry,
            OfficialMetricPurposeNarrative purposeNarrative,
            OfficialRuntimeEvidenceCheckInterpreter checkInterpreter,
            OfficialActualPromptProblemNarrative problemNarrative) {
        this.contractRegistry = contractRegistry;
        this.purposeNarrative = purposeNarrative;
        this.checkInterpreter = checkInterpreter;
        this.problemNarrative = problemNarrative;
    }

    List<OfficialActualPromptProblem> collect(
            String aggregateRunId,
            String packageId,
            List<RuntimeEvidenceMetricResult> metrics,
            List<OfficialVerificationPromptComparison> comparisons) {
        if (!StringUtils.hasText(aggregateRunId) || !StringUtils.hasText(packageId)) {
            return List.of();
        }
        Map<String, OfficialActualPromptProblem> problems = new LinkedHashMap<>();
        addMetricProblems(problems, aggregateRunId, packageId, metrics);
        addComparisonProblems(problems, aggregateRunId, packageId, comparisons);
        return List.copyOf(problems.values());
    }

    Map<String, List<OfficialActualPromptProblem>> byMetric(List<OfficialActualPromptProblem> problems) {
        Map<String, List<OfficialActualPromptProblem>> result = new LinkedHashMap<>();
        for (OfficialActualPromptProblem problem : safeList(problems)) {
            if (problem == null || !"BLOCKING".equals(normalize(problem.severity()))) {
                continue;
            }
            for (String metricCode : safeList(problem.metricCodes())) {
                String normalized = normalize(metricCode);
                if (StringUtils.hasText(normalized)) {
                    result.computeIfAbsent(normalized, ignored -> new ArrayList<>()).add(problem);
                }
            }
        }
        return result;
    }

    boolean officialPromptIssueField(String fieldKey) {
        String normalized = safe(fieldKey);
        return normalized.startsWith("finalUserPrompt.") || normalized.startsWith("finalSystemPrompt.");
    }

    private void addMetricProblems(
            Map<String, OfficialActualPromptProblem> problems,
            String aggregateRunId,
            String packageId,
            List<RuntimeEvidenceMetricResult> metrics) {
        for (RuntimeEvidenceMetricResult metric : safeList(metrics)) {
            if (!eligibleMetric(metric)) {
                continue;
            }
            String metricCode = normalize(metric.metricCode());
            for (RuntimeEvidenceCheckResult check : safeList(metric.checks())) {
                if (!eligibleCheck(check)) {
                    continue;
                }
                String fieldKey = firstNonBlank(check.issueKey(), check.source());
                if (!officialPromptIssueField(fieldKey)) {
                    continue;
                }
                FinalPromptMetricCheckContract contract = customerPromptProblemContract(metricCode, check);
                add(problems, new ProblemDraft(
                        aggregateRunId, packageId, contract.issueKey(), contract.failureType(), contract.source(),
                        contract.problemTitle(), contract.shortProblem(), sourceFieldPath(check, contract),
                        sealedEvidencePath(contract.issueKey()), contract.expectedMessage(),
                        purposeNarrative.actualProblemState(check, contract), contract.severity(), List.of(metricCode),
                        contract.remediationOwner(), contract.qualityQuestion(), contract.whyItMatters(),
                        contract.nextAction(), contract.reverifyCriterion()));
            }
        }
    }

    private void addComparisonProblems(
            Map<String, OfficialActualPromptProblem> problems,
            String aggregateRunId,
            String packageId,
            List<OfficialVerificationPromptComparison> comparisons) {
        for (OfficialVerificationPromptComparison comparison : safeList(comparisons)) {
            if (!blocking(comparison)
                    || "OFFICIAL_FINDING".equalsIgnoreCase(safe(comparison.canonicalSource()))
                    || !officialPromptIssueField(comparison.fieldKey())) {
                continue;
            }
            List<String> metricCodes = comparisonMetricCodes(comparison);
            if (metricCodes.isEmpty()) {
                throw new IllegalStateException(
                        "ENGINE_CONTRACT_ERROR: Prompt comparison problem is not bound to any official metric. "
                                + "fieldKey=" + safe(comparison.fieldKey())
                                + ", state=" + safe(comparison.state()));
            }
            String label = firstNonBlank(comparison.fieldLabel(), comparison.fieldKey(), "Prompt field");
            String location = firstNonBlank(comparison.promptLocation(), comparison.fieldKey(), "finalUserPrompt");
            add(problems, new ProblemDraft(
                    aggregateRunId, packageId, comparison.fieldKey(),
                    normalize(firstNonBlank(comparison.state(), "CONTRACT_MISMATCH")), location, label,
                    firstNonBlank(comparison.promptValue(), comparison.meaning(), label), location,
                    firstNonBlank(comparison.evidenceSource(), sealedEvidencePath(comparison.fieldKey()), location),
                    expectedComparisonState(comparison), actualComparisonState(comparison), "BLOCKING", metricCodes,
                    firstNonBlank(comparison.recommendedOwner(), "PROMPT_ASSEMBLER"),
                    "Does the final prompt preserve the sealed evidence contract for this field?",
                    firstNonBlank(comparison.meaning(),
                            "A final prompt field is not synchronized with its sealed evidence contract."),
                    "Fix the source that creates this prompt field, collect new sealed evidence, and rerun official inspection.",
                    "The same prompt field must be recorded as matched or non-blocking in the next official inspection."));
        }
    }

    private void add(Map<String, OfficialActualPromptProblem> problems, ProblemDraft draft) {
        String fieldKey = safe(draft.fieldKey());
        String problemType = normalize(draft.problemType());
        if (!StringUtils.hasText(fieldKey) || !StringUtils.hasText(problemType)) {
            return;
        }
        List<String> metricCodes = problemNarrative.normalizeMetricCodes(draft.metricCodes());
        String severity = "BLOCKING".equals(normalize(draft.severity())) ? "BLOCKING" : "REVIEW";
        assertContract(fieldKey, problemType, severity, metricCodes, draft.remediationOwner());
        OfficialActualPromptProblem incoming = problem(draft, fieldKey, problemType, severity, metricCodes);
        String key = fieldKey + "|" + problemType;
        problems.put(key, merge(problems.get(key), incoming));
    }

    private OfficialActualPromptProblem problem(
            ProblemDraft draft,
            String fieldKey,
            String problemType,
            String severity,
            List<String> metricCodes) {
        return new OfficialActualPromptProblem(
                problemNarrative.problemId(draft.packageId(), fieldKey, problemType),
                safe(draft.packageId()), safe(draft.aggregateRunId()), fieldKey, problemType,
                safe(draft.promptSection(), "userPrompt"), safe(draft.promptLabel(), fieldKey),
                safe(draft.promptValue()), safe(draft.sourceFieldPath(), fieldKey),
                safe(draft.sealedEvidencePath(), draft.sourceFieldPath()), safe(draft.expectedState()),
                safe(draft.actualState()), severity, metricCodes, safe(draft.remediationOwner()),
                safe(draft.qualityQuestion()), safe(draft.whyItMatters()), safe(draft.fixAction()),
                safe(draft.reverifyCriterion()), List.of(), List.of());
    }

    private OfficialActualPromptProblem merge(
            OfficialActualPromptProblem existing,
            OfficialActualPromptProblem incoming) {
        if (existing == null) {
            return incoming;
        }
        List<String> metricCodes = new ArrayList<>();
        safeList(existing.metricCodes()).forEach(code -> addUnique(metricCodes, code));
        safeList(incoming.metricCodes()).forEach(code -> addUnique(metricCodes, code));
        boolean incomingBlocking = "BLOCKING".equals(normalize(incoming.severity()));
        boolean existingBlocking = "BLOCKING".equals(normalize(existing.severity()));
        OfficialActualPromptProblem primary = incomingBlocking && !existingBlocking ? incoming : existing;
        return new OfficialActualPromptProblem(
                primary.problemId(), primary.packageId(), primary.aggregateRunId(), primary.fieldKey(),
                primary.problemType(), primary.promptSection(), primary.promptLabel(), primary.promptValue(),
                primary.sourceFieldPath(), primary.sealedEvidencePath(), primary.expectedState(), primary.actualState(),
                incomingBlocking || existingBlocking ? "BLOCKING" : primary.severity(), List.copyOf(metricCodes),
                primary.remediationOwner(), firstNonBlank(primary.qualityQuestion(), incoming.qualityQuestion(), existing.qualityQuestion()),
                firstNonBlank(primary.whyItMatters(), incoming.whyItMatters(), existing.whyItMatters()),
                firstNonBlank(primary.fixAction(), incoming.fixAction(), existing.fixAction()),
                firstNonBlank(primary.reverifyCriterionDetail(), incoming.reverifyCriterionDetail(), existing.reverifyCriterionDetail()),
                primary.runtimeFacts(), primary.contextItems());
    }

    private FinalPromptMetricCheckContract customerPromptProblemContract(
            String metricCode,
            RuntimeEvidenceCheckResult check) {
        if (check == null || !StringUtils.hasText(check.purposeVersion()) || !StringUtils.hasText(check.checkCode())) {
            throw contractError("Customer prompt problem check is not contract backed.", metricCode, check);
        }
        FinalPromptMetricContract metricContract = contractRegistry.metric(metricCode);
        if (!check.purposeVersion().trim().equals(metricContract.version())) {
            throw contractError("Customer prompt problem check uses an unknown contract version.", metricCode, check);
        }
        FinalPromptMetricCheckContract contract = contractRegistry.check(metricCode, check);
        if (!contract.customerVisible()
                || !"CUSTOMER_PROMPT_QUALITY".equalsIgnoreCase(contract.readinessScope())) {
            throw contractError("Customer prompt problem check is not customer prompt quality scoped.", metricCode, check);
        }
        return contract;
    }

    private String sourceFieldPath(
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract contract) {
        for (String signal : checkInterpreter.detectedSignals(check)) {
            String parsed = sourceFromSignal(signal);
            if (StringUtils.hasText(parsed)) {
                return parsed;
            }
        }
        return contract == null ? "" : contract.source();
    }

    private String sourceFromSignal(String signal) {
        String text = safe(signal);
        for (String prefix : List.of(
                "truncatedField=", "truncatedBullet=", "truncatedNarrative=", "unmappedPromptFact=")) {
            if (text.startsWith(prefix)) {
                String value = text.substring(prefix.length()).trim();
                int valueIndex = value.indexOf(" value=");
                return valueIndex < 0 ? value : value.substring(0, valueIndex).trim();
            }
        }
        return "";
    }

    private boolean eligibleMetric(RuntimeEvidenceMetricResult metric) {
        return metric != null && !PASS_STATES.contains(normalize(metric.state()))
                && !Set.of("MTR", "RPI", "PRE").contains(normalize(metric.metricCode()))
                && metric.checks() != null;
    }

    private boolean eligibleCheck(RuntimeEvidenceCheckResult check) {
        return check != null && !check.pass() && !checkInterpreter.inputNotReady(check)
                && check.customerVisible()
                && "CUSTOMER_PROMPT_QUALITY".equalsIgnoreCase(
                        firstNonBlank(check.readinessScope(), "CUSTOMER_PROMPT_QUALITY"))
                && "BLOCKING".equalsIgnoreCase(safe(check.severity()));
    }

    private boolean blocking(OfficialVerificationPromptComparison comparison) {
        if (comparison == null) {
            return false;
        }
        String state = normalize(comparison.state());
        return state.startsWith("FINAL_PROMPT_") || Set.of(
                "PROMPT_MISSING", "FACT_MISSING", "VALUE_MISMATCH", "CONTRACT_MISMATCH",
                "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING", "UNKNOWN_WITHOUT_REASON",
                "PROMPT_COMPACTED_SIGNAL", "PRODUCER_NOT_AVAILABLE", "PROVISIONAL_EVIDENCE",
                "NO_DIRECT_COMPARABLE", "BASELINE_MISMATCH_SIGNAL").contains(state);
    }

    private List<String> comparisonMetricCodes(OfficialVerificationPromptComparison comparison) {
        return safeList(comparison == null ? null : comparison.metricCodes()).stream()
                .filter(StringUtils::hasText).map(this::normalize).distinct().toList();
    }

    private String expectedComparisonState(OfficialVerificationPromptComparison comparison) {
        return switch (normalize(comparison == null ? null : comparison.state())) {
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
            default -> firstNonBlank(
                    comparison == null ? null : comparison.officialFactValue(),
                    comparison == null ? null : comparison.sealedEvidenceValue(),
                    comparison == null ? null : comparison.meaning(),
                    "The actual prompt field must satisfy the sealed evidence contract.");
        };
    }

    private String actualComparisonState(OfficialVerificationPromptComparison comparison) {
        return switch (normalize(comparison == null ? null : comparison.state())) {
            case "PROMPT_MISSING" -> "The final user prompt does not contain the sealed evidence value for this field.";
            case "FACT_MISSING" -> "The sealed evidence package does not contain the final prompt value for this field.";
            case "VALUE_MISMATCH", "CONTRACT_MISMATCH" -> "The final prompt value and the sealed evidence value do not match for this field.";
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" -> "A required prompt evidence field was recorded as missing.";
            case "UNKNOWN_WITHOUT_REASON" -> "The field is unknown and no reason was recorded.";
            case "PROMPT_COMPACTED_SIGNAL" -> "The prompt was compacted or changed without complete field-level lineage.";
            case "PRODUCER_NOT_AVAILABLE" -> "The context producer did not provide the required field.";
            case "PROVISIONAL_EVIDENCE" -> "The field is provisional and must remain explicitly bounded.";
            case "NO_DIRECT_COMPARABLE" -> "No direct comparable history was recorded for the field.";
            case "BASELINE_MISMATCH_SIGNAL" -> "The field carries a baseline mismatch signal that requires explanation.";
            default -> firstNonBlank(
                    comparison == null ? null : comparison.promptValue(),
                    comparison == null ? null : comparison.meaning(),
                    "The actual prompt problem must be reviewed.");
        };
    }

    private String sealedEvidencePath(String fieldKey) {
        return safe(fieldKey).startsWith("finalSystemPrompt.")
                ? "sealedEvidence.systemPromptText" : "sealedEvidence.userPromptText";
    }

    private void assertContract(
            String fieldKey,
            String problemType,
            String severity,
            List<String> metricCodes,
            String remediationOwner) {
        if ("BLOCKING".equals(severity) && metricCodes.isEmpty()) {
            throw new IllegalStateException("Actual prompt problem is not bound to any official metric. fieldKey="
                    + fieldKey + ", problemType=" + problemType);
        }
        if ("BLOCKING".equals(severity) && !StringUtils.hasText(remediationOwner)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Actual final userPrompt problem is missing contract owner. "
                    + "fieldKey=" + fieldKey + ", problemType=" + problemType);
        }
    }

    private IllegalStateException contractError(
            String message,
            String metricCode,
            RuntimeEvidenceCheckResult check) {
        return new IllegalStateException("ENGINE_CONTRACT_ERROR: " + message
                + " metricCode=" + safe(metricCode)
                + ", checkCode=" + safe(check == null ? null : check.checkCode())
                + ", purposeVersion=" + safe(check == null ? null : check.purposeVersion()));
    }

    private void addUnique(List<String> values, String value) {
        if (StringUtils.hasText(value) && !values.contains(value.trim())) {
            values.add(value.trim());
        }
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }

    private String safe(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : safe(fallback);
    }

    private <T> List<T> safeList(List<T> values) {
        return values == null ? List.of() : values;
    }

    private record ProblemDraft(
            String aggregateRunId,
            String packageId,
            String fieldKey,
            String problemType,
            String promptSection,
            String promptLabel,
            String promptValue,
            String sourceFieldPath,
            String sealedEvidencePath,
            String expectedState,
            String actualState,
            String severity,
            List<String> metricCodes,
            String remediationOwner,
            String qualityQuestion,
            String whyItMatters,
            String fixAction,
            String reverifyCriterion) {
    }
}
