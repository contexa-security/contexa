package io.contexa.contexacore.verification.runtime.prompt;

import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ContractBackedFinalPromptMetricEvaluator implements FinalPromptMetricEvaluator {

    private static final Pattern TEMPLATE_PLACEHOLDER = Pattern.compile("\\{\\{([^}]+)}}");
    private static final Pattern CUSTOMER_EVIDENCE_KEY_VALUE =
            Pattern.compile("[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*");
    private final FinalPromptMetricContract metricContract;
    private final FinalPromptMetricRuleEngine ruleEngine;
    private final FinalPromptMetricContractCatalog contractCatalog;
    private final OfficialVerificationMessageResolver messageResolver;

    ContractBackedFinalPromptMetricEvaluator(
            FinalPromptMetricContract metricContract,
            FinalPromptMetricRuleEngine ruleEngine,
            FinalPromptMetricContractCatalog contractCatalog,
            OfficialVerificationMessageResolver messageResolver) {
        if (metricContract == null || !StringUtils.hasText(metricContract.metricCode())) {
            throw new IllegalArgumentException("final prompt metric contract is required.");
        }
        this.metricContract = metricContract;
        this.ruleEngine = Objects.requireNonNull(ruleEngine, "ruleEngine");
        this.contractCatalog = Objects.requireNonNull(contractCatalog, "contractCatalog");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    @Override
    public String metricCode() {
        return normalizeMetric(metricContract.metricCode());
    }

    @Override
    public FinalPromptMetricResult evaluate(FinalPromptMetricEvaluationContext context) {
        List<FinalPromptMetricCheck> checks = new ArrayList<>();
        for (FinalPromptMetricCheckContract checkContract : metricContract.checks()) {
            if (checkContract == null) {
                throw new IllegalStateException("Final prompt metric contract contains a null check. metricCode="
                        + metricCode());
            }
            if (checkContract.rule() == null || !StringUtils.hasText(checkContract.rule().operator())) {
                throw new IllegalStateException("Final prompt metric check has no executable rule. metricCode="
                        + metricCode() + ", checkName=" + FinalPromptDisplayValues.firstNonBlank(checkContract.checkName(), "UNKNOWN_CHECK"));
            }
            FinalPromptMetricInputReadiness inputReadiness = inputReadiness(checkContract, context);
            if (!inputReadiness.ready()) {
                checks.add(inputMissingCheck(checkContract, inputReadiness));
                continue;
            }
            if (conditionalRagMetricNotApplicable(context)
                    && "INTERNAL_REFERENCE".equalsIgnoreCase(readinessScope(checkContract))) {
                checks.add(notApplicableCheck(checkContract, context));
                continue;
            }
            if (notApplicable(checkContract, context)) {
                checks.add(notApplicableCheck(checkContract, context));
                continue;
            }
            boolean passed = ruleEngine.evaluate(checkContract.rule(), context);
            if (passed && !customerPassedEvidenceSufficient(checkContract, context)) {
                passed = false;
            }
            checks.add(check(checkContract, passed, context));
        }
        return FinalPromptMetricResultAssembler.result(metricCode(), checks);
    }

    private boolean customerPassedEvidenceSufficient(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricEvaluationContext context) {
        if (checkContract == null || !displayVisibleCheck(checkContract)) {
            return true;
        }
        if (optionalFieldValuesConsistentCheck(checkContract)) {
            return true;
        }
        try {
            String runtimeFacts = contractRuntimeFacts(checkContract, true, context);
            return customerRuntimeFactsUsable(checkContract, true, context, runtimeFacts);
        }
        catch (IllegalStateException exception) {
            if (missingRuntimeEvidence(exception)) {
                return false;
            }
            throw exception;
        }
    }

    private boolean missingRuntimeEvidence(IllegalStateException exception) {
        String message = exception == null ? null : exception.getMessage();
        return StringUtils.hasText(message)
                && message.startsWith("ENGINE_CONTRACT_ERROR:")
                && (message.contains("binding has no prompt value")
                || message.contains("binding has no present term")
                || message.contains("binding has missing section"));
    }

    private boolean optionalFieldValuesConsistentCheck(FinalPromptMetricCheckContract checkContract) {
        FinalPromptMetricRule rule = checkContract == null ? null : checkContract.rule();
        String operator = normalizeCheckName(rule == null ? "" : rule.operator());
        return "OPTIONAL_FIELD_VALUES_CONSISTENT".equals(operator);
    }

    private String optionalFieldValuesConsistentRuntimeFacts(FinalPromptMetricCheckContract checkContract) {
        FinalPromptMetricRule rule = checkContract == null ? null : checkContract.rule();
        List<String> labels = rule == null ? List.of() : rule.labels();
        String labelText = labels == null || labels.isEmpty()
                ? message("verification.finalPrompt.comparison.selectableLabel")
                : labels.stream()
                        .filter(StringUtils::hasText)
                        .map(String::trim)
                        .distinct()
                        .collect(Collectors.joining(", "));
        if (!StringUtils.hasText(labelText)) {
            labelText = message("verification.finalPrompt.comparison.selectableLabel");
        }
        return message("verification.finalPrompt.comparison.noActualValue", labelText);
    }
    private boolean customerRuntimeFactsContainHardMissing(String runtimeFacts) {
        if (!StringUtils.hasText(runtimeFacts)) {
            return true;
        }
        String normalized = runtimeFacts
                .toLowerCase(Locale.ROOT)
                .replace(' ', ' ')
                .replaceAll("\\s+", " ");
        return normalized.contains(" n/a")
                || normalized.contains("값은 n/a")
                || normalized.contains("value is n/a")
                || normalized.contains("value n/a")
                || normalized.contains("=n/a")
                || normalized.contains("값은 missing")
                || normalized.contains("value is missing")
                || normalized.contains("=missing")
                || normalized.contains("missing(line")
                || normalized.contains("no input values");
    }

    private FinalPromptMetricCheck check(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptMetricEvaluationContext context) {
        String checkCode = stableCheckCode(checkContract.checkName());
        String expected = requiredContractText(checkContract, checkContract.expectedMessage(), "expectedMessage");
        List<String> evidenceValues = evidenceValues(checkContract, passed, context);
        String detectedSignals = purposeDetectedSignalsJson(
                checkContract,
                passed ? "PURPOSE_PASSED" : "PURPOSE_FAILED",
                evidenceValues,
                displayVisibleCheck(checkContract));
        String fallbackActual = passed
                ? requiredContractText(checkContract, checkContract.passMessage(), "passMessage")
                : requiredContractText(checkContract, checkContract.failureMessage(), "failureMessage");
        String actual = displayActualValue(checkContract, passed, expected, fallbackActual, evidenceValues);
        String nextAction = requiredContractText(checkContract, checkContract.nextAction(), "nextAction");
        String reverify = requiredContractText(checkContract, checkContract.reverifyCriterion(), "reverifyCriterion");
        String evidence = previewList(evidenceValues);
        return new FinalPromptMetricCheck(
                metricCode(),
                checkCode,
                checkContract.checkName(),
                expected,
                actual,
                passed,
                checkContract.source(),
                passed ? "INFO" : checkContract.severity(),
                passed ? "" : checkContract.failureType(),
                checkContract.remediationOwner(),
                fallbackActual,
                passed ? "" : nextAction,
                reverify,
                passed ? "" : checkContract.issueKey(),
                checkContract.customerVisible(),
                readinessScope(checkContract),
                metricContract.version(),
                "READY",
                passed ? "PURPOSE_PASSED" : "PURPOSE_FAILED",
                detectedSignals,
                FinalPromptMetricInterpretationCodec.interpretationLinksJson(
                        metricContract, metricCode(), checkContract, passed, evidence),
                requiredContractText(checkContract, checkContract.qualityQuestion(), "qualityQuestion"),
                requiredContractText(checkContract, checkContract.whyItMatters(), "whyItMatters"));
    }

    private String displayActualValue(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            String expected,
            String fallbackActual,
            List<String> evidenceValues) {
        String fallback = requiredText(fallbackActual, "final prompt metric actual value");
        String detail = contractPurposeDetail(checkContract, passed, fallback);
        if (StringUtils.hasText(detail)
                && !normalizeCustomerPurposeText(detail).equals(normalizeCustomerPurposeText(expected))
                && !normalizeCustomerPurposeText(detail).equals(normalizeCustomerPurposeText(fallback))) {
            return detail;
        }
        if (displayVisibleCheck(checkContract)) {
            return fallback;
        }
        String evidence = firstDistinctEvidenceValue(expected, fallback, evidenceValues);
        if (StringUtils.hasText(evidence)) {
            return evidence;
        }
        return fallback;
    }

    private String firstDistinctEvidenceValue(String expected, String fallbackActual, List<String> evidenceValues) {
        if (evidenceValues == null || evidenceValues.isEmpty()) {
            return "";
        }
        String fallbackCandidate = "";
        for (String evidenceValue : evidenceValues) {
            String text = FinalPromptMetricInterpretationCodec.interpretationEvidenceText(evidenceValue);
            String runtimeFacts = FinalPromptMetricInterpretationCodec.interpretationRuntimeFactsText(evidenceValue);
            if (!StringUtils.hasText(text)) {
                text = runtimeFacts;
            }
            String normalized = normalizeCustomerPurposeText(text);
            if (!normalized.equals(normalizeCustomerPurposeText(expected))
                    && !normalized.equals(normalizeCustomerPurposeText(fallbackActual))) {
                return customerPurposeText(text);
            }
            String normalizedRuntimeFacts = normalizeCustomerPurposeText(runtimeFacts);
            if (StringUtils.hasText(runtimeFacts)
                    && !normalizedRuntimeFacts.equals(normalizeCustomerPurposeText(expected))
                    && !normalizedRuntimeFacts.equals(normalizeCustomerPurposeText(fallbackActual))) {
                return customerPurposeText(runtimeFacts);
            }
            if (!normalized.equals(normalizeCustomerPurposeText(expected))
                    && !StringUtils.hasText(fallbackCandidate)) {
                fallbackCandidate = customerPurposeText(text);
            }
        }
        return fallbackCandidate;
    }

    private boolean notApplicable(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricEvaluationContext context) {
        FinalPromptMetricRule applicabilityRule = checkContract == null ? null : checkContract.applicabilityRule();
        if (applicabilityRule == null || !StringUtils.hasText(applicabilityRule.operator())) {
            return false;
        }
        return !ruleEngine.evaluate(applicabilityRule, context);
    }

    private boolean conditionalRagMetricNotApplicable(FinalPromptMetricEvaluationContext context) {
        if (!"CONDITIONAL_RAG".equalsIgnoreCase(FinalPromptDisplayValues.firstNonBlank(metricContract.metricRole(), ""))) {
            return false;
        }
        return metricContract.checks().stream()
                .map(FinalPromptMetricCheckContract::applicabilityRule)
                .filter(rule -> rule != null && StringUtils.hasText(rule.operator()))
                .anyMatch(rule -> !ruleEngine.evaluate(rule, context));
    }

    private FinalPromptMetricInputReadiness inputReadiness(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricEvaluationContext context) {
        FinalPromptMetricRule readinessRule = checkContract == null ? null : checkContract.inputReadinessRule();
        if (readinessRule == null || !StringUtils.hasText(readinessRule.operator())) {
            return FinalPromptMetricInputReadiness.evaluate(checkContract == null ? null : checkContract.rule(), context);
        }
        if (ruleEngine.evaluate(readinessRule, context)) {
            return new FinalPromptMetricInputReadiness(
                    true,
                    List.of(),
                    evidenceValues(readinessRule, context));
        }
        return new FinalPromptMetricInputReadiness(
                false,
                evidenceValues(readinessRule, context),
                List.of());
    }

    private FinalPromptMetricCheck notApplicableCheck(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricEvaluationContext context) {
        String checkCode = stableCheckCode(checkContract.checkName());
        String expected = requiredContractText(checkContract, checkContract.expectedMessage(), "expectedMessage");
        String actual = requiredContractText(checkContract, checkContract.notApplicableMessage(), "notApplicableMessage");
        List<String> evidenceValues = evidenceValues(checkContract.applicabilityRule(), context);
        List<String> displayEvidenceValues = notApplicableEvidenceValues(checkContract, evidenceValues);
        String evidence = previewList(evidenceValues);
        String source = internalApplicabilitySource(checkCode);
        return new FinalPromptMetricCheck(
                metricCode(),
                checkCode,
                checkContract.checkName(),
                expected,
                actual,
                true,
                source,
                "INFO",
                "",
                checkContract.remediationOwner(),
                actual,
                "",
                requiredContractText(checkContract, checkContract.reverifyCriterion(), "reverifyCriterion"),
                source,
                checkContract.customerVisible(),
                "INTERNAL_REFERENCE",
                metricContract.version(),
                "NOT_APPLICABLE",
                "NOT_APPLICABLE",
                purposeDetectedSignalsJson(
                        checkContract,
                        "NOT_APPLICABLE",
                        displayEvidenceValues,
                        displayVisibleCheck(checkContract)),
                FinalPromptMetricInterpretationCodec.interpretationLinksJson(
                        metricContract, metricCode(), checkContract, "NOT_APPLICABLE", evidence),
                requiredContractText(checkContract, checkContract.qualityQuestion(), "qualityQuestion"),
                requiredContractText(checkContract, checkContract.whyItMatters(), "whyItMatters"));
    }

    private List<String> notApplicableEvidenceValues(
            FinalPromptMetricCheckContract checkContract,
            List<String> evidenceValues) {
        if (!displayVisibleCheck(checkContract)) {
            return evidenceValues == null ? List.of() : evidenceValues;
        }
        String title = requiredContractText(checkContract, checkContract.notApplicableMessage(), "notApplicableMessage");
        String detail = contractPurposeDetail(checkContract, true, title);
        if (!StringUtils.hasText(detail)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Not-applicable customer-visible evidence requires contract text. metric="
                    + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK"));
        }
        return List.of(customerPurposeEvidence(checkContract, title, detail, evidenceValues));
    }

    private FinalPromptMetricCheck inputMissingCheck(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricInputReadiness readiness) {
        String checkCode = stableCheckCode(checkContract.checkName());
        String missing = previewList(readiness.missingInputs());
        String present = previewList(readiness.presentInputs());
        String expected = requiredContractText(checkContract, checkContract.expectedMessage(), "expectedMessage");
        String actual = requiredContractText(checkContract, checkContract.failureMessage(), "failureMessage");
        String nextAction = requiredContractText(checkContract, checkContract.nextAction(), "nextAction");
        String reverify = requiredContractText(checkContract, checkContract.reverifyCriterion(), "reverifyCriterion");
        List<String> readinessSignals = new ArrayList<>();
        for (String presentInput : readiness.presentInputs()) {
            readinessSignals.add("present:" + presentInput);
        }
        for (String missingInput : readiness.missingInputs()) {
            readinessSignals.add("missing:" + missingInput);
        }
        return new FinalPromptMetricCheck(
                metricCode(),
                checkCode,
                checkContract.checkName(),
                expected,
                actual,
                false,
                internalInputSource(checkCode),
                "BLOCKING",
                "INPUT_NOT_READY",
                checkContract.remediationOwner(),
                actual,
                nextAction,
                reverify,
                internalInputSource(checkCode),
                false,
                "METRIC_INPUT_READINESS",
                metricContract.version(),
                "INPUT_NOT_READY",
                "INPUT_NOT_READY",
                purposeDetectedSignalsJson(checkContract, "INPUT_NOT_READY", readinessSignals, false),
                FinalPromptMetricInterpretationCodec.readinessInterpretationJson(
                        metricContract, metricCode(), checkContract,
                        previewList(readiness.missingInputs()), previewList(readiness.presentInputs())),
                requiredContractText(checkContract, checkContract.qualityQuestion(), "qualityQuestion"),
                requiredContractText(checkContract, checkContract.whyItMatters(), "whyItMatters"));
    }

    private String internalInputSource(String checkCode) {
        return "internalGate.metricInput." + metricCode() + "." + FinalPromptDisplayValues.firstNonBlank(checkCode, "CHECK");
    }

    private String internalApplicabilitySource(String checkCode) {
        return "internalGate.metricApplicability." + metricCode() + "." + FinalPromptDisplayValues.firstNonBlank(checkCode, "CHECK");
    }

    private String readinessScope(FinalPromptMetricCheckContract checkContract) {
        String scope = checkContract == null ? "" : checkContract.readinessScope();
        if (StringUtils.hasText(scope)) {
            return scope.trim();
        }
        return checkContract != null && checkContract.customerVisible()
                ? "CUSTOMER_PROMPT_QUALITY"
                : "INTERNAL_EXECUTION_GATE";
    }

    private String requiredContractText(
            FinalPromptMetricCheckContract checkContract,
            String value,
            String fieldName) {
        if (StringUtils.hasText(value)) {
            return value.trim();
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Final prompt metric check contract is missing " + fieldName
                + ". metricCode=" + metricCode()
                + ", checkName=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? "" : checkContract.checkName(), "UNKNOWN_CHECK"));
    }

    private String ruleEvidenceSummary(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context) {
        if (rule == null) {
            return "";
        }
        EvidenceCollector collector = new EvidenceCollector();
        collectEvidence(rule, context, collector);
        return collector.summary();
    }

    private String ruleEvidenceJson(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context) {
        if (rule == null) {
            return "[]";
        }
        EvidenceCollector collector = new EvidenceCollector();
        collectEvidence(rule, context, collector);
        return FinalPromptMetricInterpretationCodec.jsonArray(collector.values());
    }

    private String purposeDetectedSignalsJson(
            FinalPromptMetricCheckContract checkContract,
            String purposeResult,
            List<String> evidenceValues) {
        return purposeDetectedSignalsJson(
                checkContract,
                purposeResult,
                evidenceValues,
                checkContract != null && checkContract.customerVisible());
    }

    private String purposeDetectedSignalsJson(
            FinalPromptMetricCheckContract checkContract,
            String purposeResult,
            List<String> evidenceValues,
            boolean requireStructuredCustomerEvidence) {
        if (requireStructuredCustomerEvidence) {
            return FinalPromptMetricInterpretationCodec.jsonArray(requireCustomerDisplayEvidence(checkContract, evidenceValues));
        }
        List<String> structured = new ArrayList<>();
        if (evidenceValues != null) {
            for (String evidenceValue : evidenceValues) {
                if (!StringUtils.hasText(evidenceValue)) {
                    continue;
                }
                String trimmed = evidenceValue.trim();
                if (trimmed.startsWith("{")
                        && trimmed.endsWith("}")
                        && trimmed.contains("\"signalKey\"")
                        && trimmed.contains("\"evidenceValue\"")) {
                    structured.add(trimmed);
                }
            }
        }
        if (!structured.isEmpty()) {
            return FinalPromptMetricInterpretationCodec.jsonArray(structured);
        }
        String title = purposeResultTitle(checkContract, purposeResult);
        String detail = purposeResultDetail(checkContract, purposeResult, title);
        if (!StringUtils.hasText(title) || !StringUtils.hasText(detail)
                || normalizeCustomerPurposeText(title).equals(normalizeCustomerPurposeText(detail))) {
            return "[]";
        }
        return FinalPromptMetricInterpretationCodec.jsonArray(List.of(customerPurposeEvidence(title, detail)));
    }

    private String purposeResultTitle(
            FinalPromptMetricCheckContract checkContract,
            String purposeResult) {
        if (checkContract == null) {
            return "";
        }
        String normalized = purposeResult == null ? "" : purposeResult.trim().toUpperCase(Locale.ROOT);
        if ("NOT_APPLICABLE".equals(normalized)) {
            return FinalPromptDisplayValues.firstNonBlank(checkContract.notApplicableMessage(), checkContract.passMessage(), checkContract.expectedMessage());
        }
        if ("INPUT_NOT_READY".equals(normalized)) {
            return FinalPromptDisplayValues.firstNonBlank(checkContract.problemTitle(), checkContract.failureMessage(), checkContract.expectedMessage());
        }
        if ("PURPOSE_FAILED".equals(normalized) || "FAILED".equals(normalized)) {
            return FinalPromptDisplayValues.firstNonBlank(checkContract.problemTitle(), checkContract.failureMessage(), checkContract.expectedMessage());
        }
        return FinalPromptDisplayValues.firstNonBlank(checkContract.passMessage(), checkContract.expectedMessage(), checkContract.qualityQuestion());
    }

    private String purposeResultDetail(
            FinalPromptMetricCheckContract checkContract,
            String purposeResult,
            String title) {
        if (checkContract == null) {
            return "";
        }
        String normalized = purposeResult == null ? "" : purposeResult.trim().toUpperCase(Locale.ROOT);
        boolean passed = !("PURPOSE_FAILED".equals(normalized)
                || "FAILED".equals(normalized)
                || "INPUT_NOT_READY".equals(normalized));
        String detail = contractPurposeDetail(checkContract, passed, title);
        if (StringUtils.hasText(detail)
                && !normalizeCustomerPurposeText(detail).equals(normalizeCustomerPurposeText(title))) {
            return detail;
        }
        return firstDistinctContractText(
                title,
                checkContract.whyItMatters(),
                checkContract.qualityQuestion(),
                checkContract.securityRelevance(),
                checkContract.meaning(),
                checkContract.interpretationLink(),
                checkContract.expectedMessage(),
                checkContract.failureMessage(),
                checkContract.reverifyCriterion());
    }

    private List<String> requireCustomerDisplayEvidence(
            FinalPromptMetricCheckContract checkContract,
            List<String> evidenceValues) {
        if (evidenceValues == null || evidenceValues.isEmpty()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence is missing. metric="
                    + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK"));
        }
        List<String> structured = new ArrayList<>();
        for (String evidenceValue : evidenceValues) {
            if (!StringUtils.hasText(evidenceValue)) {
                continue;
            }
            String trimmed = evidenceValue.trim();
            if (!trimmed.startsWith("{") || !trimmed.endsWith("}")
                    || !trimmed.contains("\"signalKey\"")
                    || !trimmed.contains("\"evidenceValue\"")) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence must be structured. metric="
                        + metricCode()
                        + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK"));
            }
            structured.add(trimmed);
        }
        if (structured.isEmpty()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence did not produce display payload. metric="
                    + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK"));
        }
        return structured;
    }

    private void addContractSignal(List<String> values, String key, String value) {
        if (values == null || !StringUtils.hasText(key) || !StringUtils.hasText(value)) {
            return;
        }
        values.add(key.trim() + "=" + value.trim());
    }

    private List<String> evidenceValues(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context) {
        if (rule == null) {
            return List.of();
        }
        EvidenceCollector collector = new EvidenceCollector();
        collectEvidence(rule, context, collector);
        return collector.values();
    }

    private List<String> evidenceValues(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptMetricEvaluationContext context) {
        if (checkContract == null) {
            return List.of();
        }
        List<String> purposeEvidence = purposeEvidenceValues(checkContract, passed, context);
        if (!purposeEvidence.isEmpty()) {
            return purposeEvidence;
        }
        if (displayVisibleCheck(checkContract)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence is not contract-backed. metric="
                    + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract.checkName(), "UNKNOWN_CHECK"));
        }
        return evidenceValues(checkContract.rule(), context);
    }

    private List<String> purposeEvidenceValues(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptMetricEvaluationContext context) {
        String contractEvidence = renderContractEvidenceTemplate(checkContract, passed, context);
        if (displayVisibleCheck(checkContract)) {
            String title = passed
                    ? requiredContractText(checkContract, checkContract.passMessage(), "passMessage")
                    : requiredContractText(
                            checkContract,
                            FinalPromptDisplayValues.firstNonBlank(checkContract.problemTitle(), checkContract.failureMessage()),
                            "problemTitle");
            if (!StringUtils.hasText(contractEvidence)) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible evidence template is required. metric="
                        + metricCode()
                        + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract.checkName(), "UNKNOWN_CHECK"));
            }
            return List.of(customerPurposeEvidence(checkContract, title, contractEvidence, passed, context));
        }
        if (StringUtils.hasText(contractEvidence)) {
            String title = passed
                    ? requiredContractText(checkContract, checkContract.passMessage(), "passMessage")
                    : requiredContractText(
                            checkContract,
                            FinalPromptDisplayValues.firstNonBlank(checkContract.problemTitle(), checkContract.failureMessage()),
                            "problemTitle");
            return List.of(customerPurposeEvidence(title, contractEvidence));
        }
        return List.of();
    }

    private boolean displayVisibleCheck(FinalPromptMetricCheckContract checkContract) {
        return checkContract != null
                && (checkContract.customerVisible()
                || "INTERNAL_EXECUTION_GATE".equalsIgnoreCase(readinessScope(checkContract)));
    }

    private String renderContractEvidenceTemplate(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptMetricEvaluationContext context) {
        String template = passed
                ? (checkContract == null ? "" : checkContract.passEvidenceTemplate())
                : (checkContract == null ? "" : checkContract.failureEvidenceTemplate());
        if (!StringUtils.hasText(template)) {
            return "";
        }
        FinalPromptSnapshot prompt = context == null ? null : context.prompt();
        if (prompt == null) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Evidence template requires final prompt snapshot. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK"));
        }
        String displayTemplate = displayVisibleCheck(checkContract)
                ? customerVisibleConclusionTemplate(checkContract, passed, template)
                : template;
        Map<String, String> placeholders = contractEvidencePlaceholders(checkContract, passed, context, prompt, displayTemplate);
        String rendered = renderTemplate(displayTemplate, placeholders);
        if (rendered.contains("{{") || rendered.contains("}}")) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Evidence template contains unresolved placeholder. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK"));
        }
        String text = customerPurposeText(rendered);
        if (checkContract != null && displayVisibleCheck(checkContract) && customerVisibleEvidenceUnsafe(text)) {
            String headline = passed
                    ? requiredContractText(checkContract, checkContract.passMessage(), "passMessage")
                    : requiredContractText(
                            checkContract,
                            FinalPromptDisplayValues.firstNonBlank(checkContract.problemTitle(), checkContract.failureMessage()),
                            "problemTitle");
            text = contractPurposeDetail(checkContract, passed, headline);
        }
        if (checkContract != null && displayVisibleCheck(checkContract) && customerVisibleEvidenceUnsafe(text)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible evidence template renders raw technical text. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract.checkName(), "UNKNOWN_CHECK"));
        }
        return text;
    }

    private String customerVisibleConclusionTemplate(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            String template) {
        String conclusion = removeEvidenceBindingSentences(template);
        if (StringUtils.hasText(conclusion)) {
            return conclusion;
        }
        String fallback = passed
                ? FinalPromptDisplayValues.firstNonBlank(
                checkContract == null ? null : checkContract.passMessage(),
                checkContract == null ? null : checkContract.interpretationLink(),
                checkContract == null ? null : checkContract.meaning())
                : FinalPromptDisplayValues.firstNonBlank(
                checkContract == null ? null : checkContract.failureMessage(),
                checkContract == null ? null : checkContract.problemTitle(),
                checkContract == null ? null : checkContract.interpretationLink());
        return requiredText(fallback, "customer-visible purpose conclusion template");
    }

    private String removeEvidenceBindingSentences(String template) {
        if (!StringUtils.hasText(template)) {
            return "";
        }
        List<String> sentences = new ArrayList<>();
        for (String raw : template.trim().split("(?<=[.!?])\\s+")) {
            if (!StringUtils.hasText(raw)) {
                continue;
            }
            String sentence = raw.trim();
            if (sentence.contains("{{") || sentence.contains("}}")) {
                continue;
            }
            sentences.add(sentence);
        }
        return String.join(" ", sentences).trim();
    }

    private Map<String, String> contractEvidencePlaceholders(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptMetricEvaluationContext context,
            FinalPromptSnapshot prompt,
            String template) {
        Map<String, String> values = baseContractEvidencePlaceholders(checkContract);
        List<Map<String, String>> bindings = checkContract == null ? null : checkContract.evidenceBindings();
        if (bindings == null) {
            return values;
        }
        for (Map<String, String> binding : bindings) {
            if (binding != null) {
                addContractEvidenceBinding(values, checkContract, binding, passed, context, prompt, template);
            }
        }
        return values;
    }

    private Map<String, String> baseContractEvidencePlaceholders(
            FinalPromptMetricCheckContract checkContract) {
        Map<String, String> values = new LinkedHashMap<>();
        addContractTemplateValue(values, "purposeSignal", checkContract == null ? "" : checkContract.purposeSignal());
        addContractTemplateValue(values, "meaning", checkContract == null ? "" : checkContract.meaning());
        addContractTemplateValue(values, "securityRelevance", checkContract == null ? "" : checkContract.securityRelevance());
        addContractTemplateValue(values, "interpretationLink", checkContract == null ? "" : checkContract.interpretationLink());
        addContractTemplateValue(values, "qualityQuestion", checkContract == null ? "" : checkContract.qualityQuestion());
        addContractTemplateValue(values, "expectedMessage", checkContract == null ? "" : checkContract.expectedMessage());
        addContractTemplateValue(values, "passMessage", checkContract == null ? "" : checkContract.passMessage());
        addContractTemplateValue(values, "failureMessage", checkContract == null ? "" : checkContract.failureMessage());
        addContractTemplateValue(values, "problemTitle", checkContract == null ? "" : checkContract.problemTitle());
        addContractTemplateValue(values, "whyItMatters", checkContract == null ? "" : checkContract.whyItMatters());
        addContractTemplateValue(values, "nextAction", checkContract == null ? "" : checkContract.nextAction());
        addContractTemplateValue(values, "reverifyCriterion", checkContract == null ? "" : checkContract.reverifyCriterion());
        return values;
    }

    private void addContractEvidenceBinding(
            Map<String, String> values,
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            boolean passed,
            FinalPromptMetricEvaluationContext context,
            FinalPromptSnapshot prompt,
            String template) {
        String id = binding.get("id");
        String label = binding.get("label");
        if (!StringUtils.hasText(id)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Evidence binding id is required. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK"));
        }
        if (!templateUsesBinding(template, id)) {
            return;
        }
        String renderedSpecial = renderContractSpecialBinding(checkContract, binding, passed, prompt, context);
        if (renderedSpecial != null) {
            values.put(id.trim(), renderedSpecial);
            return;
        }
        if (!StringUtils.hasText(label)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Evidence binding label is required. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK")
                    + ", binding=" + id);
        }
        String rawValue = prompt.firstValue(label);
        if (!StringUtils.hasText(rawValue)) {
            if (!contractBindingRequired(binding)) {
                values.put(id.trim(), "");
                return;
            }
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Evidence template binding has no prompt value. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK")
                    + ", binding=" + id
                    + ", label=" + label);
        }
        values.put(id.trim(), renderContractBindingValue(checkContract, binding, rawValue));
    }
    private void addContractTemplateValue(Map<String, String> values, String key, String value) {
        if (values != null && StringUtils.hasText(key) && StringUtils.hasText(value)) {
            values.put(key.trim(), customerPurposeText(value));
        }
    }

    private boolean templateUsesBinding(String template, String id) {
        if (!StringUtils.hasText(template) || !StringUtils.hasText(id)) {
            return false;
        }
        Pattern placeholder = Pattern.compile("\\{\\{\\s*" + Pattern.quote(id.trim()) + "\\s*}}");
        return placeholder.matcher(template).find();
    }

    private String renderContractSpecialBinding(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            boolean passed,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context) {
        String source = FinalPromptDisplayValues.firstNonBlank(binding.get("source"), binding.get("type")).trim().toUpperCase(Locale.ROOT);
        if (!StringUtils.hasText(source)) {
            return null;
        }
        if ("RULE_PURPOSE_EVIDENCE".equals(source)) {
            return rulePurposeEvidence(checkContract, passed, context);
        }
        if ("SECTION_LIST".equals(source)) {
            return renderSectionListBinding(checkContract, binding, passed, prompt);
        }
        if ("TERM_LIST_PRESENT".equals(source)) {
            return renderTermListBinding(checkContract, binding, passed, prompt);
        }
        if ("FIRST_FIELD_VALUE".equals(source)) {
            return renderFirstFieldBinding(checkContract, binding, passed, prompt);
        }
        if ("FIELD_GROUP".equals(source)) {
            return renderFieldGroupBinding(checkContract, binding, passed, prompt);
        }
        if ("TRUNCATED_FACT_DETAILS".equals(source)) {
            return renderTruncatedFactBinding(checkContract, binding, passed, prompt);
        }
        if ("RAG_RUNTIME_STATE".equals(source)) {
            return ragRuntimeStateEvidence(checkContract, binding, prompt, context);
        }
        if ("INTERNALGATE.PROMPTFACTMAPPING".equals(source)) {
            return promptFactMappingRuntimeEvidence(binding, passed, prompt);
        }
        if (source.startsWith("INTERNALGATE.PROMPT")
                || "INTERNALGATE.RAWFINALPROMPTLINEAGE".equals(source)) {
            return promptTraceRuntimeEvidence(checkContract, binding, context == null ? null : context.evidence());
        }
        return null;
    }

    private String renderSectionListBinding(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            boolean passed,
            FinalPromptSnapshot prompt) {
        List<String> sections = splitContractList(binding.get("sections"));
        if (sections.isEmpty()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: SECTION_LIST binding requires sections. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK")
                    + ", binding=" + binding.get("id"));
        }
        List<String> present = sections.stream().filter(prompt::hasSection).toList();
        if (passed && present.size() != sections.size() && contractBindingRequired(binding)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: SECTION_LIST binding has missing section. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK")
                    + ", binding=" + binding.get("id"));
        }
        return present.isEmpty() && !contractBindingRequired(binding)
                ? FinalPromptDisplayValues.firstNonBlank(binding.get("emptyValue"), "")
                : String.join(", ", present);
    }

    private String renderTermListBinding(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            boolean passed,
            FinalPromptSnapshot prompt) {
        List<String> terms = splitContractList(binding.get("terms"));
        if (terms.isEmpty()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: TERM_LIST_PRESENT binding requires terms. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK")
                    + ", binding=" + binding.get("id"));
        }
        List<String> present = terms.stream()
                .filter(prompt::contains)
                .map(term -> contractMappedValue(checkContract, term))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        if (passed && present.isEmpty() && contractBindingRequired(binding)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: TERM_LIST_PRESENT binding has no present term. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK")
                    + ", binding=" + binding.get("id"));
        }
        return present.isEmpty()
                ? FinalPromptDisplayValues.firstNonBlank(binding.get("emptyValue"), "")
                : String.join(", ", present);
    }

    private String renderFirstFieldBinding(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            boolean passed,
            FinalPromptSnapshot prompt) {
        List<String> labels = splitContractList(binding.get("labels"));
        if (labels.isEmpty()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: FIRST_FIELD_VALUE binding requires labels. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK")
                    + ", binding=" + binding.get("id"));
        }
        for (String label : labels) {
            String value = prompt.firstValue(label);
            if (usableRuntimeDisplayValue(value)) {
                return renderContractBindingValue(checkContract, binding, value);
            }
        }
        if (passed && contractBindingRequired(binding)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: FIRST_FIELD_VALUE binding has no prompt value. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK")
                    + ", binding=" + binding.get("id"));
        }
        return FinalPromptDisplayValues.firstNonBlank(binding.get("emptyValue"), "");
    }

    private String renderFieldGroupBinding(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            boolean passed,
            FinalPromptSnapshot prompt) {
        List<String> labels = splitContractList(binding.get("labels"));
        if (labels.isEmpty()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: FIELD_GROUP binding requires labels. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK")
                    + ", binding=" + binding.get("id"));
        }
        List<String> values = labels.stream()
                .map(label -> {
                    String value = prompt.firstValue(label);
                    return StringUtils.hasText(value) ? runtimeBindingFact(checkContract, binding, label, value) : "";
                })
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        if (values.isEmpty() && StringUtils.hasText(binding.get("fallbackTerms"))) {
            values = splitContractList(binding.get("fallbackTerms")).stream()
                    .filter(prompt::contains)
                    .map(term -> contractMappedValue(checkContract, term))
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList();
        }
        if (passed && values.isEmpty() && contractBindingRequired(binding)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: FIELD_GROUP binding has no prompt value. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK")
                    + ", binding=" + binding.get("id"));
        }
        return values.isEmpty() ? FinalPromptDisplayValues.firstNonBlank(binding.get("emptyValue"), "") : joinCustomerSentences(values);
    }

    private String renderTruncatedFactBinding(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            boolean passed,
            FinalPromptSnapshot prompt) {
        String details = truncatedFactDetails(checkContract, prompt);
        if (passed && !StringUtils.hasText(details) && contractBindingRequired(binding)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: TRUNCATED_FACT_DETAILS binding has no prompt value. "
                    + "metric=" + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK")
                    + ", binding=" + binding.get("id"));
        }
        if (StringUtils.hasText(details)) {
            return details;
        }
        return FinalPromptDisplayValues.firstNonBlank(binding.get("emptyValue"),
                message("verification.finalPrompt.truncation.none"));
    }
    private String promptTraceRuntimeEvidence(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            FinalPromptEvidenceContext evidence) {
        if (binding == null || evidence == null) {
            return "";
        }
        List<String> items = new ArrayList<>();
        addContractItems(items, binding.get("runtimeFactItems"));
        addContractItems(items, binding.get("customerVisibleRuntimeItems"));
        if (items.isEmpty()) {
            addContractItems(items, binding.get("customerVisibleContextItems"));
            addContractItems(items, binding.get("contextItems"));
            addContractItems(items, binding.get("labels"));
            addContractItems(items, binding.get("label"));
        }
        List<String> facts = new ArrayList<>();
        for (String item : items) {
            String value = promptTraceValue(evidence, item);
            if (StringUtils.hasText(value)) {
                facts.add(readableFact(checkContract, item, value));
            }
        }
        return joinCustomerSentences(facts.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .toList());
    }

    private String promptTraceValue(FinalPromptEvidenceContext evidence, String item) {
        if (evidence == null || !StringUtils.hasText(item)) {
            return "";
        }
        String key = item.trim().toLowerCase(Locale.ROOT);
        return switch (key) {
            case "packageid" -> evidence.packageId();
            case "prompthash", "finalprompthash" -> evidence.promptHash();
            case "userprompthash" -> evidence.userPromptHash();
            case "systemprompthash" -> evidence.systemPromptHash();
            case "rawprompthash", "rawuserprompthash" -> evidence.rawUserPromptHash();
            case "rawsystemprompthash" -> evidence.rawSystemPromptHash();
            case "systempromptartifact" -> FinalPromptDisplayValues.presentText(FinalPromptDisplayValues.firstNonBlank(evidence.systemPrompt(), evidence.systemPromptHash()), messageResolver);
            case "userpromptartifact" -> FinalPromptDisplayValues.presentText(FinalPromptDisplayValues.firstNonBlank(evidence.rawUserPrompt(), evidence.userPromptHash()), messageResolver);
            case "promptmanifest" -> FinalPromptDisplayValues.presentText(evidence.promptEvidenceManifestJson(), messageResolver);
            case "promptlineage" -> StringUtils.hasText(evidence.rawUserPromptHash())
                    && StringUtils.hasText(evidence.userPromptHash()) ? message("verification.finalPrompt.value.present") : message("verification.finalPrompt.value.absent");
            default -> "";
        };
    }

    private String promptFactMappingRuntimeEvidence(
            Map<String, String> binding,
            boolean passed,
            FinalPromptSnapshot prompt) {
        if (binding == null || prompt == null) {
            return "";
        }
        String template = passed
                ? binding.get("template")
                : FinalPromptDisplayValues.firstNonBlank(binding.get("failureTemplate"), binding.get("template"));
        if (!StringUtils.hasText(template)) {
            return "";
        }
        List<FinalPromptUnmappedFact> unmappedFacts = prompt.unmappedFacts();
        FinalPromptUnmappedFact first = unmappedFacts.isEmpty() ? null : unmappedFacts.get(0);
        Map<String, String> values = new LinkedHashMap<>();
        values.put("count", String.valueOf(unmappedFacts.size()));
        values.put("firstSection", first == null ? "" : FinalPromptDisplayValues.firstNonBlank(first.section(), ""));
        values.put("firstLabel", first == null ? "" : FinalPromptDisplayValues.firstNonBlank(first.label(), ""));
        values.put("firstLine", first == null ? "" : String.valueOf(first.lineNumber()));
        values.put("firstErrorCode", first == null ? "" : FinalPromptDisplayValues.firstNonBlank(first.errorCode(), ""));
        String rendered = renderTemplate(template, values);
        return rendered.contains("{{") || rendered.contains("}}") ? "" : customerPurposeText(rendered);
    }

    private String ragRuntimeStateEvidence(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context) {
        if (displayVisibleCheck(checkContract)) {
            String purposeFacts = purposeSpecificDisplayRuntimeFacts(checkContract, binding, prompt, context);
            if (StringUtils.hasText(purposeFacts)) {
                return purposeFacts;
            }
        }
        List<String> labels = contractBindingLabels(binding);
        Map<String, Object> rag = context == null || context.evidence() == null
                ? Map.of()
                : context.evidence().ragResults();
        List<String> values = new ArrayList<>();
        for (String label : labels) {
            String rawValue = prompt == null ? "" : prompt.firstValue(label);
            if (!StringUtils.hasText(rawValue)) {
                rawValue = String.valueOf(FinalPromptDisplayValues.firstPresent(rag, FinalPromptDisplayValues.lowerFirst(label), label));
            }
            if ("RagApplicability".equalsIgnoreCase(label) && !StringUtils.hasText(rawValue)) {
                rawValue = valueAfter(ragApplicabilityEvidence(context, checkContract == null ? null : checkContract.rule()),
                        "ragApplicability=");
            }
            if (StringUtils.hasText(rawValue) && !"null".equalsIgnoreCase(rawValue.trim())) {
                values.add(readableFact(checkContract, label, rawValue));
            }
        }
        if (values.isEmpty() && contractBindingRequired(binding)) {
            return runtimeFallbackEvidence(
                    checkContract,
                    true,
                    checkContract == null ? "" : checkContract.passMessage());
        }
        return joinCustomerSentences(values.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .toList());
    }

    private String joinCustomerSentences(List<String> values) {
        if (values == null || values.isEmpty()) {
            return "";
        }
        return values.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .map(this::trimSentenceEnd)
                .filter(StringUtils::hasText)
                .distinct()
                .collect(Collectors.joining(". "));
    }

    private String trimSentenceEnd(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.trim().replaceAll("[.!?。]+$", "");
    }

    private String runtimeFallbackEvidence(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            String headline) {
        return displayVisibleCheck(checkContract)
                ? ""
                : contractPurposeDetail(checkContract, passed, headline);
    }

    private String rulePurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptMetricEvaluationContext context) {
        FinalPromptMetricRule rule = checkContract == null ? null : checkContract.rule();
        FinalPromptSnapshot prompt = context == null ? null : context.prompt();
        String operator = normalizeCheckName(rule == null ? "" : rule.operator());
        if (isCorePurposeOperator(operator)) {
            return coreRulePurposeEvidence(checkContract, rule, prompt, operator, passed, context);
        }
        if (isRagPurposeOperator(operator)) {
            return ragRulePurposeEvidence(checkContract, rule, prompt, operator, context);
        }
        if ("ALL".equals(operator)) {
            String compositeEvidence = compositeRulePurposeEvidence(checkContract, rule, prompt, passed);
            if (StringUtils.hasText(compositeEvidence)) {
                return compositeEvidence;
            }
        }
        return fallbackRulePurposeEvidence(checkContract, rule, passed, context);
    }

    private boolean isCorePurposeOperator(String operator) {
        return Set.of(
                "FIELD_VALUES_CONSISTENT",
                "OPTIONAL_FIELD_VALUES_CONSISTENT",
                "BOOLEAN_FIELDS_CONSISTENT",
                "SENSITIVE_FLAG_CONSISTENT",
                "IF_ANY_TERM_PRESENT_THEN_ANY_FIELD_OR_TERM_PRESENT",
                "IF_ANY_TERM_PRESENT_THEN_FORBIDDEN_TERMS_ABSENT",
                "FORBIDDEN_TERMS_ABSENT",
                "SYSTEM_TERM_GROUPS_PRESENT").contains(operator);
    }

    private String coreRulePurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            FinalPromptSnapshot prompt,
            String operator,
            boolean passed,
            FinalPromptMetricEvaluationContext context) {
        return switch (operator) {
            case "FIELD_VALUES_CONSISTENT", "OPTIONAL_FIELD_VALUES_CONSISTENT", "BOOLEAN_FIELDS_CONSISTENT" ->
                    consistencyPurposeEvidence(checkContract, prompt, rule == null ? List.of() : rule.labels(), operator, passed);
            case "SENSITIVE_FLAG_CONSISTENT" ->
                    sensitivePurposeEvidence(checkContract, prompt, rule == null ? List.of() : rule.labels(), passed);
            case "IF_ANY_TERM_PRESENT_THEN_ANY_FIELD_OR_TERM_PRESENT" ->
                    termSupportPurposeEvidence(checkContract, rule, prompt, passed);
            case "IF_ANY_TERM_PRESENT_THEN_FORBIDDEN_TERMS_ABSENT" ->
                    forbiddenTermPurposeEvidence(checkContract, rule, prompt, passed);
            case "FORBIDDEN_TERMS_ABSENT" -> plainForbiddenTermsPurposeEvidence(checkContract, rule, prompt);
            case "SYSTEM_TERM_GROUPS_PRESENT" -> systemTermGroupPurposeEvidence(checkContract, rule, context, passed);
            default -> "";
        };
    }

    private boolean isRagPurposeOperator(String operator) {
        return Set.of(
                "RAG_NOT_FAILED_WHEN_USED",
                "RAG_DOCUMENT_SURFACE_PRESENT",
                "RAG_NO_SCOPE_MISMATCH_DOCUMENT",
                "RAG_BLOCKED_DOCUMENT_EXCLUDED",
                "RAG_TEXT_TERM_GROUPS_PRESENT_WHEN_RAG_PRESENT",
                "RAG_TEXT_FORBIDDEN_TERMS_ABSENT").contains(operator);
    }

    private String ragRulePurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            FinalPromptSnapshot prompt,
            String operator,
            FinalPromptMetricEvaluationContext context) {
        FinalPromptEvidenceContext evidence = context == null ? null : context.evidence();
        return switch (operator) {
            case "RAG_NOT_FAILED_WHEN_USED" -> ragStateSummary(
                    checkContract, prompt, evidence,
                    "RagSearchExecuted", "RagRetrievalState", "RagAbsenceReason");
            case "RAG_DOCUMENT_SURFACE_PRESENT" -> ragStateSummary(
                    checkContract, prompt, evidence,
                    "RagProjectionState", "RagProjectedToFinalPrompt", "RelatedDocumentCount");
            case "RAG_NO_SCOPE_MISMATCH_DOCUMENT" ->
                    ragContaminationScopeSummary(checkContract, prompt, evidence);
            case "RAG_BLOCKED_DOCUMENT_EXCLUDED" -> ragStateSummary(
                    checkContract, prompt, evidence,
                    "RagDeniedDocumentCount", "RagAuthorizedDocumentCount", "RagPermissionFiltered", "RagProjectionState");
            case "RAG_TEXT_TERM_GROUPS_PRESENT_WHEN_RAG_PRESENT" ->
                    ragTermGroupsPurposeEvidence(checkContract, rule, context);
            case "RAG_TEXT_FORBIDDEN_TERMS_ABSENT" ->
                    ragForbiddenTermsPurposeEvidence(checkContract, rule, context);
            default -> "";
        };
    }

    private String fallbackRulePurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            boolean passed,
            FinalPromptMetricEvaluationContext context) {
        String headline = passed
                ? requiredContractText(checkContract, checkContract.passMessage(), "passMessage")
                : requiredContractText(checkContract, checkContract.failureMessage(), "failureMessage");
        String readable = readableEvidenceFacts(checkContract, evidenceValues(rule, context));
        if (StringUtils.hasText(readable)) {
            if (checkContract != null && checkContract.customerVisible() && customerVisibleEvidenceUnsafe(readable)) {
                return "";
            }
            return readable;
        }
        if (checkContract != null && checkContract.customerVisible()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible runtime evidence must be derived from prompt facts. metric="
                    + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract.checkName(), "UNKNOWN_CHECK"));
        }
        return contractPurposeDetail(checkContract, passed, headline);
    }
    private String compositeRulePurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            FinalPromptSnapshot prompt,
            boolean passed) {
        if (rule == null || rule.all() == null || rule.all().isEmpty()) {
            return "";
        }
        List<String> parts = new ArrayList<>();
        for (FinalPromptMetricRule child : rule.all()) {
            String childOperator = normalizeCheckName(child == null ? "" : child.operator());
            String childEvidence = "";
            if ("IF_ANY_TERM_PRESENT_THEN_ANY_FIELD_OR_TERM_PRESENT".equals(childOperator)) {
                childEvidence = termSupportPurposeEvidence(checkContract, child, prompt, passed);
            }
            else if ("IF_ANY_TERM_PRESENT_THEN_FORBIDDEN_TERMS_ABSENT".equals(childOperator)) {
                childEvidence = forbiddenTermPurposeEvidence(checkContract, child, prompt, passed);
            }
            if (StringUtils.hasText(childEvidence)) {
                parts.add(childEvidence);
            }
        }
        return joinCustomerSentences(parts.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .toList());
    }

    private String termSupportPurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            FinalPromptSnapshot prompt,
            boolean passed) {
        String headline = passed
                ? requiredContractText(checkContract, checkContract.passMessage(), "passMessage")
                : requiredContractText(checkContract, checkContract.failureMessage(), "failureMessage");
        String termGroupLabel = contractSpecialMapping(checkContract, "__termGroupLabel", "input signal");
        String supportGroupLabel = contractSpecialMapping(checkContract, "__thenGroupLabel", "interpretation evidence");
        List<String> triggerTerms = rule == null ? List.of() : rule.terms();
        List<String> supportTermCandidates = rule == null ? List.of() : rule.thenTerms();
        List<String> presentTerms = mappedPresentTerms(checkContract, prompt, triggerTerms);
        List<String> absentTerms = mappedAbsentTerms(checkContract, prompt, triggerTerms);
        List<String> supportTerms = mappedPresentTerms(checkContract, prompt, supportTermCandidates);
        List<String> missingSupportTerms = mappedAbsentTerms(checkContract, prompt, supportTermCandidates);
        List<String> support = new ArrayList<>();
        support.addAll(readableLabels(checkContract, prompt, rule == null ? List.of() : rule.labels()));
        support.addAll(readableLabels(checkContract, prompt, rule == null ? List.of() : rule.thenLabels()));
        support.addAll(supportTerms);
        List<String> parts = new ArrayList<>();
        if (!displayVisibleCheck(checkContract) && presentTerms.isEmpty() && passed) {
            String absencePassEvidence = contractSpecialMapping(checkContract, "__termAbsentPassEvidence", "");
            if (StringUtils.hasText(absencePassEvidence)) {
                parts.add(absencePassEvidence);
            }
        }
        if (!presentTerms.isEmpty()) {
            parts.add(termGroupLabel + ": " + String.join(", ", presentTerms));
        }
        if (!displayVisibleCheck(checkContract) && presentTerms.isEmpty() && !absentTerms.isEmpty()) {
            parts.add(message("verification.finalPrompt.trigger.missing", FinalPromptDisplayValues.clippedCustomerList(absentTerms, 5, messageResolver)));
        }
        if (!support.isEmpty()) {
            parts.add(supportGroupLabel + ": " + String.join(", ", support));
        }
        if (!displayVisibleCheck(checkContract) && support.isEmpty() && !missingSupportTerms.isEmpty()) {
            parts.add(message("verification.finalPrompt.support.missing", FinalPromptDisplayValues.clippedCustomerList(missingSupportTerms, 5, messageResolver)));
        }
        if (parts.isEmpty()) {
            String fallback = runtimeFallbackEvidence(checkContract, passed, headline);
            if (StringUtils.hasText(fallback)) {
                parts.add(fallback);
            }
        }
        return joinCustomerSentences(parts);
    }

    private String forbiddenTermPurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            FinalPromptSnapshot prompt,
            boolean passed) {
        String headline = passed
                ? requiredContractText(checkContract, checkContract.passMessage(), "passMessage")
                : requiredContractText(checkContract, checkContract.failureMessage(), "failureMessage");
        String termGroupLabel = contractSpecialMapping(checkContract, "__termGroupLabel", "input signal");
        List<String> presentTerms = mappedPresentTerms(checkContract, prompt, rule == null ? List.of() : rule.terms());
        String absenceMessage = contractSpecialMapping(checkContract, "__forbiddenAbsenceMessage", "");
        List<String> parts = new ArrayList<>();
        if (!presentTerms.isEmpty()) {
            parts.add(termGroupLabel + ": " + String.join(", ", presentTerms));
        }
        if (!displayVisibleCheck(checkContract) && StringUtils.hasText(absenceMessage)) {
            parts.add(absenceMessage);
        }
        if (parts.isEmpty()) {
            String fallback = runtimeFallbackEvidence(checkContract, passed, headline);
            if (StringUtils.hasText(fallback)) {
                parts.add(fallback);
            }
        }
        return joinCustomerSentences(parts);
    }

    private String plainForbiddenTermsPurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            FinalPromptSnapshot prompt) {
        List<String> terms = rule == null ? List.of() : rule.forbiddenTerms();
        if (terms == null || terms.isEmpty()) {
            terms = rule == null ? List.of() : rule.terms();
        }
        if (prompt == null || terms == null || terms.isEmpty()) {
            return "";
        }
        List<String> present = terms.stream()
                .filter(prompt::contains)
                .map(term -> contractMappedValue(checkContract, term))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        List<String> absent = terms.stream()
                .filter(term -> !prompt.contains(term))
                .map(term -> contractMappedValue(checkContract, term))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        List<String> facts = new ArrayList<>();
        if (!present.isEmpty()) {
            if (displayVisibleCheck(checkContract)) {
                facts.add(readableFact(checkContract, "ForbiddenTermMatchCount", String.valueOf(present.size())));
            }
            else {
                facts.add(message("verification.finalPrompt.rag.forbiddenFound", String.join(", ", present)));
            }
        }
        if (!displayVisibleCheck(checkContract) && !absent.isEmpty()) {
            facts.add(message("verification.finalPrompt.rag.forbiddenAbsent", String.join(", ", absent)));
        }
        return joinCustomerSentences(facts);
    }

    private String ragTermGroupsPurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context) {
        String ragText = ragText(context == null ? null : context.prompt(), rule);
        if (!StringUtils.hasText(ragText)) {
            return "";
        }
        if (displayVisibleCheck(checkContract)) {
            return visibleRagTermGroupPurposeEvidence(checkContract, rule, ragText);
        }
        return detailedRagTermGroupPurposeEvidence(checkContract, rule, ragText);
    }

    private String visibleRagTermGroupPurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            String ragText) {
        int matchedGroups = 0;
        int missingGroups = 0;
        if (rule != null && rule.labelGroups() != null) {
            for (List<String> group : rule.labelGroups()) {
                List<String> groupTerms = ragGroupTerms(group);
                if (groupTerms.isEmpty()) {
                    continue;
                }
                if (groupTerms.stream().anyMatch(term -> containsIgnoreCase(ragText, term))) {
                    matchedGroups++;
                }
                else {
                    missingGroups++;
                }
            }
        }
        List<String> facts = new ArrayList<>();
        facts.add(readableFact(checkContract, "RagEvidenceRequirementMetCount", String.valueOf(matchedGroups)));
        facts.add(readableFact(checkContract, "RagEvidenceRequirementMissingCount", String.valueOf(missingGroups)));
        return joinCustomerSentences(facts.stream().filter(StringUtils::hasText).distinct().toList());
    }

    private String detailedRagTermGroupPurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            String ragText) {
        List<String> facts = new ArrayList<>();
        List<String> evidenceLines = ragEvidenceLines(ragText);
        if (!evidenceLines.isEmpty()) {
            facts.add(message("verification.finalPrompt.rag.documentContent", FinalPromptDisplayValues.clippedCustomerList(evidenceLines, 3, messageResolver)));
        }
        if (rule != null && rule.labelGroups() != null) {
            for (List<String> group : rule.labelGroups()) {
                addDetailedRagTermGroupFact(facts, checkContract, ragGroupTerms(group), ragText);
            }
        }
        return joinCustomerSentences(facts.stream().filter(StringUtils::hasText).distinct().toList());
    }

    private void addDetailedRagTermGroupFact(
            List<String> facts,
            FinalPromptMetricCheckContract checkContract,
            List<String> groupTerms,
            String ragText) {
        if (groupTerms.isEmpty()) {
            return;
        }
        List<String> present = groupTerms.stream()
                .filter(term -> containsIgnoreCase(ragText, term))
                .map(term -> contractMappedValue(checkContract, term))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        if (!present.isEmpty()) {
            facts.add("ragEvidenceRequirementPresent=" + String.join(",", present));
            return;
        }
        List<String> missing = groupTerms.stream()
                .map(term -> contractMappedValue(checkContract, term))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        if (!missing.isEmpty()) {
            facts.add("ragEvidenceRequirementMissing=" + String.join(",", missing));
        }
    }

    private List<String> ragGroupTerms(List<String> group) {
        return group == null ? List.of() : group.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .toList();
    }
    private String ragForbiddenTermsPurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context) {
        List<String> terms = new ArrayList<>();
        if (rule != null) {
            addContractItems(terms, rule.terms() == null ? "" : String.join(",", rule.terms()));
            addContractItems(terms, rule.forbiddenTerms() == null ? "" : String.join(",", rule.forbiddenTerms()));
            addContractItems(terms, rule.thenTerms() == null ? "" : String.join(",", rule.thenTerms()));
        }
        List<String> facts = new ArrayList<>();
        String ragText = ragText(context == null ? null : context.prompt(), rule);
        if (!StringUtils.hasText(ragText)) {
            if (displayVisibleCheck(checkContract) && !terms.isEmpty()) {
                facts.add(readableFact(checkContract, "RagForbiddenTermCheckedCount", String.valueOf(terms.size())));
                facts.add(readableFact(checkContract, "RagForbiddenTermMatchCount", "0"));
                return joinCustomerSentences(facts.stream().filter(StringUtils::hasText).distinct().toList());
            }
            return "";
        }
        List<String> evidenceLines = ragEvidenceLines(ragText);
        if (!displayVisibleCheck(checkContract) && !evidenceLines.isEmpty()) {
            facts.add(message("verification.finalPrompt.rag.documentContent", FinalPromptDisplayValues.clippedCustomerList(evidenceLines, 3, messageResolver)));
        }
        List<String> present = terms.stream()
                .filter(term -> containsIgnoreCase(ragText, term))
                .map(term -> contractMappedValue(checkContract, term))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        List<String> absent = terms.stream()
                .filter(term -> !containsIgnoreCase(ragText, term))
                .map(term -> contractMappedValue(checkContract, term))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        if (displayVisibleCheck(checkContract)) {
            facts.add(readableFact(checkContract, "RagForbiddenTermCheckedCount", String.valueOf(terms.size())));
            facts.add(readableFact(checkContract, "RagForbiddenTermMatchCount", String.valueOf(present.size())));
            return joinCustomerSentences(facts.stream().filter(StringUtils::hasText).distinct().toList());
        }
        if (!present.isEmpty()) {
            facts.add("ragForbiddenTermPresent=" + String.join(",", present));
        }
        else if (!absent.isEmpty()) {
            facts.add("ragForbiddenTermAbsent=" + FinalPromptDisplayValues.clippedCustomerList(absent, 5, messageResolver));
        }
        return joinCustomerSentences(facts.stream().filter(StringUtils::hasText).distinct().toList());
    }

    private List<String> ragEvidenceLines(String ragText) {
        if (!StringUtils.hasText(ragText)) {
            return List.of();
        }
        return Arrays.stream(ragText.split("\\R+"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .filter(line -> containsIgnoreCase(line, "document")
                        || containsIgnoreCase(line, "rag")
                        || containsIgnoreCase(line, "authorization")
                        || containsIgnoreCase(line, "scope")
                        || containsIgnoreCase(line, "tenant")
                        || containsIgnoreCase(line, "resource")
                        || containsIgnoreCase(line, "purpose"))
                .map(this::customerPurposeText)
                .map(line -> line.replaceAll("\\s+", " ").trim())
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private String systemTermGroupPurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context,
            boolean passed) {
        String systemPrompt = systemPrompt(context);
        if (!StringUtils.hasText(systemPrompt) || rule == null || rule.labelGroups().isEmpty()) {
            return runtimeFallbackEvidence(
                    checkContract,
                    passed,
                    passed
                            ? checkContract == null ? "" : checkContract.passMessage()
                            : checkContract == null ? "" : checkContract.failureMessage());
        }
        List<String> confirmed = new ArrayList<>();
        List<String> missing = new ArrayList<>();
        for (List<String> group : rule.labelGroups()) {
            List<String> groupTerms = group == null ? List.of() : group.stream()
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .toList();
            List<String> present = groupTerms.stream()
                    .filter(term -> containsIgnoreCase(systemPrompt, term))
                    .map(term -> contractMappedValue(checkContract, term))
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList();
            if (!present.isEmpty()) {
                confirmed.add(String.join(", ", present));
            }
            else if (!groupTerms.isEmpty()) {
                missing.add(groupTerms.stream()
                        .map(term -> contractMappedValue(checkContract, term))
                        .filter(StringUtils::hasText)
                        .distinct()
                        .collect(Collectors.joining(", ")));
            }
        }
        List<String> parts = new ArrayList<>();
        if (!confirmed.isEmpty()) {
            parts.add(message("verification.finalPrompt.format.confirmed", String.join(", ", confirmed)));
        }
        if (!missing.isEmpty()) {
            parts.add(message("verification.finalPrompt.format.missing", String.join(", ", missing)));
        }
        return joinCustomerSentences(parts);
    }

    private List<String> mappedPresentTerms(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            List<String> terms) {
        if (prompt == null || terms == null || terms.isEmpty()) {
            return List.of();
        }
        return terms.stream()
                .filter(StringUtils::hasText)
                .filter(term -> containsIgnoreCase(prompt.userPrompt(), term))
                .map(term -> readableTermFact(checkContract, term))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private List<String> mappedAbsentTerms(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            List<String> terms) {
        if (prompt == null || terms == null || terms.isEmpty()) {
            return List.of();
        }
        return terms.stream()
                .filter(StringUtils::hasText)
                .filter(term -> !containsIgnoreCase(prompt.userPrompt(), term))
                .map(term -> contractMappedValue(checkContract, term))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private String readableTermFact(FinalPromptMetricCheckContract checkContract, String term) {
        String mapped = contractMappedValue(checkContract, term);
        String template = contractSpecialMapping(checkContract, "__termFactTemplate", "");
        if (!StringUtils.hasText(template)) {
            return mapped;
        }
        Map<String, String> values = new LinkedHashMap<>();
        values.put("label", mapped);
        values.put("term", mapped);
        String rendered = renderTemplate(template, values);
        return rendered.contains("{{") || rendered.contains("}}") ? mapped : customerPurposeText(rendered);
    }

    private List<String> readableLabels(FinalPromptMetricCheckContract checkContract, FinalPromptSnapshot prompt, List<String> labels) {
        if (prompt == null || labels == null || labels.isEmpty()) {
            return List.of();
        }
        List<String> facts = new ArrayList<>();
        for (String label : labels) {
            if (!StringUtils.hasText(label)) {
                continue;
            }
            List<FinalPromptField> fields = prompt.fieldsByLabel(label);
            if (fields.isEmpty()) {
                continue;
            }
            String fact = readableFact(checkContract, label, stripLineSuffix(fields.get(0).value()));
            if (StringUtils.hasText(fact)) {
                facts.add(fact);
            }
        }
        return facts.stream().distinct().toList();
    }

    private String readableFieldFact(
            FinalPromptMetricCheckContract checkContract,
            String label,
            FinalPromptField field,
            boolean duplicateLabel) {
        if (field == null) {
            return "";
        }
        String displayLabel = label;
        if (duplicateLabel && StringUtils.hasText(field.section())) {
            displayLabel = field.section().trim() + " " + label;
        }
        return readableFact(checkContract, label, stripLineSuffix(field.value()), displayLabel);
    }

    private String contractSpecialMapping(
            FinalPromptMetricCheckContract checkContract,
            String key,
            String fallback) {
        Map<String, String> mappings = checkContract == null ? null : checkContract.valueMappings();
        if (mappings == null) {
            return fallback;
        }
        return FinalPromptDisplayValues.firstNonBlank(mappings.get(key), fallback);
    }

    private String consistencyPurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            List<String> labels,
            String operator,
            boolean passed) {
        if (prompt == null || labels == null || labels.isEmpty()) {
            return runtimeFallbackEvidence(
                    checkContract,
                    false,
                    checkContract == null ? "" : checkContract.failureMessage());
        }
        List<String> facts = consistencyReadableFacts(checkContract, prompt, labels, operator, passed);
        Set<String> distinctValues = new LinkedHashSet<>();
        for (String label : labels) {
            List<FinalPromptField> fields = prompt.fieldsByLabel(label);
            for (FinalPromptField field : fields) {
                String value = stripLineSuffix(field.value());
                if (passed && placeholderConsistencyValue(value)) {
                    continue;
                }
                String comparable = "BOOLEAN_FIELDS_CONSISTENT".equals(operator)
                        ? normalizeBooleanComparable(value)
                        : normalizeComparableValue(value);
                if (StringUtils.hasText(comparable)) {
                    distinctValues.add(comparable);
                }
            }
        }
        String headline = passed
                ? requiredContractText(checkContract, checkContract.passMessage(), "passMessage")
                : requiredContractText(checkContract, checkContract.failureMessage(), "failureMessage");
        List<String> parts = new ArrayList<>();
        if (!facts.isEmpty()) {
            parts.add(joinCustomerSentences(facts));
        }
        if (!distinctValues.isEmpty()) {
            String outcome = consistencyOutcomeEvidence(checkContract, labels, distinctValues, passed);
            if (StringUtils.hasText(outcome)) {
                parts.add(outcome);
            }
        }
        if (parts.isEmpty()) {
            String fallback = runtimeFallbackEvidence(checkContract, passed, headline);
            if (StringUtils.hasText(fallback)) {
                parts.add(fallback);
            }
        }
        return joinCustomerSentences(parts);
    }

    private List<String> consistencyReadableFacts(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            List<String> labels,
            String operator,
            boolean passed) {
        if (passed) {
            return readableLabels(checkContract, prompt, labels);
        }
        if (prompt == null || labels == null || labels.isEmpty()) {
            return List.of();
        }
        List<String> facts = new ArrayList<>();
        for (String label : labels) {
            if (!StringUtils.hasText(label)) {
                continue;
            }
            List<FinalPromptField> fields = prompt.fieldsByLabel(label);
            boolean duplicateLabel = fields.size() > 1;
            for (FinalPromptField field : fields) {
                String value = stripLineSuffix(field.value());
                if (passed && placeholderConsistencyValue(value)) {
                    continue;
                }
                String comparable = "BOOLEAN_FIELDS_CONSISTENT".equals(operator)
                        ? normalizeBooleanComparable(value)
                        : normalizeComparableValue(value);
                if (!StringUtils.hasText(comparable)) {
                    continue;
                }
                String fact = readableFieldFact(checkContract, label, field, duplicateLabel);
                if (StringUtils.hasText(fact)) {
                    facts.add(fact);
                }
            }
        }
        if (facts.isEmpty()) {
            return readableLabels(checkContract, prompt, labels);
        }
        return facts.stream().distinct().toList();
    }

    private String consistencyOutcomeEvidence(
            FinalPromptMetricCheckContract checkContract,
            List<String> labels,
            Set<String> distinctValues,
            boolean passed) {
        if (checkContract == null || distinctValues == null || distinctValues.isEmpty()) {
            return "";
        }
        String templateKey = passed
                ? ((labels == null || labels.size() <= 1) ? "__singleOutcomeTemplate" : "__consistentOutcomeTemplate")
                : "__conflictOutcomeTemplate";
        String template = contractSpecialMapping(checkContract, templateKey, "");
        if (!StringUtils.hasText(template) && checkContract.customerVisible()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible consistency outcome template is required. metric="
                    + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract.checkName(), "UNKNOWN_CHECK")
                    + ", template=" + templateKey);
        }
        if (!StringUtils.hasText(template)) {
            return "";
        }
        Map<String, String> values = new LinkedHashMap<>();
        values.put("normalizedValues", String.join(", ", distinctValues));
        values.put("fieldList", customerFieldList(labels));
        values.put("primaryField", labels == null || labels.isEmpty() ? "" : labels.get(0));
        return renderTemplate(template, values);
    }

    private String customerFieldList(List<String> labels) {
        if (labels == null || labels.isEmpty()) {
            return message("verification.finalPrompt.inspection.genericItem");
        }
        return labels.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .collect(Collectors.joining(", "));
    }

    private String sensitivePurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            List<String> labels,
            boolean passed) {
        String headline = passed
                ? requiredContractText(checkContract, checkContract.passMessage(), "passMessage")
                : requiredContractText(checkContract, checkContract.failureMessage(), "failureMessage");
        List<String> facts = readableLabels(checkContract, prompt, labels);
        List<String> parts = new ArrayList<>();
        if (!facts.isEmpty()) {
            parts.add(joinCustomerSentences(facts));
        }
        String outcome = contractSpecialMapping(checkContract,
                passed ? "__sensitiveConsistentOutcome" : "__sensitiveConflictOutcome", "");
        if (StringUtils.hasText(outcome)) {
            parts.add(outcome);
        }
        if (!parts.isEmpty()) {
            return joinCustomerSentences(parts);
        }
        return runtimeFallbackEvidence(checkContract, passed, headline);
    }

    private String contractPurposeDetail(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            String headline) {
        String detail = passed
                ? firstDistinctContractText(
                        headline,
                        checkContract == null ? null : checkContract.expectedMessage(),
                        checkContract == null ? null : checkContract.interpretationLink(),
                        checkContract == null ? null : checkContract.meaning(),
                        checkContract == null ? null : checkContract.qualityQuestion(),
                        checkContract == null ? null : checkContract.securityRelevance(),
                        checkContract == null ? null : checkContract.whyItMatters())
                : firstDistinctContractText(
                        headline,
                        checkContract == null ? null : checkContract.failureMessage(),
                        checkContract == null ? null : checkContract.expectedMessage(),
                        checkContract == null ? null : checkContract.interpretationLink(),
                        checkContract == null ? null : checkContract.securityRelevance(),
                        checkContract == null ? null : checkContract.whyItMatters(),
                        checkContract == null ? null : checkContract.meaning(),
                        checkContract == null ? null : checkContract.qualityQuestion());
        if (StringUtils.hasText(detail)) {
            return detail;
        }
        if (checkContract != null && checkContract.customerVisible()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence requires distinct contract text. metric="
                    + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract.checkName(), "UNKNOWN_CHECK"));
        }
        return FinalPromptDisplayValues.firstNonBlank(headline, "");
    }

    private String firstDistinctContractText(String headline, String... candidates) {
        if (candidates == null || candidates.length == 0) {
            return "";
        }
        String normalizedHeadline = normalizeCustomerPurposeText(headline);
        for (String candidate : candidates) {
            if (!StringUtils.hasText(candidate)) {
                continue;
            }
            String text = customerPurposeText(candidate);
            if (StringUtils.hasText(text) && !normalizeCustomerPurposeText(text).equals(normalizedHeadline)) {
                return text;
            }
        }
        return "";
    }

    private String normalizeCustomerPurposeText(String value) {
        return value == null
                ? ""
                : customerPurposeText(value)
                        .replaceAll("\\s+", " ")
                        .replaceAll("[.!?]+$", "")
                        .trim()
                        .toLowerCase(Locale.ROOT);
    }

    private String truncatedFactDetails(FinalPromptMetricCheckContract checkContract, FinalPromptSnapshot prompt) {
        if (prompt == null) {
            return "";
        }
        List<String> details = new ArrayList<>();
        for (FinalPromptField field : prompt.fields()) {
            if (containsTruncationMarker(field.value())) {
                details.add(truncatedFactDetail(checkContract, field.section(), field.label(), field.lineNumber(), field.value()));
            }
        }
        for (FinalPromptBullet bullet : prompt.bullets()) {
            if (containsTruncationMarker(bullet.text())) {
                details.add(truncatedFactDetail(checkContract, bullet.section(), "bullet", bullet.lineNumber(), bullet.text()));
            }
        }
        for (FinalPromptNarrativeLine line : prompt.narrativeLines()) {
            if (containsTruncationMarker(line.text())) {
                details.add(truncatedFactDetail(checkContract, line.section(), "narrative", line.lineNumber(), line.text()));
            }
        }
        return details.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .collect(Collectors.joining(" "));
    }

    private int truncatedFactCount(FinalPromptSnapshot prompt) {
        if (prompt == null) {
            return 0;
        }
        int count = 0;
        for (FinalPromptField field : prompt.fields()) {
            if (containsTruncationMarker(field.value())) {
                count++;
            }
        }
        for (FinalPromptBullet bullet : prompt.bullets()) {
            if (containsTruncationMarker(bullet.text())) {
                count++;
            }
        }
        for (FinalPromptNarrativeLine line : prompt.narrativeLines()) {
            if (containsTruncationMarker(line.text())) {
                count++;
            }
        }
        return count;
    }

    private String truncatedFactDetail(
            FinalPromptMetricCheckContract checkContract,
            String section,
            String label,
            int lineNumber,
            String value) {
        String sectionText = FinalPromptDisplayValues.firstNonBlank(section, "section unknown");
        String labelText = FinalPromptDisplayValues.firstNonBlank(label, "field unknown");
        String lineText = lineNumber > 0 ? String.valueOf(lineNumber) : "unknown";
        String template = contractSpecialMapping(checkContract, "__truncatedFactTemplate", "");
        if (!StringUtils.hasText(template) && checkContract != null && checkContract.customerVisible()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible truncated fact template is required. metric="
                    + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract.checkName(), "UNKNOWN_CHECK"));
        }
        if (!StringUtils.hasText(template)) {
            return sectionText + "." + labelText + "(line " + lineText + ")";
        }
        Map<String, String> values = new LinkedHashMap<>();
        values.put("section", contractMappedValue(checkContract, sectionText));
        values.put("label", contractMappedValue(checkContract, labelText));
        values.put("line", lineText);
        values.put("value", evidencePreview(checkContract, value));
        return renderTemplate(template, values);
    }

    private List<String> splitContractList(String raw) {
        if (!StringUtils.hasText(raw)) {
            return List.of();
        }
        return Arrays.stream(raw.split("\\|"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .toList();
    }

    private boolean contractBindingRequired(Map<String, String> binding) {
        String required = binding == null ? "" : FinalPromptDisplayValues.firstNonBlank(binding.get("required"), binding.get("optional"));
        if (!StringUtils.hasText(required)) {
            return true;
        }
        String normalized = required.trim().toLowerCase(Locale.ROOT);
        if ("false".equals(normalized)) {
            return false;
        }
        return !"true".equals(normalized) || !"true".equalsIgnoreCase(binding.get("optional"));
    }

    private boolean usableRuntimeDisplayValue(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String normalized = value.trim();
        return !"N/A".equalsIgnoreCase(normalized)
                && !"UNKNOWN".equalsIgnoreCase(normalized)
                && !"null".equalsIgnoreCase(normalized);
    }

    private String renderContractBindingValue(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            String rawValue) {
        String format = FinalPromptDisplayValues.firstNonBlank(binding.get("format"), "VALUE").trim().toUpperCase(Locale.ROOT);
        String normalized = stripLineSuffix(rawValue);
        String value = switch (format) {
            case "LIST", "DELTA_LIST" -> splitReadableList(normalized).stream()
                    .map(item -> contractMappedListItem(checkContract, item))
                    .filter(StringUtils::hasText)
                    .distinct()
                    .collect(Collectors.joining(", "));
            case "DAY_LIST" -> splitReadableList(normalized).stream()
                    .map(item -> contractMappedListItem(checkContract, item))
                    .map(this::dayListItem)
                    .filter(StringUtils::hasText)
                    .distinct()
                    .collect(Collectors.joining(", "));
            default -> contractMappedValue(checkContract, normalized);
        };
        String template = binding.get("template");
        if (!StringUtils.hasText(template)) {
            return value;
        }
        Map<String, String> placeholders = new LinkedHashMap<>();
        placeholders.put("value", value);
        placeholders.put("rawValue", normalized);
        return renderTemplate(template, placeholders);
    }

    private String dayListItem(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String text = value.trim();
        String normalized = text.endsWith("일") ? text.substring(0, text.length() - 1) : text;
        return message("verification.finalPrompt.duration.days", normalized);
    }

    private String contractMappedListItem(FinalPromptMetricCheckContract checkContract, String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String text = value.trim();
        String exact = contractMappedValue(checkContract, text);
        if (!exact.equals(text)) {
            return exact;
        }
        int equalsIndex = text.indexOf('=');
        if (equalsIndex > 0 && equalsIndex < text.length() - 1) {
            String key = text.substring(0, equalsIndex).trim();
            String rawValue = text.substring(equalsIndex + 1).trim();
            String mappedKey = contractMappedValue(checkContract, key);
            String mappedValue = contractMappedValue(checkContract, rawValue);
            if (StringUtils.hasText(mappedKey) && StringUtils.hasText(mappedValue)) {
                return message("verification.finalPrompt.value.named", mappedKey, mappedValue);
            }
        }
        return exact;
    }

    private String contractMappedValue(FinalPromptMetricCheckContract checkContract, String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String text = value.trim();
        Map<String, String> mappings = checkContract == null ? null : checkContract.valueMappings();
        if (mappings != null) {
            String mapped = mappings.get(text);
            if (StringUtils.hasText(mapped)) {
                return mapped.trim();
            }
            mapped = mappings.get(text.toLowerCase(Locale.ROOT));
            if (StringUtils.hasText(mapped)) {
                return mapped.trim();
            }
            mapped = mappings.get(text.toUpperCase(Locale.ROOT));
            if (StringUtils.hasText(mapped)) {
                return mapped.trim();
            }
        }
        return text;
    }

    private String renderTemplate(String template, Map<String, String> values) {
        if (!StringUtils.hasText(template)) {
            return "";
        }
        Matcher matcher = TEMPLATE_PLACEHOLDER.matcher(template);
        StringBuffer result = new StringBuffer();
        while (matcher.find()) {
            String key = matcher.group(1) == null ? "" : matcher.group(1).trim();
            String replacement = values == null ? "" : values.get(key);
            if (replacement == null) {
                replacement = "";
            }
            matcher.appendReplacement(result, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(result);
        return result.toString().replaceAll("\\s+", " ").trim();
    }
    private List<String> splitReadableList(String value) {
        if (!StringUtils.hasText(value)) {
            return List.of();
        }
        return Arrays.stream(value.split("\\s*,\\s*|\\s*\\|\\s*|\\R+|\\s+and\\s+"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .toList();
    }
    private String readableEvidenceFacts(FinalPromptMetricCheckContract checkContract, List<String> evidence) {
        if (evidence == null || evidence.isEmpty()) {
            return "";
        }
        List<String> values = new ArrayList<>();
        List<String> presentTerms = new ArrayList<>();
        List<String> absentTerms = new ArrayList<>();
        for (String item : evidence) {
            if (!StringUtils.hasText(item) || contractMetadataSignal(item)) {
                continue;
            }
            for (String part : evidenceFactParts(item)) {
                if (!StringUtils.hasText(part) || contractMetadataSignal(part)) {
                    continue;
                }
                if (part.startsWith("section ") && part.contains("=present")) {
                    String section = part.substring("section ".length(), part.indexOf("=present")).trim();
                    values.add(readableFact(checkContract, "section", section, message("verification.finalPrompt.prompt.section")));
                    continue;
                }
                int equalsIndex = part.indexOf('=');
                if (equalsIndex > 0) {
                    String key = part.substring(0, equalsIndex).trim();
                    String value = stripLineSuffix(part.substring(equalsIndex + 1).trim());
                    if ("present".equalsIgnoreCase(value)) {
                        presentTerms.add(contractMappedValue(checkContract, key));
                        continue;
                    }
                    if ("absent".equalsIgnoreCase(value)) {
                        absentTerms.add(contractMappedValue(checkContract, key));
                        continue;
                    }
                    if ("missing".equalsIgnoreCase(value)) {
                        continue;
                    }
                    if (StringUtils.hasText(key) && StringUtils.hasText(value)
                            && !"missing".equalsIgnoreCase(value)) {
                        values.add(readableFact(checkContract, key, value));
                    }
                }
            }
        }
        if (!presentTerms.isEmpty() && !displayVisibleCheck(checkContract)) {
            values.add(message(
                    "verification.finalPrompt.prompt.presentTerms",
                    presentTerms.stream().filter(StringUtils::hasText).distinct().collect(Collectors.joining(", "))));
        }
        if (!absentTerms.isEmpty() && !displayVisibleCheck(checkContract)) {
            values.add(message(
                    "verification.finalPrompt.prompt.absentTerms",
                    absentTerms.stream().filter(StringUtils::hasText).distinct().collect(Collectors.joining(", "))));
        }
        return joinCustomerSentences(values.stream().filter(StringUtils::hasText).distinct().toList());
    }

    private List<String> evidenceFactParts(String item) {
        if (!StringUtils.hasText(item)) {
            return List.of();
        }
        return Arrays.stream(item.trim().split(",\\s*(?=[A-Za-z][A-Za-z0-9_ .-]*=)"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .toList();
    }

    private String readableFact(FinalPromptMetricCheckContract checkContract, String key, String value) {
        return readableFact(checkContract, key, value, "");
    }

    private String readableFact(FinalPromptMetricCheckContract checkContract, String key, String value, String displayLabel) {
        String name = key == null ? "" : key.trim();
        String text = value == null ? "" : value.trim();
        if (!StringUtils.hasText(name) || !StringUtils.hasText(text)) {
            return "";
        }
        String exact = contractSpecialMapping(checkContract, name + ": " + text, "");
        if (!StringUtils.hasText(exact)) {
            exact = contractSpecialMapping(checkContract, name + ": " + text.toLowerCase(Locale.ROOT), "");
        }
        if (!StringUtils.hasText(exact)) {
            exact = contractSpecialMapping(checkContract, name + ": " + text.toUpperCase(Locale.ROOT), "");
        }
        if (StringUtils.hasText(exact)) {
            return exact;
        }
        int explanationIndex = text.indexOf(" - ");
        if (explanationIndex > 0) {
            String prefix = text.substring(0, explanationIndex).trim();
            String prefixExact = contractSpecialMapping(checkContract, name + ": " + prefix, "");
            if (StringUtils.hasText(prefixExact)) {
                return prefixExact;
            }
        }
        String label = StringUtils.hasText(displayLabel)
                ? displayLabel.trim()
                : contractSpecialMapping(checkContract, name, name);
        String mappedValue = contractMappedValue(checkContract, text);
        String template = contractSpecialMapping(checkContract, "__factTemplate", "");
        if (!StringUtils.hasText(template)) {
            if (checkContract != null && checkContract.customerVisible()) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible fact template is required. metric="
                        + metricCode()
                        + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract.checkName(), "UNKNOWN_CHECK")
                        + ", fact=" + name);
            }
            if (displayVisibleCheck(checkContract)) {
                return message("verification.finalPrompt.value.named", label, mappedValue);
            }
            return label + "=" + mappedValue;
        }
        Map<String, String> values = new LinkedHashMap<>();
        values.put("label", label);
        values.put("value", mappedValue);
        return renderTemplate(template, values);
    }

    private String customerPurposeText(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.trim()
                .replace("...", " " + message("verification.finalPrompt.fragment.omitted"))
                .replace("=", " " + message("verification.finalPrompt.fragment.valueConnector") + " ")
                .replace("|", ", ")
                .replaceAll("\\s+", " ")
                .replaceAll("\\s+,\\s*", ", ")
                .trim();
    }

    private boolean customerVisibleEvidenceUnsafe(String value) {
        if (!StringUtils.hasText(value)) {
            return true;
        }
        String text = value.trim();
        return text.contains("=")
                || text.contains("|")
                || text.contains("...")
                || text.contains("Evidence:")
                || text.contains("evidence:")
                || text.contains("검사 대상 항목")
                || text.contains("검사 대상 컨텍스트")
                || text.contains("프롬프트 섹션")
                || text.contains("실제 프롬프트에서 발견된 표현")
                || text.contains("실제 프롬프트에서 발견되지 않은 표현")
                || text.contains("검사한 표현")
                || text.contains("실행 근거:")
                || text.contains("확인 결과:")
                || text.matches(".*\\sline\\s*$")
                || customerVisiblePromptLocationToken(text)
                || CUSTOMER_EVIDENCE_KEY_VALUE.matcher(text).find();
    }

    private boolean customerVisiblePromptLocationToken(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String text = value.trim();
        return text.startsWith("finalUserPrompt.")
                || text.startsWith("finalSystemPrompt.")
                || text.startsWith("sealedEvidence.")
                || text.startsWith("internalGate.")
                || text.startsWith("section ");
    }

    private String customerPurposeEvidence(String title, String detail) {
        return FinalPromptMetricInterpretationCodec.jsonObject(
                "signalKey", requiredText(customerPurposeText(title), "customer purpose evidence title"),
                "evidenceValue", requiredText(customerPurposeText(detail), "customer purpose evidence detail"));
    }

    private String customerPurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            String title,
            String detail) {
        return customerPurposeEvidence(
                checkContract,
                title,
                detail,
                contractRuntimeFactsFromEvidence(checkContract, List.of()),
                contractContextItemsText(checkContract));
    }

    private String customerPurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            String title,
            String detail,
            List<String> evidenceValues) {
        return customerPurposeEvidence(
                checkContract,
                title,
                detail,
                contractRuntimeFactsFromEvidence(checkContract, evidenceValues),
                contractContextItemsText(checkContract));
    }

    private String customerPurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            String title,
            String detail,
            boolean passed,
            FinalPromptMetricEvaluationContext context) {
        return customerPurposeEvidence(
                checkContract,
                title,
                detail,
                contractRuntimeFacts(checkContract, passed, context),
                contractContextItemsText(checkContract));
    }

    private String customerPurposeEvidence(
            FinalPromptMetricCheckContract checkContract,
            String title,
            String detail,
            String runtimeFacts,
            String contextItems) {
        String scopedRuntimeFacts = displayVisibleCheck(checkContract)
                ? purposeScopedRuntimeFacts(checkContract, Map.of(), List.of(runtimeFacts))
                : runtimeFacts;
        String displayDetail = customerPurposeDisplayDetail(checkContract, title, detail, scopedRuntimeFacts);
        String displayRuntimeFacts = customerPurposeText(scopedRuntimeFacts);
        if (!StringUtils.hasText(displayRuntimeFacts)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Missing customer purpose runtime facts. metric="
                    + metricCode()
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK"));
        }
        return FinalPromptMetricInterpretationCodec.jsonObject(
                "signalKey", requiredText(customerPurposeText(title), "customer purpose evidence title"),
                "evidenceValue", requiredText(displayDetail, "customer purpose evidence detail"),
                "purposeSignal", requiredContractText(checkContract, checkContract.purposeSignal(), "purposeSignal"),
                "meaning", requiredContractText(checkContract, checkContract.meaning(), "meaning"),
                "securityRelevance", requiredContractText(checkContract, checkContract.securityRelevance(), "securityRelevance"),
                "interpretationLink", requiredContractText(checkContract, checkContract.interpretationLink(), "interpretationLink"),
                "runtimeFacts", displayRuntimeFacts,
                "contextItems", requiredText(customerPurposeText(contextItems), "customer purpose context items"));
    }

    private String customerPurposeDisplayDetail(
            FinalPromptMetricCheckContract checkContract,
            String title,
            String detail,
            String runtimeFacts) {
        String displayDetail = customerPurposeText(detail);
        if (!contractDisplayTextRepeated(checkContract, title, displayDetail)
                && !sameCustomerPurposeText(displayDetail, runtimeFacts)) {
            return displayDetail;
        }
        String contractDetail = firstDisplayDetailCandidate(
                checkContract,
                title,
                runtimeFacts,
                detail,
                checkContract == null ? null : checkContract.meaning(),
                checkContract == null ? null : checkContract.securityRelevance(),
                checkContract == null ? null : checkContract.interpretationLink(),
                checkContract == null ? null : checkContract.qualityQuestion(),
                checkContract == null ? null : checkContract.whyItMatters());
        if (StringUtils.hasText(contractDetail)) {
            return contractDetail;
        }
        return displayDetail;
    }

    private String firstDisplayDetailCandidate(
            FinalPromptMetricCheckContract checkContract,
            String title,
            String runtimeFacts,
            String... candidates) {
        if (candidates == null || candidates.length == 0) {
            return "";
        }
        String normalizedRuntimeFacts = normalizeCustomerPurposeText(runtimeFacts);
        for (String candidate : candidates) {
            if (!StringUtils.hasText(candidate)) {
                continue;
            }
            String text = customerPurposeText(candidate);
            if (!contractDisplayTextRepeated(checkContract, title, text)
                    && !normalizeCustomerPurposeText(text).equals(normalizedRuntimeFacts)
                    && !customerVisibleEvidenceUnsafe(text)) {
                return text;
            }
        }
        return "";
    }

    private boolean sameCustomerPurposeText(String left, String right) {
        String normalizedLeft = normalizeCustomerPurposeText(left);
        String normalizedRight = normalizeCustomerPurposeText(right);
        return StringUtils.hasText(normalizedLeft) && normalizedLeft.equals(normalizedRight);
    }

    private boolean contractDisplayTextRepeated(
            FinalPromptMetricCheckContract checkContract,
            String title,
            String value) {
        String normalized = normalizeCustomerPurposeText(value);
        if (!StringUtils.hasText(normalized)) {
            return true;
        }
        return normalized.equals(normalizeCustomerPurposeText(title))
                || normalized.equals(normalizeCustomerPurposeText(checkContract == null ? null : checkContract.expectedMessage()))
                || normalized.equals(normalizeCustomerPurposeText(checkContract == null ? null : checkContract.passMessage()))
                || normalized.equals(normalizeCustomerPurposeText(checkContract == null ? null : checkContract.failureMessage()))
                || normalized.equals(normalizeCustomerPurposeText(checkContract == null ? null : checkContract.problemTitle()))
                || normalized.equals(normalizeCustomerPurposeText(checkContract == null ? null : checkContract.interpretationLink()))
                || normalized.equals(normalizeCustomerPurposeText(checkContract == null ? null : checkContract.qualityQuestion()));
    }

    private boolean contractRuntimeFactsRepeatDisplayText(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptMetricEvaluationContext context,
            String runtimeFacts) {
        String normalized = normalizeCustomerPurposeText(runtimeFacts);
        if (!StringUtils.hasText(normalized)) {
            return true;
        }
        List<String> displayTexts = new ArrayList<>();
        displayTexts.add(checkContract == null ? null : checkContract.expectedMessage());
        displayTexts.add(checkContract == null ? null : checkContract.passMessage());
        displayTexts.add(checkContract == null ? null : checkContract.failureMessage());
        displayTexts.add(checkContract == null ? null : checkContract.problemTitle());
        displayTexts.add(checkContract == null ? null : checkContract.interpretationLink());
        displayTexts.add(checkContract == null ? null : checkContract.qualityQuestion());
        displayTexts.add(checkContract == null ? null : checkContract.meaning());
        displayTexts.add(checkContract == null ? null : checkContract.securityRelevance());
        displayTexts.add(checkContract == null ? null : checkContract.whyItMatters());
        try {
            displayTexts.add(renderContractEvidenceTemplate(checkContract, passed, context));
        } catch (RuntimeException ignored) {
            // This helper only prevents copied display text; normal evidence validation still runs elsewhere.
        }
        Set<String> normalizedDisplayTexts = displayTexts.stream()
                .filter(StringUtils::hasText)
                .flatMap(text -> customerPurposeTextUnits(text).stream())
                .filter(StringUtils::hasText)
                .map(this::normalizeCustomerPurposeText)
                .filter(StringUtils::hasText)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (normalizedDisplayTexts.contains(normalized)) {
            return true;
        }
        return customerPurposeTextUnits(runtimeFacts).stream()
                .map(this::normalizeCustomerPurposeText)
                .filter(StringUtils::hasText)
                .anyMatch(normalizedDisplayTexts::contains);
    }

    private List<String> customerPurposeTextUnits(String text) {
        if (!StringUtils.hasText(text)) {
            return List.of();
        }
        return Arrays.stream(customerPurposeText(text).split("\\R+|(?<=[.!?。])\\s+"))
                .map(String::trim)
                .map(this::trimSentenceEnd)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private String contractRuntimeFacts(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptMetricEvaluationContext context) {
        FinalPromptSnapshot prompt = context == null ? null : context.prompt();
        if (prompt == null) {
            return displayVisibleCheck(checkContract)
                    ? ""
                    : contractRuntimeFactsFromEvidence(checkContract, List.of());
        }
        String displayFacts = displaySpecificRuntimeFacts(checkContract, passed, prompt, context);
        if (customerRuntimeFactsUsable(checkContract, passed, context, displayFacts)) {
            return displayFacts;
        }
        String templateFacts = displayVisibleCheck(checkContract)
                ? ""
                : renderContractRuntimeEvidenceTemplate(checkContract, passed, context);
        if (customerRuntimeFactsUsable(checkContract, passed, context, templateFacts)) {
            return templateFacts;
        }
        String bindingFacts = contractBindingRuntimeFacts(checkContract, passed, prompt, context);
        if (customerRuntimeFactsUsable(checkContract, passed, context, bindingFacts)) {
            return bindingFacts;
        }
        String safeAbsenceFailureFacts = safeAbsenceFailureRuntimeFacts(checkContract, passed, prompt);
        if (customerRuntimeFactsUsable(checkContract, passed, context, safeAbsenceFailureFacts)) {
            return safeAbsenceFailureFacts;
        }
        if (displayVisibleCheck(checkContract)) {
            return "";
        }
        String evidenceFacts = readableEvidenceFacts(
                checkContract,
                evidenceValues(checkContract == null ? null : checkContract.rule(), context));
        if (customerRuntimeFactsUsable(checkContract, passed, context, evidenceFacts)) {
            return evidenceFacts;
        }
        return runtimeFactFallback(checkContract);
    }

    private String displaySpecificRuntimeFacts(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context) {
        if (!displayVisibleCheck(checkContract)) {
            return "";
        }
        if (passed && optionalFieldValuesConsistentCheck(checkContract)) {
            String optionalFacts = optionalFieldValuesConsistentRuntimeFacts(checkContract);
            if (customerRuntimeFactsUsable(checkContract, passed, context, optionalFacts)) {
                return optionalFacts;
            }
        }
        String purposeFacts = purposeSpecificDisplayRuntimeFacts(checkContract, Map.of(), prompt, context);
        return customerRuntimeFactsUsable(checkContract, passed, context, purposeFacts) ? purposeFacts : "";
    }

    private String contractBindingRuntimeFacts(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context) {
        List<String> facts = new ArrayList<>();
        for (Map<String, String> binding : safeEvidenceBindings(checkContract)) {
            if (binding != null) {
                facts.addAll(runtimeFactsForBinding(checkContract, binding, passed, prompt, context));
            }
        }
        return joinCustomerSentences(facts.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .toList());
    }

    private List<String> runtimeFactsForBinding(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            boolean passed,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context) {
        String renderedSpecial = renderContractRuntimeBinding(checkContract, binding, passed, prompt, context);
        if (customerRuntimeFactsUsable(checkContract, passed, context, renderedSpecial)) {
            return List.of(renderedSpecial.trim());
        }
        if (StringUtils.hasText(binding.get("runtimeFactItems"))
                || StringUtils.hasText(binding.get("customerVisibleRuntimeItems"))) {
            return List.of();
        }
        List<String> bindingFacts = new ArrayList<>();
        List<String> labels = contractBindingLabels(binding);
        for (String label : labels) {
            addRuntimeBindingFact(bindingFacts, checkContract, binding, label, passed, prompt, context);
        }
        if (labels.isEmpty() && StringUtils.hasText(binding.get("label"))) {
            addRuntimeBindingFact(
                    bindingFacts, checkContract, binding, binding.get("label").trim(), passed, prompt, context);
        }
        return bindingFacts.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .toList();
    }

    private void addRuntimeBindingFact(
            List<String> bindingFacts,
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            String label,
            boolean passed,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context) {
        String rawValue = prompt.firstValue(label);
        String value = StringUtils.hasText(rawValue)
                ? rawValue
                : displayVisibleCheck(checkContract) && !passed ? "MISSING" : "";
        if (!StringUtils.hasText(value)) {
            return;
        }
        String fact = runtimeBindingFact(checkContract, binding, label, value);
        if (customerRuntimeFactsUsable(checkContract, passed, context, fact)) {
            bindingFacts.add(fact);
        }
    }
    private boolean customerRuntimeFactsUsable(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptMetricEvaluationContext context,
            String runtimeFacts) {
        if (!StringUtils.hasText(runtimeFacts)) {
            return false;
        }
        if (!displayVisibleCheck(checkContract)) {
            return true;
        }
        String text = runtimeFacts.trim();
        boolean repeatedDisplayText = contractRuntimeFactsRepeatDisplayText(checkContract, passed, context, text);
        return !customerVisibleEvidenceUnsafe(text)
                && (!passed || !customerRuntimeFactsContainHardMissing(text))
                && !customerRuntimeFactsContainUndeclaredLegacyAggregate(checkContract, text)
                && (!repeatedDisplayText || absenceMeasurementRuntimeFactAllowed(checkContract, text));
    }

    private boolean absenceMeasurementRuntimeFactAllowed(
            FinalPromptMetricCheckContract checkContract,
            String runtimeFacts) {
        if (!StringUtils.hasText(runtimeFacts)) {
            return false;
        }
        FinalPromptMetricRule rule = checkContract == null ? null : checkContract.rule();
        String operator = normalizeCheckName(rule == null ? "" : rule.operator());
        if (!"TRUNCATED_VALUES_ABSENT".equals(operator) && !"COMPACT_MARKERS_ABSENT".equals(operator)) {
            return false;
        }
        return Pattern.compile("\\d+").matcher(runtimeFacts).find();
    }

    private String safeAbsenceFailureRuntimeFacts(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptSnapshot prompt) {
        if (passed || prompt == null) {
            return "";
        }
        FinalPromptMetricRule rule = checkContract == null ? null : checkContract.rule();
        String operator = normalizeCheckName(rule == null ? "" : rule.operator());
        if ("TRUNCATED_VALUES_ABSENT".equals(operator)) {
            int count = truncatedFactCount(prompt);
            return count > 0
                    ? message("verification.finalPrompt.truncation.foundCount", count)
                    : "";
        }
        return "";
    }
    private boolean customerRuntimeFactsContainUndeclaredLegacyAggregate(
            FinalPromptMetricCheckContract checkContract,
            String runtimeFacts) {
        if (!StringUtils.hasText(runtimeFacts)) {
            return false;
        }
        String normalizedFacts = runtimeFacts.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "");
        boolean legacyRagStateAggregate = normalizedFacts.contains("ragsearchexecuted")
                && normalizedFacts.contains("ragretrievalstate")
                && normalizedFacts.contains("relateddocumentcount")
                && normalizedFacts.contains("ragapplicability");
        if (!legacyRagStateAggregate) {
            return false;
        }
        Set<String> declaredRuntimeItems = declaredRuntimeFactItems(checkContract);
        return !declaredRuntimeItems.contains("ragapplicabilitysummary");
    }

    private Set<String> declaredRuntimeFactItems(FinalPromptMetricCheckContract checkContract) {
        Set<String> items = new LinkedHashSet<>();
        for (Map<String, String> binding : safeEvidenceBindings(checkContract)) {
            if (binding == null) {
                continue;
            }
            List<String> bindingItems = new ArrayList<>();
            addContractItems(bindingItems, binding.get("runtimeFactItems"));
            addContractItems(bindingItems, binding.get("customerVisibleRuntimeItems"));
            bindingItems.stream()
                    .filter(StringUtils::hasText)
                    .map(value -> value.trim().toLowerCase(Locale.ROOT))
                    .forEach(items::add);
        }
        return items;
    }

    private String renderContractRuntimeBinding(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            boolean passed,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context) {
        String source = FinalPromptDisplayValues.firstNonBlank(binding.get("source"), binding.get("type")).trim().toUpperCase(Locale.ROOT);
        if ("RULE_PURPOSE_EVIDENCE".equals(source)) {
            return rulePurposeRuntimeBinding(checkContract, binding, passed, prompt, context);
        }
        if ("TERM_LIST_PRESENT".equals(source)) {
            String termFacts = termListRuntimeBinding(checkContract, binding, passed, prompt, context);
            if (customerRuntimeFactsUsable(checkContract, passed, context, termFacts)) {
                return termFacts;
            }
        }
        String rendered = renderContractSpecialBinding(checkContract, binding, passed, prompt, context);
        if (!StringUtils.hasText(rendered)) {
            return rendered;
        }
        if (Set.of(
                "FIELD_GROUP", "SECTION_LIST", "TERM_LIST_PRESENT",
                "RAG_RUNTIME_STATE", "TRUNCATED_FACT_DETAILS").contains(source)) {
            return rendered.trim();
        }
        return rendered;
    }

    private String rulePurposeRuntimeBinding(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            boolean passed,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context) {
        boolean declaresRuntimeFacts = StringUtils.hasText(binding.get("runtimeFactItems"))
                || StringUtils.hasText(binding.get("customerVisibleRuntimeItems"));
        if (declaresRuntimeFacts) {
            if (displayVisibleCheck(checkContract)) {
                String purposeFacts = purposeSpecificDisplayRuntimeFacts(checkContract, binding, prompt, context);
                if (customerRuntimeFactsUsable(checkContract, passed, context, purposeFacts)) {
                    return purposeFacts;
                }
            }
            String promptFacts = runtimeFactsFromBindingContextItems(
                    checkContract, binding, prompt, context,
                    displayVisibleCheck(checkContract), displayVisibleCheck(checkContract) && !passed);
            return customerRuntimeFactsUsable(checkContract, passed, context, promptFacts) ? promptFacts : "";
        }
        String ruleDerivedFacts = ruleDerivedRuntimeFacts(checkContract, passed, prompt, context);
        if (customerRuntimeFactsUsable(checkContract, passed, context, ruleDerivedFacts)) {
            return ruleDerivedFacts;
        }
        String promptFacts = runtimeFactsFromBindingContextItems(
                checkContract, binding, prompt, context,
                displayVisibleCheck(checkContract), displayVisibleCheck(checkContract) && !passed);
        if (customerRuntimeFactsUsable(checkContract, passed, context, promptFacts)) {
            return promptFacts;
        }
        if (!displayVisibleCheck(checkContract)) {
            String templateFacts = renderContractRuntimeEvidenceTemplate(checkContract, passed, context);
            if (customerRuntimeFactsUsable(checkContract, passed, context, templateFacts)) {
                return templateFacts;
            }
        }
        String evidenceFacts = renderContractSpecialBinding(checkContract, binding, passed, prompt, context);
        return customerRuntimeFactsUsable(checkContract, passed, context, evidenceFacts) ? evidenceFacts : "";
    }

    private String termListRuntimeBinding(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            boolean passed,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context) {
        String promptFacts = runtimeFactsFromBindingContextItems(
                checkContract, binding, prompt, context,
                displayVisibleCheck(checkContract), displayVisibleCheck(checkContract) && !passed);
        if (customerRuntimeFactsUsable(checkContract, passed, context, promptFacts)) {
            return promptFacts;
        }
        return runtimeFactsFromTermList(checkContract, binding, prompt);
    }
    private String purposeSpecificDisplayRuntimeFacts(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context) {
        if (!displayVisibleCheck(checkContract)) {
            return "";
        }
        String summaryItem = FinalPromptDisplayValues.firstNonBlank(
                checkPurposeRuntimeSummaryItem(checkContract),
                declaredPurposeRuntimeSummaryItem(binding));
        if (!StringUtils.hasText(summaryItem)) {
            return "";
        }
        return runtimeSummaryValueForDeclaredItem(checkContract, summaryItem, prompt, context);
    }

    private String declaredPurposeRuntimeSummaryItem(Map<String, String> binding) {
        if (binding == null) {
            return "";
        }
        List<String> items = new ArrayList<>();
        addContractItems(items, binding.get("runtimeFactItems"));
        addContractItems(items, binding.get("customerVisibleRuntimeItems"));
        return items.stream()
                .filter(StringUtils::hasText)
                .filter(this::isRuntimeSummaryItem)
                .filter(item -> !"ragapplicabilitysummary".equalsIgnoreCase(item.trim()))
                .findFirst()
                .orElse("");
    }

    private String checkPurposeRuntimeSummaryItem(FinalPromptMetricCheckContract checkContract) {
        String checkName = normalizeCheckName(checkContract == null ? "" : checkContract.checkName());
        FinalPromptMetricRule rule = checkContract == null ? null : checkContract.rule();
        String operator = normalizeCheckName(rule == null ? "" : rule.operator());
        if (checkName.contains("PROMPT_INJECTION") || operator.equals("RAG_TEXT_FORBIDDEN_TERMS_ABSENT")) {
            return "RagForbiddenTermSummary";
        }
        if (checkName.contains("NO_SCOPE_MISMATCH")
                || checkName.contains("SCOPE_CONTAMINATION")
                || operator.equals("RAG_NO_SCOPE_MISMATCH_DOCUMENT")) {
            return "RagContaminationScopeSummary";
        }
        if (checkName.contains("EVIDENCE_BOUNDARY") || checkName.contains("INSTRUCTION_BOUNDARY")) {
            return "RagEvidenceBoundarySummary";
        }
        if (checkName.contains("RETRIEVAL_NOT_FAILED") || operator.equals("RAG_NOT_FAILED_WHEN_USED")) {
            return "RagRetrievalSummary";
        }
        if (checkName.contains("PROJECTED") || operator.equals("RAG_DOCUMENT_SURFACE_PRESENT")) {
            return "RagProjectionSummary";
        }
        if (checkName.contains("AUTHORIZATION_REASON") || checkName.contains("AUTH_REASON")) {
            return "RagAuthorizationDecisionSummary";
        }
        if (checkName.contains("SCOPE_REASON")) {
            return "RagScopeDecisionSummary";
        }
        if (checkName.contains("DECISION_CONTEXT")) {
            return "DecisionContextSummary";
        }
        if (checkName.contains("BLOCKED") || checkName.contains("EXCLUDED")
                || operator.equals("RAG_BLOCKED_DOCUMENT_EXCLUDED")) {
            return "RagBlockedSummary";
        }
        if (checkName.contains("APPLICABILITY")) {
            return "RagApplicabilitySummary";
        }
        return "";
    }

    private String ruleDerivedRuntimeFacts(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context) {
        FinalPromptMetricRule rule = checkContract == null ? null : checkContract.rule();
        String operator = normalizeCheckName(rule == null ? "" : rule.operator());
        if ("FIELD_VALUES_CONSISTENT".equals(operator)
                || "OPTIONAL_FIELD_VALUES_CONSISTENT".equals(operator)
                || "BOOLEAN_FIELDS_CONSISTENT".equals(operator)
                || "SENSITIVE_FLAG_CONSISTENT".equals(operator)
                || "IF_ANY_TERM_PRESENT_THEN_ANY_FIELD_OR_TERM_PRESENT".equals(operator)
                || "IF_ANY_TERM_PRESENT_THEN_FORBIDDEN_TERMS_ABSENT".equals(operator)
                || "FORBIDDEN_TERMS_ABSENT".equals(operator)
                || "SYSTEM_TERM_GROUPS_PRESENT".equals(operator)
                || "RAG_TEXT_TERM_GROUPS_PRESENT_WHEN_RAG_PRESENT".equals(operator)
                || "RAG_TEXT_FORBIDDEN_TERMS_ABSENT".equals(operator)
                || "RAG_BLOCKED_DOCUMENT_EXCLUDED".equals(operator)
                || "ALL".equals(operator)) {
            return renderContractSpecialBinding(checkContract, Map.of("source", "RULE_PURPOSE_EVIDENCE"), passed, prompt, context);
        }
        return "";
    }

    private String renderContractRuntimeEvidenceTemplate(
            FinalPromptMetricCheckContract checkContract,
            boolean passed,
            FinalPromptMetricEvaluationContext context) {
        String template = passed
                ? (checkContract == null ? "" : checkContract.passEvidenceTemplate())
                : (checkContract == null ? "" : checkContract.failureEvidenceTemplate());
        if (!StringUtils.hasText(template) || !template.contains("{{") || template.contains("{{purposeEvidence}}")) {
            return "";
        }
        FinalPromptSnapshot prompt = context == null ? null : context.prompt();
        if (prompt == null) {
            return "";
        }
        Map<String, String> placeholders = contractEvidencePlaceholders(checkContract, passed, context, prompt, template);
        String rendered = renderTemplate(template, placeholders);
        if (rendered.contains("{{") || rendered.contains("}}")) {
            return "";
        }
        return customerPurposeText(rendered);
    }

    private String runtimeFactsFromTermList(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            FinalPromptSnapshot prompt) {
        if (displayVisibleCheck(checkContract)) {
            return "";
        }
        if (binding == null || prompt == null) {
            return "";
        }
        List<String> terms = splitContractList(binding.get("terms"));
        if (terms.isEmpty()) {
            return "";
        }
        List<String> present = terms.stream()
                .filter(prompt::contains)
                .map(term -> contractMappedValue(checkContract, term))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        if (!present.isEmpty()) {
            return "promptTermMatchCount=" + present.size();
        }
        if (!contractBindingRequired(binding)) {
            List<String> checked = terms.stream()
                    .map(term -> contractMappedValue(checkContract, term))
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList();
            if (!checked.isEmpty()) {
                return "promptTermCheckedCount=" + checked.size() + ", promptTermMatchCount=0";
            }
        }
        return "";
    }

    private String runtimeBindingFact(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            String label,
            String rawValue) {
        String rendered = renderContractBindingValue(checkContract, binding, rawValue);
        if (bindingTemplateAddsCustomerMeaning(binding)) {
            return customerPurposeText(rendered);
        }
        return readableFact(checkContract, label, rendered);
    }

    private boolean bindingTemplateAddsCustomerMeaning(Map<String, String> binding) {
        String template = binding == null ? "" : binding.get("template");
        if (!StringUtils.hasText(template)) {
            return false;
        }
        String normalized = template.replaceAll("\\s+", "");
        return !"{{value}}".equals(normalized) && !"{{rawValue}}".equals(normalized);
    }

    private String runtimeFactsFromBindingContextItems(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context,
            boolean promptValuesOnly,
            boolean includeMissingDeclaredFacts) {
        if (prompt == null || binding == null) {
            return "";
        }
        List<String> items = new ArrayList<>();
        addContractItems(items, binding.get("runtimeFactItems"));
        addContractItems(items, binding.get("customerVisibleRuntimeItems"));
        boolean explicitRuntimeFacts = !items.isEmpty();
        if (items.isEmpty()) {
            addContractItems(items, binding.get("customerVisibleContextItems"));
            addContractItems(items, binding.get("customerVisiblePromptItems"));
            if (!displayVisibleCheck(checkContract)) {
                addContractItems(items, binding.get("contextItems"));
                addContractItems(items, binding.get("promptItems"));
                addContractItems(items, binding.get("labels"));
                addContractItems(items, binding.get("label"));
            }
        }
        List<String> facts = new ArrayList<>();
        for (String item : items) {
            String rawValue = runtimeValueForDeclaredItem(checkContract, item, prompt, context);
            if (StringUtils.hasText(rawValue)) {
                facts.add(isRuntimeSummaryItem(item)
                        ? customerPurposeText(rawValue)
                        : readableFact(checkContract, item, rawValue));
                continue;
            }
            if (promptValuesOnly) {
                if (includeMissingDeclaredFacts && !contractTermOrForbiddenItem(checkContract, binding, item)) {
                    facts.add(readableFact(checkContract, item, "MISSING"));
                }
                continue;
            }
            if (prompt.hasSection(item)) {
                facts.add(readableFact(checkContract, "section", item, message("verification.finalPrompt.prompt.section")));
                continue;
            }
            if (prompt.contains(item)) {
                facts.add(readableFact(checkContract, item, message("verification.finalPrompt.prompt.found"), message("verification.finalPrompt.prompt.expression")));
            }
        }
        List<String> normalizedFacts = facts.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .toList();
        if (explicitRuntimeFacts || displayVisibleCheck(checkContract)) {
            return purposeScopedRuntimeFacts(checkContract, binding, normalizedFacts);
        }
        return joinCustomerSentences(normalizedFacts);
    }

    private String purposeScopedRuntimeFacts(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            List<String> facts) {
        if (facts == null || facts.isEmpty()) {
            return "";
        }
        List<String> normalizedFacts = facts.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .flatMap(fact -> Arrays.stream(fact
                        .replace("\r\n", "\n")
                        .replace('\r', '\n')
                .split("(?<=\\.)\\s+|\\R+")))
                .map(String::trim)
                .map(this::trimSentenceEnd)
                .map(this::runtimeFactValueOnly)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        if (normalizedFacts.isEmpty()) {
            return "";
        }
        String joinedFacts = String.join(", ", normalizedFacts);
        return joinedFacts;
    }

    private String runtimeFactValueOnly(String fact) {
        if (!StringUtils.hasText(fact)) {
            return "";
        }
        String text = fact.trim();
        text = text.replaceAll("(^|,\\s*)[^,\\.]*확인합니다\\s*:\\s*", "$1");
        text = text.replaceAll("(^|,\\s*)[^,\\.]*확인해야 합니다\\s*:\\s*", "$1");
        return text.trim();
    }

    private boolean isRuntimeSummaryItem(String item) {
        if (!StringUtils.hasText(item)) {
            return false;
        }
        String normalized = item.trim().toLowerCase(Locale.ROOT);
        return normalized.endsWith("summary")
                || "ragdocument".equals(normalized)
                || "decisionindependence".equals(normalized)
                || "priorroundverificationboundary".equals(normalized)
                || "pqaprocessinstructionboundary".equals(normalized);
    }

    private boolean contractTermOrForbiddenItem(
            FinalPromptMetricCheckContract checkContract,
            Map<String, String> binding,
            String item) {
        if (!StringUtils.hasText(item)) {
            return false;
        }
        String normalized = item.trim().toLowerCase(Locale.ROOT);
        List<String> terms = new ArrayList<>();
        addContractItems(terms, binding == null ? "" : binding.get("terms"));
        addContractItems(terms, binding == null ? "" : binding.get("forbiddenTerms"));
        addContractItems(terms, binding == null ? "" : binding.get("fallbackTerms"));
        FinalPromptMetricRule rule = checkContract == null ? null : checkContract.rule();
        addRuleTerms(terms, rule);
        return terms.stream()
                .filter(StringUtils::hasText)
                .map(value -> value.trim().toLowerCase(Locale.ROOT))
                .anyMatch(normalized::equals);
    }

    private void addRuleTerms(List<String> terms, FinalPromptMetricRule rule) {
        if (terms == null || rule == null) {
            return;
        }
        addContractItems(terms, rule.terms() == null ? "" : String.join(",", rule.terms()));
        addContractItems(terms, rule.forbiddenTerms() == null ? "" : String.join(",", rule.forbiddenTerms()));
        addContractItems(terms, rule.thenTerms() == null ? "" : String.join(",", rule.thenTerms()));
        if (rule.labelGroups() != null) {
            rule.labelGroups().forEach(group -> addContractItems(terms, group == null ? "" : String.join(",", group)));
        }
        if (rule.all() != null) {
            rule.all().forEach(child -> addRuleTerms(terms, child));
        }
        if (rule.any() != null) {
            rule.any().forEach(child -> addRuleTerms(terms, child));
        }
    }

    private String runtimeValueForDeclaredItem(
            FinalPromptMetricCheckContract checkContract,
            String item,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context) {
        if (!StringUtils.hasText(item)) {
            return "";
        }
        String summaryValue = runtimeSummaryValueForDeclaredItem(checkContract, item, prompt, context);
        if (StringUtils.hasText(summaryValue)) {
            return summaryValue;
        }
        FinalPromptEvidenceContext evidence = context == null ? null : context.evidence();
        if ("ragdocument".equalsIgnoreCase(item.trim())) {
            String documentSummary = ragDocumentCountSummary(checkContract, prompt, evidence);
            if (StringUtils.hasText(documentSummary)) {
                return documentSummary;
            }
        }
        if (isRagRuntimeItem(item)) {
            String evidenceValue = runtimeEvidenceValue(checkContract, item, evidence);
            if (StringUtils.hasText(evidenceValue)) {
                return evidenceValue;
            }
        }
        String snapshotValue = runtimeSnapshotValueForDeclaredItem(checkContract, item, prompt);
        if (StringUtils.hasText(snapshotValue)) {
            return snapshotValue;
        }
        String rawValue = prompt == null ? "" : prompt.firstValue(item);
        if (StringUtils.hasText(rawValue)) {
            return rawValue;
        }
        String evidenceValue = runtimeEvidenceValue(checkContract, item, evidence);
        return StringUtils.hasText(evidenceValue) ? evidenceValue : "";
    }

    private String runtimeSummaryValueForDeclaredItem(
            FinalPromptMetricCheckContract checkContract,
            String item,
            FinalPromptSnapshot prompt,
            FinalPromptMetricEvaluationContext context) {
        if (!StringUtils.hasText(item)) {
            return "";
        }
        String normalized = item.trim().toLowerCase(Locale.ROOT);
        FinalPromptEvidenceContext evidence = context == null ? null : context.evidence();
        return switch (normalized) {
            case "ragapplicabilitysummary" -> ragStateSummary(checkContract, prompt, evidence,
                    "RagApplicability", "RelatedDocumentCount");
            case "ragretrievalsummary" -> ragStateSummary(checkContract, prompt, evidence,
                    "RagRetrievalState", "RagAbsenceReason");
            case "ragprojectionsummary" -> ragStateSummary(checkContract, prompt, evidence,
                    "RagProjectionState", "RagProjectedToFinalPrompt", "RelatedDocumentCount");
            case "ragblockedsummary" -> ragStateSummary(checkContract, prompt, evidence,
                    "RagDeniedDocumentCount", "RagPermissionFiltered");
            case "ragauthorizationsummary" -> ragDocumentAlignmentSummary(checkContract, prompt, evidence, true, true);
            case "ragscopesummary" -> ragDocumentAlignmentSummary(checkContract, prompt, evidence, false, false);
            case "ragauthorizationdecisionsummary" -> ragAuthorizationDecisionSummary(checkContract, prompt, evidence);
            case "ragscopedecisionsummary" -> ragScopeDecisionSummary(checkContract, prompt, evidence);
            case "ragcontaminationscopesummary" -> ragContaminationScopeSummary(checkContract, prompt, evidence);
            case "ragforbiddentermsummary" -> ragRuleTermSummary(checkContract, prompt, true);
            case "ragevidenceboundarysummary" -> ragEvidenceBoundarySummary(checkContract, prompt);
            case "decisioncontextsummary" -> decisionContextSummary(checkContract, prompt);
            case "devicechangeexplanationsummary" -> termMatchSummary(
                    checkContract, prompt, "DeviceChangeExplanationTermCount");
            case "priorroundforbiddenphrasesummary" -> termMatchSummary(
                    checkContract, prompt, "PriorRoundForbiddenPhraseCount");
            case "pqaprocessphrasesummary" -> termMatchSummary(
                    checkContract, prompt, "PqaProcessPhraseCount");
            case "decisionindependence",
                    "priorroundverificationboundary",
                    "pqaprocessinstructionboundary" -> termMatchSummary(
                    checkContract, prompt, "ForbiddenTermMatchCount");
            default -> "";
        };
    }

    private String decisionContextSummary(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt) {
        if (prompt == null) {
            return "";
        }
        List<String> declaredItems = new ArrayList<>();
        for (Map<String, String> binding : safeEvidenceBindings(checkContract)) {
            addContractItems(declaredItems, binding == null ? "" : binding.get("customerVisibleContextItems"));
            addContractItems(declaredItems, binding == null ? "" : binding.get("customerVisiblePromptItems"));
        }
        List<String> distinctItems = declaredItems.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .toList();
        if (distinctItems.isEmpty()) {
            return "";
        }
        List<String> presentItems = distinctItems.stream()
                .filter(item -> StringUtils.hasText(runtimeSnapshotValueForDeclaredItem(checkContract, item, prompt))
                        || StringUtils.hasText(prompt.firstValue(item))
                        || prompt.hasSection(item)
                        || prompt.contains(item))
                .toList();
        List<String> facts = new ArrayList<>();
        facts.add(readableFact(checkContract, "DecisionContextPresentItemCount", String.valueOf(presentItems.size())));
        facts.add(readableFact(checkContract, "DecisionContextRequiredItemCount", String.valueOf(distinctItems.size())));
        if (!presentItems.isEmpty()) {
            facts.add(readableFact(checkContract, "DecisionContextItemSample", FinalPromptDisplayValues.clippedCustomerList(presentItems, 5, messageResolver)));
        }
        return joinCustomerSentences(facts.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .toList());
    }

    private String ragAuthorizationDecisionSummary(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            FinalPromptEvidenceContext evidence) {
        List<Object> documents = FinalPromptRagDocumentReader.documents(prompt, evidence);
        if (documents.isEmpty()) {
            return "";
        }
        String requestUser = FinalPromptRagDocumentReader.firstPromptValue(prompt, "UserId", "User");
        int userMismatchCount = 0;
        int authorizationMissingCount = 0;
        for (Object document : documents) {
            if (StringUtils.hasText(requestUser)
                    && !FinalPromptRagDocumentReader.sameValue(FinalPromptRagDocumentReader.fieldValue(document, "userId"), requestUser)) {
                userMismatchCount++;
            }
            if (!FinalPromptRagDocumentReader.authorizationPresent(document)) {
                authorizationMissingCount++;
            }
        }
        List<String> facts = new ArrayList<>();
        facts.add(readableFact(checkContract, "RagAuthorizationCheckedDocumentCount", String.valueOf(documents.size())));
        facts.add(readableFact(checkContract, "RagAuthorizationMissingCount", String.valueOf(authorizationMissingCount)));
        if (StringUtils.hasText(requestUser)) {
            facts.add(readableFact(checkContract, "RagUserMismatchCount", String.valueOf(userMismatchCount)));
        }
        String authorizedCount = runtimeEvidenceValue(checkContract, "RagAuthorizedDocumentCount", evidence);
        if (StringUtils.hasText(authorizedCount)) {
            facts.add(readableFact(checkContract, "RagAuthorizedDocumentCount", authorizedCount));
        }
        return joinCustomerSentences(facts.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .toList());
    }

    private String ragScopeDecisionSummary(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            FinalPromptEvidenceContext evidence) {
        List<Object> documents = FinalPromptRagDocumentReader.documents(prompt, evidence);
        if (documents.isEmpty()) {
            return "";
        }
        RagScopeCounts counts = ragScopeCounts(prompt, documents);
        List<String> facts = new ArrayList<>();
        facts.add(readableFact(checkContract, "RagScopeCheckedDocumentCount", String.valueOf(documents.size())));
        facts.add(readableFact(checkContract, "RagTenantMismatchCount", String.valueOf(counts.tenantMismatchCount())));
        facts.add(readableFact(checkContract, "RagResourceMismatchCount", String.valueOf(counts.resourceMismatchCount())));
        facts.add(readableFact(checkContract, "RagPurposeMissingCount", String.valueOf(counts.purposeMissingCount())));
        return joinCustomerSentences(facts.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .toList());
    }

    private String ragContaminationScopeSummary(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            FinalPromptEvidenceContext evidence) {
        List<Object> documents = FinalPromptRagDocumentReader.documents(prompt, evidence);
        if (documents.isEmpty()) {
            List<String> facts = new ArrayList<>();
            facts.add(readableFact(checkContract, "RagOutOfScopeDocumentCount", "0"));
            facts.add(readableFact(checkContract, "RelatedDocumentCount", FinalPromptDisplayValues.firstNonBlank(
                    runtimeEvidenceValue(checkContract, "RelatedDocumentCount", evidence),
                    runtimeSnapshotValueForDeclaredItem(checkContract, "RelatedDocumentCount", prompt),
                    "0")));
            return joinCustomerSentences(facts.stream()
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList());
        }
        RagScopeCounts counts = ragScopeCounts(prompt, documents);
        int outOfScopeCount = documents.isEmpty() ? 0 : Math.max(
                Math.max(counts.tenantMismatchCount(), counts.resourceMismatchCount()),
                counts.purposeMissingCount());
        List<String> facts = new ArrayList<>();
        facts.add(readableFact(checkContract, "RagOutOfScopeDocumentCount", String.valueOf(outOfScopeCount)));
        facts.add(readableFact(checkContract, "RagTenantMismatchCount", String.valueOf(counts.tenantMismatchCount())));
        facts.add(readableFact(checkContract, "RagResourceMismatchCount", String.valueOf(counts.resourceMismatchCount())));
        facts.add(readableFact(checkContract, "RagPurposeMissingCount", String.valueOf(counts.purposeMissingCount())));
        return joinCustomerSentences(facts.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .toList());
    }

    private RagScopeCounts ragScopeCounts(FinalPromptSnapshot prompt, List<Object> documents) {
        String requestTenant = FinalPromptRagDocumentReader.firstPromptValue(prompt, "TenantId", "Tenant");
        String requestResourceId = FinalPromptRagDocumentReader.firstPromptValue(prompt, "ResourceId", "Resource ID");
        String requestPath = FinalPromptRagDocumentReader.firstPromptValue(prompt, "RequestPath", "Path");
        String requestResourceFamily = FinalPromptRagDocumentReader.firstPromptValue(prompt, "CurrentResourceFamily", "ResourceFamily");
        String requestPathFamily = FinalPromptRagDocumentReader.firstPromptValue(prompt, "CurrentPathFamily", "PathFamily");
        int tenantMismatchCount = 0;
        int resourceMismatchCount = 0;
        int purposeMissingCount = 0;
        for (Object document : documents) {
            if (!FinalPromptRagDocumentReader.sameValue(FinalPromptRagDocumentReader.fieldValue(document, "tenantId"), requestTenant)) {
                tenantMismatchCount++;
            }
            if (!FinalPromptRagDocumentReader.resourceMatchesRequest(document, requestResourceId, requestPath, requestResourceFamily, requestPathFamily)) {
                resourceMismatchCount++;
            }
            if (!StringUtils.hasText(FinalPromptDisplayValues.firstNonBlank(
                    FinalPromptRagDocumentReader.fieldValue(document, "retrievalPurpose"),
                    FinalPromptRagDocumentReader.fieldValue(document, "purpose")))) {
                purposeMissingCount++;
            }
        }
        return new RagScopeCounts(tenantMismatchCount, resourceMismatchCount, purposeMissingCount);
    }

    private record RagScopeCounts(int tenantMismatchCount, int resourceMismatchCount, int purposeMissingCount) {
    }

    private String ragEvidenceBoundarySummary(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt) {
        if (prompt == null) {
            return "";
        }
        String ragText = ragText(prompt, checkContract == null ? null : checkContract.rule());
        boolean boundaryPresent = StringUtils.hasText(ragText)
                && (containsIgnoreCase(ragText, "evidence only")
                || containsIgnoreCase(ragText, "not instructions")
                || containsIgnoreCase(ragText, "authorized document facts"));
        List<String> facts = new ArrayList<>();
        facts.add(readableFact(checkContract, "RagEvidenceBoundaryPresent", String.valueOf(boundaryPresent)));
        return joinCustomerSentences(facts.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .toList());
    }

    private String termMatchSummary(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            String countLabel) {
        FinalPromptMetricRule rule = checkContract == null ? null : checkContract.rule();
        if (prompt == null || rule == null) {
            return "";
        }
        List<String> terms = new ArrayList<>();
        addContractItems(terms, rule.forbiddenTerms() == null ? "" : String.join(",", rule.forbiddenTerms()));
        addContractItems(terms, rule.terms() == null ? "" : String.join(",", rule.terms()));
        if (terms.isEmpty()) {
            return "";
        }
        long matched = terms.stream()
                .filter(StringUtils::hasText)
                .filter(prompt::contains)
                .distinct()
                .count();
        return readableFact(checkContract, FinalPromptDisplayValues.firstNonBlank(countLabel, "TermMatchCount"), String.valueOf(matched));
    }

    private String ragDocumentAlignmentSummary(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            FinalPromptEvidenceContext evidence,
            boolean requireUser,
            boolean requireAuthorization) {
        List<Object> documents = FinalPromptRagDocumentReader.documents(prompt, evidence);
        if (documents.isEmpty()) {
            return "";
        }
        RagAlignmentRequest request = ragAlignmentRequest(prompt);
        List<String> facts = ragAlignmentRequestFacts(checkContract, documents.size(), request, requireUser);
        RagAlignmentCounts counts = ragAlignmentCounts(documents, request, requireUser, requireAuthorization);
        addRagAlignmentCountFacts(facts, checkContract, counts, requireUser, requireAuthorization);
        return joinCustomerSentences(facts.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .toList());
    }

    private RagAlignmentRequest ragAlignmentRequest(FinalPromptSnapshot prompt) {
        return new RagAlignmentRequest(
                FinalPromptRagDocumentReader.firstPromptValue(prompt, "TenantId", "Tenant"),
                FinalPromptRagDocumentReader.firstPromptValue(prompt, "UserId", "User"),
                FinalPromptRagDocumentReader.firstPromptValue(prompt, "ResourceId", "Resource ID"),
                FinalPromptRagDocumentReader.firstPromptValue(prompt, "RequestPath", "Path"),
                FinalPromptRagDocumentReader.firstPromptValue(prompt, "CurrentResourceFamily", "ResourceFamily"),
                FinalPromptRagDocumentReader.firstPromptValue(prompt, "CurrentPathFamily", "PathFamily"));
    }

    private List<String> ragAlignmentRequestFacts(
            FinalPromptMetricCheckContract checkContract,
            int documentCount,
            RagAlignmentRequest request,
            boolean requireUser) {
        List<String> facts = new ArrayList<>();
        facts.add(readableFact(checkContract, "RagDocumentCount", String.valueOf(documentCount)));
        if (StringUtils.hasText(request.tenant())) {
            facts.add(readableFact(checkContract, "RequestTenantId", request.tenant()));
        }
        if (requireUser && StringUtils.hasText(request.user())) {
            facts.add(readableFact(checkContract, "RequestUserId", request.user()));
        }
        if (StringUtils.hasText(request.resourceId())) {
            facts.add(readableFact(checkContract, "RequestResourceId", request.resourceId()));
        }
        if (StringUtils.hasText(request.path())) {
            facts.add(readableFact(checkContract, "RequestPath", request.path()));
        }
        return facts;
    }

    private RagAlignmentCounts ragAlignmentCounts(
            List<Object> documents,
            RagAlignmentRequest request,
            boolean requireUser,
            boolean requireAuthorization) {
        int tenantMismatch = 0;
        int userMismatch = 0;
        int resourceMismatch = 0;
        int purposeMissing = 0;
        int authorizationMissing = 0;
        for (Object document : documents) {
            tenantMismatch += FinalPromptRagDocumentReader.sameValue(FinalPromptRagDocumentReader.fieldValue(document, "tenantId"), request.tenant()) ? 0 : 1;
            userMismatch += requireUser
                    && !FinalPromptRagDocumentReader.sameValue(FinalPromptRagDocumentReader.fieldValue(document, "userId"), request.user()) ? 1 : 0;
            resourceMismatch += FinalPromptRagDocumentReader.resourceMatchesRequest(
                    document, request.resourceId(), request.path(), request.resourceFamily(), request.pathFamily()) ? 0 : 1;
            purposeMissing += StringUtils.hasText(FinalPromptDisplayValues.firstNonBlank(
                    FinalPromptRagDocumentReader.fieldValue(document, "retrievalPurpose"),
                    FinalPromptRagDocumentReader.fieldValue(document, "purpose"))) ? 0 : 1;
            authorizationMissing += requireAuthorization && !FinalPromptRagDocumentReader.authorizationPresent(document) ? 1 : 0;
        }
        return new RagAlignmentCounts(
                tenantMismatch, userMismatch, resourceMismatch, purposeMissing, authorizationMissing);
    }

    private void addRagAlignmentCountFacts(
            List<String> facts,
            FinalPromptMetricCheckContract checkContract,
            RagAlignmentCounts counts,
            boolean requireUser,
            boolean requireAuthorization) {
        facts.add(readableFact(checkContract, "RagTenantMismatchCount", String.valueOf(counts.tenantMismatch())));
        if (requireUser) {
            facts.add(readableFact(checkContract, "RagUserMismatchCount", String.valueOf(counts.userMismatch())));
        }
        facts.add(readableFact(checkContract, "RagResourceMismatchCount", String.valueOf(counts.resourceMismatch())));
        facts.add(readableFact(checkContract, "RagPurposeMissingCount", String.valueOf(counts.purposeMissing())));
        if (requireAuthorization) {
            facts.add(readableFact(
                    checkContract, "RagAuthorizationMissingCount", String.valueOf(counts.authorizationMissing())));
        }
    }

    private record RagAlignmentRequest(
            String tenant,
            String user,
            String resourceId,
            String path,
            String resourceFamily,
            String pathFamily) {
    }

    private record RagAlignmentCounts(
            int tenantMismatch,
            int userMismatch,
            int resourceMismatch,
            int purposeMissing,
            int authorizationMissing) {
    }
    private String ragStateSummary(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            FinalPromptEvidenceContext evidence,
            String... items) {
        if (items == null || items.length == 0) {
            return "";
        }
        List<String> facts = new ArrayList<>();
        for (String item : items) {
            String value = runtimeEvidenceValue(checkContract, item, evidence);
            if (!StringUtils.hasText(value)) {
                value = runtimeSnapshotValueForDeclaredItem(checkContract, item, prompt);
            }
            if (!StringUtils.hasText(value) && prompt != null) {
                value = prompt.firstValue(item);
            }
            if (StringUtils.hasText(value)) {
                facts.add(readableFact(checkContract, item, value));
            }
        }
        return joinCustomerSentences(facts.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .toList());
    }

    private String ragRuleTermSummary(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            boolean forbiddenTerms) {
        FinalPromptMetricRule rule = checkContract == null ? null : checkContract.rule();
        if (prompt == null || rule == null) {
            return "";
        }
        String ragText = ragText(prompt, rule);
        if (forbiddenTerms) {
            return forbiddenRagTermSummary(
                    checkContract, rule, ragText, displayVisibleCheck(checkContract));
        }
        return requiredRagTermSummary(
                checkContract, rule, ragText, displayVisibleCheck(checkContract));
    }

    private String forbiddenRagTermSummary(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            String ragText,
            boolean customerDisplay) {
        List<String> terms = ragForbiddenTerms(rule);
        List<String> facts = new ArrayList<>();
        if (!StringUtils.hasText(ragText)) {
            if (customerDisplay) {
                facts.add(readableFact(checkContract, "RagForbiddenTermCheckedCount", String.valueOf(terms.size())));
                facts.add(readableFact(checkContract, "RagForbiddenTermMatchCount", "0"));
                return joinCustomerSentences(facts.stream()
                        .filter(StringUtils::hasText)
                        .distinct()
                        .toList());
            }
            List<String> expected = terms.stream()
                    .map(term -> contractMappedValue(checkContract, term))
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList();
            if (!expected.isEmpty()) {
                facts.add("ragForbiddenTermCheckedCount=" + expected.size());
                facts.add("ragForbiddenTermMatchCount=0");
            }
            return joinCustomerSentences(facts);
        }
        long matchCount = terms.stream()
                .filter(term -> containsIgnoreCase(ragText, term))
                .map(term -> contractMappedValue(checkContract, term))
                .filter(StringUtils::hasText)
                .distinct()
                .count();
        if (customerDisplay) {
            facts.add(readableFact(checkContract, "RagForbiddenTermCheckedCount", String.valueOf(terms.size())));
            facts.add(readableFact(checkContract, "RagForbiddenTermMatchCount", String.valueOf(matchCount)));
            return joinCustomerSentences(facts.stream()
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList());
        }
        facts.add("ragForbiddenTermCheckedCount=" + terms.size());
        facts.add("ragForbiddenTermMatchCount=" + matchCount);
        return joinCustomerSentences(facts);
    }

    private List<String> ragForbiddenTerms(FinalPromptMetricRule rule) {
        List<String> terms = new ArrayList<>();
        addContractItems(terms, rule.terms() == null ? "" : String.join(",", rule.terms()));
        addContractItems(terms, rule.forbiddenTerms() == null ? "" : String.join(",", rule.forbiddenTerms()));
        addContractItems(terms, rule.thenTerms() == null ? "" : String.join(",", rule.thenTerms()));
        return terms;
    }

    private String requiredRagTermSummary(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule,
            String ragText,
            boolean customerDisplay) {
        if (customerDisplay || rule.labelGroups() == null || rule.labelGroups().isEmpty()) {
            return "";
        }
        if (!StringUtils.hasText(ragText)) {
            List<String> expected = new ArrayList<>();
            for (List<String> group : rule.labelGroups()) {
                ragGroupTerms(group).stream()
                        .map(term -> contractMappedValue(checkContract, term))
                        .filter(StringUtils::hasText)
                        .forEach(expected::add);
            }
            return expected.isEmpty() ? ""
                    : "ragEvidenceRequirementMetCount=0, ragEvidenceRequirementMissingCount="
                    + expected.stream().distinct().count();
        }
        List<String> facts = new ArrayList<>();
        int groupIndex = 1;
        for (List<String> group : rule.labelGroups()) {
            List<String> groupTerms = ragGroupTerms(group);
            if (groupTerms.isEmpty()) {
                continue;
            }
            List<String> present = groupTerms.stream()
                    .filter(term -> containsIgnoreCase(ragText, term))
                    .map(term -> contractMappedValue(checkContract, term))
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList();
            long expectedCount = groupTerms.stream()
                    .map(term -> contractMappedValue(checkContract, term))
                    .filter(StringUtils::hasText)
                    .distinct()
                    .count();
            if (!present.isEmpty()) {
                facts.add("ragEvidenceGroup" + groupIndex + "PresentCount=" + present.size());
            }
            else if (expectedCount > 0) {
                facts.add("ragEvidenceGroup" + groupIndex + "MissingCount=" + expectedCount);
            }
            groupIndex++;
        }
        return joinCustomerSentences(facts);
    }
    private boolean isRagRuntimeItem(String item) {
        if (!StringUtils.hasText(item)) {
            return false;
        }
        String normalized = item.trim().toLowerCase(Locale.ROOT);
        return normalized.startsWith("rag") || "relateddocumentcount".equals(normalized);
    }

    private String runtimePromptRagDocumentValue(FinalPromptMetricCheckContract checkContract, FinalPromptSnapshot prompt) {
        if (prompt == null) {
            return "";
        }
        return ragDocumentAggregateSummary(checkContract, prompt, null,
                "userId", "tenantId", "organizationId", "resourceId", "requestPath", "retrievalPurpose", "accessScope");
    }

    private String ragDocumentAggregateSummary(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            FinalPromptEvidenceContext evidence,
            String... keys) {
        List<Object> documents = FinalPromptRagDocumentReader.documents(prompt, evidence);
        if (documents.isEmpty()) {
            return "";
        }
        List<String> facts = new ArrayList<>();
        facts.add(readableFact(checkContract, "RagDocumentCount", String.valueOf(documents.size())));
        if (keys != null) {
            for (String key : keys) {
                List<String> values = documents.stream()
                        .map(document -> FinalPromptRagDocumentReader.fieldValue(document, key))
                        .filter(StringUtils::hasText)
                        .map(FinalPromptDisplayValues::customerRuntimeValue)
                        .distinct()
                        .toList();
                if (!values.isEmpty()) {
                    facts.add(readableFact(checkContract, key, FinalPromptDisplayValues.clippedCustomerList(values, 3, messageResolver)));
                }
            }
        }
        return joinCustomerSentences(facts);
    }

    private String ragDocumentCountSummary(
            FinalPromptMetricCheckContract checkContract,
            FinalPromptSnapshot prompt,
            FinalPromptEvidenceContext evidence) {
        List<Object> documents = FinalPromptRagDocumentReader.documents(prompt, evidence);
        if (documents.isEmpty()) {
            return "";
        }
        List<String> facts = new ArrayList<>();
        facts.add(readableFact(checkContract, "RagDocumentCount", String.valueOf(documents.size())));
        return joinCustomerSentences(facts);
    }

    private String runtimeSnapshotValueForDeclaredItem(
            FinalPromptMetricCheckContract checkContract,
            String item,
            FinalPromptSnapshot prompt) {
        if (!StringUtils.hasText(item) || prompt == null) {
            return "";
        }
        if ("ragdocument".equalsIgnoreCase(item.trim())) {
            return runtimePromptRagDocumentValue(checkContract, prompt);
        }
        return runtimeSnapshotValue(item, prompt);
    }

    private String runtimeSnapshotValue(String item, FinalPromptSnapshot prompt) {
        if (!StringUtils.hasText(item) || prompt == null) {
            return "";
        }
        return switch (item.trim().toLowerCase(Locale.ROOT)) {
            case "compactmarkers", "compactmarker", "finaluserprompt.compactmarkers" ->
                    prompt.compactMarkers().isEmpty()
                            ? "0"
                            : FinalPromptDisplayValues.clippedCustomerList(prompt.compactMarkers(), 3, messageResolver);
            case "ragdocument" -> runtimePromptRagDocumentValue(null, prompt);
            case "unmappedpromptfacts", "promptfactmapping", "finaluserprompt.unmappedfacts" ->
                    String.valueOf(prompt.unmappedFacts().size());
            case "promptsectionset", "promptsections" -> prompt.sections().stream()
                    .map(FinalPromptSection::name)
                    .filter(StringUtils::hasText)
                    .distinct()
                    .collect(Collectors.joining(", "));
            default -> "";
        };
    }

    private String runtimeEvidenceValue(
            FinalPromptMetricCheckContract checkContract,
            String item,
            FinalPromptEvidenceContext evidence) {
        if (!StringUtils.hasText(item) || evidence == null) {
            return "";
        }
        String promptTrace = promptTraceValue(evidence, item);
        if (StringUtils.hasText(promptTrace) && !"missing".equalsIgnoreCase(promptTrace.trim())) {
            return promptTrace;
        }
        Map<String, Object> rag = evidence.ragResults();
        if (rag == null || rag.isEmpty()) {
            return "";
        }
        Object value = switch (item.trim().toLowerCase(Locale.ROOT)) {
            case "ragsearchexecuted" -> FinalPromptDisplayValues.firstPresent(rag, "ragSearchExecuted", "searchExecuted", "retrievalExecuted");
            case "ragretrievalstate" -> FinalPromptDisplayValues.firstPresent(rag, "ragRetrievalState", "retrievalStatus", "status");
            case "relateddocumentcount" -> FinalPromptDisplayValues.firstPresent(rag,
                    "relatedDocumentCount", "documentCount", "authorizedRelatedDocumentCount", "authorizedDocumentCount");
            case "ragcandidatedocumentcount" -> FinalPromptDisplayValues.firstPresent(rag,
                    "ragCandidateDocumentCount", "candidateDocumentCount", "candidateCount");
            case "ragauthorizeddocumentcount" -> FinalPromptDisplayValues.firstPresent(rag,
                    "ragAuthorizedDocumentCount", "authorizedRelatedDocumentCount", "authorizedDocumentCount",
                    "allowedDocumentCount", "allowedCount");
            case "ragdenieddocumentcount" -> FinalPromptDisplayValues.firstPresent(rag,
                    "ragDeniedDocumentCount", "deniedDocumentCount", "excludedDocumentCount");
            case "ragpermissionfiltered" -> FinalPromptDisplayValues.firstPresent(rag, "ragPermissionFiltered", "permissionFiltered");
            case "ragprojectionstate" -> FinalPromptDisplayValues.firstPresent(rag, "ragProjectionState", "projectionState");
            case "ragprojectedtofinalprompt" -> FinalPromptDisplayValues.firstPresent(rag, "ragProjectedToFinalPrompt", "projectedToFinalPrompt");
            case "ragabsencereason" -> FinalPromptDisplayValues.firstPresent(rag, "ragAbsenceReason", "absenceReason", "retrievalState");
            case "ragapplicability" -> FinalPromptDisplayValues.firstPresent(rag, "ragApplicability", "applicability");
            case "ragdocument" -> ragDocumentRuntimeValue(checkContract,
                    FinalPromptDisplayValues.firstPresent(rag, "ragDocument", "ragDocuments", "documents", "relatedDocuments"));
            default -> FinalPromptDisplayValues.firstPresent(rag, FinalPromptDisplayValues.lowerFirst(item.trim()), item.trim());
        };
        return FinalPromptDisplayValues.customerRuntimeValue(value, messageResolver);
    }

    private String ragDocumentRuntimeValue(FinalPromptMetricCheckContract checkContract, Object value) {
        List<Object> documents = FinalPromptRagDocumentReader.documents(value);
        if (documents.isEmpty()) {
            return "";
        }
        List<String> summaries = new ArrayList<>();
        summaries.add(readableFact(checkContract, "RagDocumentCount", String.valueOf(documents.size())));
        for (String key : List.of("userId", "tenantId", "organizationId", "resourceId", "requestPath", "retrievalPurpose", "accessScope")) {
            List<String> values = documents.stream()
                    .map(document -> FinalPromptRagDocumentReader.fieldValue(document, key))
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList();
            if (!values.isEmpty()) {
                summaries.add(readableFact(checkContract, key, FinalPromptDisplayValues.clippedCustomerList(values, 3, messageResolver)));
            }
        }
        return joinCustomerSentences(summaries);
    }

    private String ragDocumentSummaryValue(Object document, int index) {
        if (document instanceof Map<?, ?> map) {
            List<String> facts = new ArrayList<>();
            addRagDocumentFact(facts, "documentType", map.get("documentType"));
            addRagDocumentFact(facts, "userId", map.get("userId"));
            addRagDocumentFact(facts, "tenantId", map.get("tenantId"));
            addRagDocumentFact(facts, "organizationId", map.get("organizationId"));
            addRagDocumentFact(facts, "resourceId", map.get("resourceId"));
            addRagDocumentFact(facts, "requestPath", map.get("requestPath"));
            addRagDocumentFact(facts, "retrievalPurpose", map.get("retrievalPurpose"));
            addRagDocumentFact(facts, "accessScope", map.get("accessScope"));
            addRagDocumentFact(facts, "action", map.get("action"));
            if (facts.isEmpty()) {
                return "";
            }
            return "ragDocument" + index + "[" + String.join(", ", facts) + "]";
        }
        String text = FinalPromptDisplayValues.customerRuntimeValue(document, messageResolver);
        if (!StringUtils.hasText(text)) {
            return "";
        }
        List<String> parsedFacts = ragDocumentFactsFromText(text);
        if (!parsedFacts.isEmpty()) {
            return "ragDocument" + index + "[" + String.join(", ", parsedFacts) + "]";
        }
        return "ragDocument" + index + "[" + customerPurposeText(text) + "]";
    }

    private List<String> ragDocumentFactsFromText(String text) {
        if (!StringUtils.hasText(text)) {
            return List.of();
        }
        String normalized = text.trim();
        int open = normalized.indexOf('[');
        int close = normalized.indexOf(']');
        if (open >= 0 && close > open) {
            normalized = normalized.substring(open + 1, close);
        }
        List<String> facts = new ArrayList<>();
        for (String token : normalized.split("\\|\\s*|,\\s*")) {
            if (!StringUtils.hasText(token) || !token.contains("=")) {
                continue;
            }
            int index = token.indexOf('=');
            String key = token.substring(0, index).trim();
            String value = token.substring(index + 1).trim();
            if (!StringUtils.hasText(key) || !StringUtils.hasText(value)) {
                continue;
            }
            String displayKey = switch (key.toLowerCase(Locale.ROOT)) {
                case "type" -> "documentType";
                case "user" -> "userId";
                case "tenant" -> "tenantId";
                case "organization", "org" -> "organizationId";
                case "resource" -> "resourceId";
                case "auth" -> "authorization";
                case "prov" -> "provenance";
                default -> key;
            };
            if ("id".equalsIgnoreCase(displayKey) || displayKey.toLowerCase(Locale.ROOT).startsWith("doc")) {
                continue;
            }
            facts.add(message("verification.finalPrompt.value.named", displayKey, customerPurposeText(value)));
        }
        return facts.stream().filter(StringUtils::hasText).distinct().toList();
    }

    private void addRagDocumentFact(List<String> facts, String key, Object value) {
        String text = FinalPromptDisplayValues.customerRuntimeValue(value, messageResolver);
        if (facts != null && StringUtils.hasText(key) && StringUtils.hasText(text)) {
            facts.add(message("verification.finalPrompt.value.named", key, text));
        }
    }

    private String contractRuntimeFactsFromEvidence(
            FinalPromptMetricCheckContract checkContract,
            List<String> evidenceValues) {
        String readable = readableEvidenceFacts(checkContract, evidenceValues);
        if (StringUtils.hasText(readable)) {
            return readable;
        }
        return displayVisibleCheck(checkContract) ? "" : runtimeFactFallback(checkContract);
    }

    private String runtimeFactFallback(FinalPromptMetricCheckContract checkContract) {
        return "";
    }

    private List<Map<String, String>> safeEvidenceBindings(FinalPromptMetricCheckContract checkContract) {
        List<Map<String, String>> bindings = checkContract == null ? null : checkContract.evidenceBindings();
        return bindings == null ? List.of() : bindings;
    }

    private List<String> contractBindingLabels(Map<String, String> binding) {
        if (binding == null) {
            return List.of();
        }
        List<String> labels = new ArrayList<>();
        addContractItems(labels, binding.get("labels"));
        addContractItems(labels, binding.get("label"));
        return labels.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .toList();
    }

    private String contractContextItemsText(FinalPromptMetricCheckContract checkContract) {
        List<String> items = new ArrayList<>();
        for (Map<String, String> binding : safeEvidenceBindings(checkContract)) {
            if (binding == null) {
                continue;
            }
            List<String> bindingItems = new ArrayList<>();
            addContractItems(bindingItems, binding.get("customerVisibleContextItems"), checkContract);
            addContractItems(bindingItems, binding.get("customerVisiblePromptItems"), checkContract);
            if (!displayVisibleCheck(checkContract)) {
                addContractItems(bindingItems, binding.get("contextItems"), checkContract);
                addContractItems(bindingItems, binding.get("promptItems"), checkContract);
                if (bindingItems.isEmpty()) {
                    addContractItems(bindingItems, binding.get("labels"), checkContract);
                    addContractItems(bindingItems, binding.get("label"), checkContract);
                }
                if (bindingItems.isEmpty()) {
                    addContractItems(bindingItems, binding.get("sections"), checkContract);
                }
            }
            items.addAll(bindingItems);
        }
        List<String> distinctItems = items.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .toList();
        for (String item : distinctItems) {
            assertCustomerVisibleContextItem(checkContract, item);
        }
        String contextItems = String.join(", ", distinctItems);
        if (StringUtils.hasText(contextItems)) {
            return contextItems;
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible context item binding is missing. metric="
                + metricCode()
                + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract == null ? null : checkContract.checkName(), "UNKNOWN_CHECK"));
    }

    private void assertCustomerVisibleContextItem(
            FinalPromptMetricCheckContract checkContract,
            String item) {
        if (checkContract == null || !checkContract.customerVisible() || !StringUtils.hasText(item)) {
            return;
        }
        if (!isKnownPromptSignal(item)) {
            String metric = normalizeMetric(metricCode());
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible context item is not a prompt field. metric="
                    + metric
                    + ", check=" + FinalPromptDisplayValues.firstNonBlank(checkContract.checkName(), "UNKNOWN_CHECK")
                    + ", contextItem=" + item);
        }
    }

    private boolean isKnownPromptSignal(String item) {
        return contractCatalog != null && contractCatalog.isKnownPromptFact(null, item);
    }

    private void addContractItems(
            List<String> items,
            String raw,
            FinalPromptMetricCheckContract checkContract) {
        if (items == null || !StringUtils.hasText(raw)) {
            return;
        }
        for (String token : raw.split("[,|]")) {
            if (StringUtils.hasText(token)) {
                items.add(token.trim());
            }
        }
    }

    private void addContractItems(List<String> items, String raw) {
        if (items == null || !StringUtils.hasText(raw)) {
            return;
        }
        for (String token : raw.split("[,|]")) {
            if (StringUtils.hasText(token)) {
                items.add(token.trim());
            }
        }
    }

    private String requiredText(String value, String fieldName) {
        if (StringUtils.hasText(value)) {
            return value.trim();
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Missing " + fieldName
                + ". metricCode=" + metricCode());
    }

    private boolean contractMetadataSignal(String signal) {
        if (!StringUtils.hasText(signal)) {
            return false;
        }
        String trimmed = signal.trim();
        int equalsIndex = trimmed.indexOf('=');
        String key = equalsIndex < 0 ? trimmed : trimmed.substring(0, equalsIndex).trim();
        return "purposeSignal".equals(key)
                || "meaning".equals(key)
                || "securityRelevance".equals(key)
                || "interpretationLink".equals(key)
                || "purposeResult".equals(key);
    }

    private String valueAfter(String signal, String prefix) {
        if (!StringUtils.hasText(signal) || !StringUtils.hasText(prefix) || !signal.startsWith(prefix)) {
            return "";
        }
        String value = signal.substring(prefix.length()).trim();
        int commaIndex = value.indexOf(',');
        return commaIndex < 0 ? value : value.substring(0, commaIndex).trim();
    }

    private String namedPart(String signal, String name) {
        if (!StringUtils.hasText(signal) || !StringUtils.hasText(name)) {
            return "";
        }
        int index = signal.indexOf(name);
        if (index < 0) {
            return "";
        }
        String value = signal.substring(index + name.length()).trim();
        int commaIndex = value.indexOf(',');
        return commaIndex < 0 ? value : value.substring(0, commaIndex).trim();
    }

    private String stripLineSuffix(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.replaceFirst("\\s*\\(line\\s+\\d+\\)\\s*$", "").trim();
    }
    private void collectEvidence(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context,
            EvidenceCollector collector) {
        if (rule == null || collector == null) {
            return;
        }
        String operator = normalizeCheckName(rule.operator());
        FinalPromptSnapshot prompt = context == null ? null : context.prompt();
        collectDirectEvidence(rule, prompt, collector);
        collectStructuralEvidence(rule, operator, prompt, collector);
        boolean ragTextOperator = operator.startsWith("RAG_TEXT")
                || "RAG_BLOCKED_DOCUMENT_EXCLUDED".equals(operator);
        boolean systemTextOperator = "SYSTEM_TERM_GROUPS_PRESENT".equals(operator);
        collectTermOperatorEvidence(rule, context, operator, prompt, collector, ragTextOperator, systemTextOperator);
        collectContextEvidence(rule, context, operator, collector);
        collectConsistencyEvidence(
                rule, context, operator, prompt, collector, ragTextOperator, systemTextOperator);
        collectChildEvidence(rule, context, collector);
    }

    private void collectDirectEvidence(
            FinalPromptMetricRule rule,
            FinalPromptSnapshot prompt,
            EvidenceCollector collector) {
        for (String section : rule.sections()) {
            collector.add(sectionEvidence(prompt, section));
        }
        for (String label : rule.labels()) {
            collector.add(labelEvidence(prompt, label));
        }
        if (StringUtils.hasText(rule.field())) {
            collector.add(labelEvidence(prompt, rule.field()));
        }
        for (String label : rule.thenLabels()) {
            collector.add(labelEvidence(prompt, label));
        }
    }

    private void collectStructuralEvidence(
            FinalPromptMetricRule rule,
            String operator,
            FinalPromptSnapshot prompt,
            EvidenceCollector collector) {
        if ("RAG_DOCUMENT_SURFACE_PRESENT".equals(operator)) {
            collector.add("ragText=" + (StringUtils.hasText(ragText(prompt, rule)) ? "present" : "empty"));
        }
        if (operator.contains("COMPACT")) {
            collector.add(compactMarkerEvidence(prompt));
        }
        if (operator.contains("TRUNCATED")) {
            truncatedEvidence(prompt).forEach(collector::add);
        }
        if ("UNMAPPED_PROMPT_FACTS_ABSENT".equals(operator)) {
            unmappedPromptFactEvidence(prompt).forEach(collector::add);
        }
    }

    private void collectTermOperatorEvidence(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context,
            String operator,
            FinalPromptSnapshot prompt,
            EvidenceCollector collector,
            boolean ragTextOperator,
            boolean systemTextOperator) {
        if (ragTextOperator) {
            collectRagTextEvidence(rule, context, operator, collector);
            return;
        }
        if (!operator.contains("FORBIDDEN") && !operator.contains("TERM")) {
            return;
        }
        for (String term : rule.terms()) {
            collector.add(systemTextOperator
                    ? termEvidence(systemPrompt(context), term, term)
                    : termEvidence(prompt, term, term));
        }
        for (String term : rule.thenTerms()) {
            collector.add(systemTextOperator
                    ? termEvidence(systemPrompt(context), term, term)
                    : termEvidence(prompt, term, term));
        }
        for (String term : rule.forbiddenTerms()) {
            collector.add(systemTextOperator
                    ? termEvidence(systemPrompt(context), term, term)
                    : termEvidence(prompt, term, term));
        }
    }

    private void collectContextEvidence(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context,
            String operator,
            EvidenceCollector collector) {
        if (operator.startsWith("RAG_") || operator.contains("RAG")) {
            collector.add(ragEvidence(context == null ? null : context.evidence()));
            collector.add(ragApplicabilityEvidence(context, rule));
        }
        if (operator.contains("PREFLIGHT") || operator.contains("PROMPT_ARTIFACT")
                || operator.contains("LINEAGE") || operator.contains("MANIFEST")) {
            collector.add(preflightEvidence(context == null ? null : context.evidence()));
        }
    }

    private void collectConsistencyEvidence(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context,
            String operator,
            FinalPromptSnapshot prompt,
            EvidenceCollector collector,
            boolean ragTextOperator,
            boolean systemTextOperator) {
        if ("SENSITIVE_FLAG_CONSISTENT".equals(operator)) {
            collector.add(sensitiveConsistencyOutcomeEvidence(prompt, rule.labels()));
            for (String label : rule.labels()) {
                collector.add(labelEvidence(prompt, label));
            }
        }
        if ("RESOURCE_TEMPLATE_TOKEN_ABSENT".equals(operator)) {
            collector.add(labelEvidence(prompt, "ResourceId"));
            collector.add(labelEvidence(prompt, "RequestPath"));
            collector.add(labelEvidence(prompt, "Path"));
        }
        boolean promptFields = "FIELD_VALUES_CONSISTENT".equals(operator)
                || "OPTIONAL_FIELD_VALUES_CONSISTENT".equals(operator)
                || "BOOLEAN_FIELDS_CONSISTENT".equals(operator);
        if (promptFields) {
            collector.add(fieldConsistencyOutcomeEvidence(prompt, rule.labels(), operator));
        }
        if ("IF_ANY_TERM_PRESENT_THEN_ANY_FIELD_OR_TERM_PRESENT".equals(operator)
                && authorizationStageNoteRule(rule)) {
            collector.add(stageNoteRelationEvidence(prompt, rule));
        }
        collectLabelGroupEvidence(
                rule, context, prompt, collector, ragTextOperator, systemTextOperator, promptFields);
    }

    private void collectLabelGroupEvidence(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context,
            FinalPromptSnapshot prompt,
            EvidenceCollector collector,
            boolean ragTextOperator,
            boolean systemTextOperator,
            boolean promptFields) {
        for (List<String> group : rule.labelGroups()) {
            for (String term : group) {
                collector.add(promptFields
                        ? labelEvidence(prompt, term)
                        : (ragTextOperator ? "" : (systemTextOperator
                        ? termEvidence(systemPrompt(context), term, term)
                        : termEvidence(prompt, term, term))));
            }
        }
    }

    private void collectChildEvidence(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context,
            EvidenceCollector collector) {
        for (FinalPromptMetricRule child : rule.all()) {
            collectEvidence(child, context, collector);
        }
        for (FinalPromptMetricRule child : rule.any()) {
            collectEvidence(child, context, collector);
        }
    }
    private String sectionEvidence(FinalPromptSnapshot prompt, String section) {
        if (!StringUtils.hasText(section)) {
            return "";
        }
        if (prompt == null || !prompt.hasSection(section)) {
            return "section " + section + "=missing";
        }
        String normalizedSection = FinalPromptSnapshot.normalizeSection(section);
        for (FinalPromptSection item : prompt.sections()) {
            if (FinalPromptSnapshot.normalizeSection(item.name()).equals(normalizedSection)) {
                return "section " + section + "=present(line " + item.lineNumber() + ")";
            }
        }
        return "section " + section + "=present";
    }

    private String labelEvidence(FinalPromptSnapshot prompt, String label) {
        if (!StringUtils.hasText(label)) {
            return "";
        }
        if (prompt == null) {
            return label + "=missing";
        }
        List<FinalPromptField> fields = prompt.fieldsByLabel(label);
        if (fields.isEmpty()) {
            return label + "=missing";
        }
        FinalPromptField field = fields.get(0);
        return label + "=" + evidenceValue(field.value()) + "(line " + field.lineNumber() + ")";
    }

    private String evidenceValue(String value) {
        if (!StringUtils.hasText(value) || "null".equalsIgnoreCase(value)) {
            return "missing";
        }
        return value.trim()
                .replace("|", ", ")
                .replace("...", " omitted ")
                .replaceAll("\\s+", " ");
    }

    private String fieldConsistencyOutcomeEvidence(
            FinalPromptSnapshot prompt,
            List<String> labels,
            String operator) {
        if (prompt == null || labels == null || labels.isEmpty()) {
            return "consistencyOutcome=NO_INPUT_VALUES";
        }
        Set<String> distinctValues = new LinkedHashSet<>();
        List<String> presentLabels = new ArrayList<>();
        List<String> missingLabels = new ArrayList<>();
        for (String label : labels) {
            List<FinalPromptField> fields = prompt.fieldsByLabel(label);
            if (fields.isEmpty()) {
                missingLabels.add(label);
                continue;
            }
            for (FinalPromptField field : fields) {
                if (!StringUtils.hasText(field.value()) || placeholderConsistencyValue(field.value())) {
                    missingLabels.add(label);
                    continue;
                }
                String comparable = "BOOLEAN_FIELDS_CONSISTENT".equals(operator)
                        ? normalizeBooleanComparable(field.value())
                        : normalizeComparableValue(field.value());
                if (StringUtils.hasText(comparable)) {
                    presentLabels.add(label);
                    distinctValues.add(comparable);
                }
                else {
                    missingLabels.add(label);
                }
            }
        }
        String outcome;
        if (presentLabels.isEmpty()) {
            outcome = "NO_INPUT_VALUES";
        }
        else if (distinctValues.size() <= 1 && presentLabels.size() == 1) {
            outcome = "NO_CONFLICT_SINGLE_VALUE";
        }
        else if (distinctValues.size() <= 1) {
            outcome = "NO_CONFLICT_MATCHED_VALUES";
        }
        else {
            outcome = "CONFLICT_DIFFERENT_VALUES";
        }
        return "consistencyOutcome=" + outcome
                + ", comparedLabels=" + FinalPromptDisplayValues.preview(String.join("|", presentLabels))
                + ", missingLabels=" + FinalPromptDisplayValues.preview(String.join("|", missingLabels))
                + ", distinctValues=" + FinalPromptDisplayValues.preview(String.join("|", distinctValues));
    }

    private String sensitiveConsistencyOutcomeEvidence(FinalPromptSnapshot prompt, List<String> labels) {
        if (prompt == null || labels == null || labels.size() < 2) {
            return "consistencyOutcome=NO_INPUT_VALUES";
        }
        String sensitivityLabel = labels.get(0);
        String sensitiveResourceLabel = labels.get(1);
        String sensitivity = prompt.firstValue(sensitivityLabel);
        String sensitiveResource = prompt.firstValue(sensitiveResourceLabel);
        boolean highSensitivity = normalizeComparableValue(sensitivity).contains("high")
                || normalizeComparableValue(sensitivity).contains("critical");
        boolean sensitiveFalse = "FALSE".equals(normalizeBooleanComparable(sensitiveResource));
        String outcome = highSensitivity && sensitiveFalse
                ? "CONFLICT_HIGH_SENSITIVITY_MARKED_NOT_SENSITIVE"
                : "NO_CONFLICT_SENSITIVITY_FLAG";
        return "consistencyOutcome=" + outcome
                + ", comparedLabels=" + FinalPromptDisplayValues.preview(String.join("|", labels))
                + ", distinctValues=" + sensitivityLabel + ":" + FinalPromptDisplayValues.preview(sensitivity)
                + "|" + sensitiveResourceLabel + ":" + FinalPromptDisplayValues.preview(sensitiveResource);
    }

    private String stageNoteRelationEvidence(FinalPromptSnapshot prompt, FinalPromptMetricRule rule) {
        if (prompt == null || rule == null) {
            return "stageNoteRelation=NO_INPUT_VALUES";
        }
        boolean stageNotePresent = rule.terms().stream().anyMatch(term -> prompt.contains(term));
        if (!stageNotePresent) {
            return "stageNoteRelation=NO_STAGE_NOTE_PRESENT";
        }
        boolean finalEffectLinked = rule.thenLabels().stream()
                .anyMatch(label -> !prompt.fieldsByLabel(label).isEmpty())
                || rule.thenTerms().stream().anyMatch(term -> prompt.contains(term));
        return finalEffectLinked
                ? "stageNoteRelation=BOUND_TO_FINAL_AUTHORIZATION_EFFECT"
                : "stageNoteRelation=UNBOUND_PARALLEL_FACT_RISK";
    }

    private boolean authorizationStageNoteRule(FinalPromptMetricRule rule) {
        if (rule == null) {
            return false;
        }
        boolean watchesAuthorizationStageNote = rule.terms().stream()
                .anyMatch(term -> "AuthorizationEffectStageNote".equalsIgnoreCase(term));
        boolean bindsFinalAuthorizationEffect = rule.thenLabels().stream()
                .anyMatch(label -> "AuthorizationEffect".equalsIgnoreCase(label));
        return watchesAuthorizationStageNote && bindsFinalAuthorizationEffect;
    }

    private String compactMarkerEvidence(FinalPromptSnapshot prompt) {
        if (prompt == null || prompt.compactMarkers().isEmpty()) {
            return "compactMarker=absent";
        }
        return "compactMarker=" + FinalPromptDisplayValues.preview(String.join(" | ", prompt.compactMarkers()));
    }

    private String termEvidence(FinalPromptSnapshot prompt, String term, String label) {
        return termEvidence(prompt == null ? "" : prompt.userPrompt(), term, label);
    }

    private String termEvidence(String text, String term, String label) {
        if (!StringUtils.hasText(term)) {
            return "";
        }
        boolean present = containsIgnoreCase(text, term);
        return FinalPromptDisplayValues.firstNonBlank(label, term) + "=" + (present ? "present" : "absent");
    }

    private List<String> truncatedEvidence(FinalPromptSnapshot prompt) {
        if (prompt == null) {
            return List.of("truncatedMarker=absent");
        }
        List<String> evidence = new ArrayList<>();
        for (FinalPromptField field : prompt.fields()) {
            if (containsTruncationMarker(field.value())) {
                evidence.add("truncatedField=" + promptFactLocation(field.section(), field.label(), field.lineNumber())
                        + " value=" + evidencePreview(field.value()));
            }
        }
        for (FinalPromptBullet bullet : prompt.bullets()) {
            if (containsTruncationMarker(bullet.text())) {
                evidence.add("truncatedBullet=" + promptFactLocation(bullet.section(), "bullet", bullet.lineNumber())
                        + " value=" + evidencePreview(bullet.text()));
            }
        }
        for (FinalPromptNarrativeLine line : prompt.narrativeLines()) {
            if (containsTruncationMarker(line.text())) {
                evidence.add("truncatedNarrative=" + promptFactLocation(line.section(), "narrative", line.lineNumber())
                        + " value=" + evidencePreview(line.text()));
            }
        }
        if (evidence.isEmpty()) {
            return List.of("truncatedMarker=absent");
        }
        evidence.add(0, "truncatedMarker=present");
        return evidence;
    }

    private List<String> unmappedPromptFactEvidence(FinalPromptSnapshot prompt) {
        if (prompt == null || prompt.unmappedFacts().isEmpty()) {
            return List.of("unmapped prompt fact absent");
        }
        return List.of("unmapped prompt fact present");
    }

    private String promptFactLocation(String section, String label, int lineNumber) {
        return FinalPromptDisplayValues.firstNonBlank(section, "UNKNOWN SECTION")
                + "." + FinalPromptDisplayValues.firstNonBlank(label, "UNKNOWN")
                + "(line " + lineNumber + ")";
    }

    private boolean containsTruncationMarker(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String normalized = value.trim();
        return normalized.contains("...")
                || containsIgnoreCase(normalized, "CompactedLineCategories")
                || containsIgnoreCase(normalized, "additional lines compacted")
                || containsIgnoreCase(normalized, "AdditionalContextTrustWarningsCompacted")
                || containsIgnoreCase(normalized, "AdditionalConfidenceWarningsCompacted");
    }

    private String evidencePreview(String value) {
        return evidencePreview(null, value);
    }

    private String evidencePreview(FinalPromptMetricCheckContract checkContract, String value) {
        if (!StringUtils.hasText(value) || "null".equalsIgnoreCase(value)) {
            return "missing";
        }
        List<String> parts = Arrays.stream(value.split("\\s*\\|\\s*"))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .toList();
        if (parts.size() > 1) {
            List<String> readable = new ArrayList<>();
            for (String part : parts) {
                int equalsIndex = part.indexOf('=');
                if (equalsIndex > 0) {
                    String key = part.substring(0, equalsIndex).trim();
                    String factValue = part.substring(equalsIndex + 1).trim();
                    String fact = readableFact(checkContract, key, factValue);
                    if (StringUtils.hasText(fact)) {
                        readable.add(fact);
                    }
                } else {
                    String mapped = contractMappedValue(checkContract, customerPurposeText(part));
                    if (StringUtils.hasText(mapped)) {
                        readable.add(mapped);
                    }
                }
            }
            if (!readable.isEmpty()) {
                int limit = Math.min(readable.size(), 6);
                String result = joinCustomerSentences(readable.subList(0, limit));
                int remaining = readable.size() - limit;
                if (remaining > 0) {
                    result += ". omittedItemCount=" + remaining;
                }
                return result;
            }
        }
        String normalized = customerPurposeText(value).replaceAll("\\s+", " ");
        return normalized.length() <= 220 ? normalized : normalized.substring(0, 217).trim() + " omitted";
    }
    private String ragEvidence(FinalPromptEvidenceContext evidence) {
        if (evidence == null || evidence.ragResults().isEmpty()) {
            return "ragResults=empty";
        }
        Map<String, Object> rag = evidence.ragResults();
        return "ragSearchExecuted=" + FinalPromptDisplayValues.preview(String.valueOf(rag.get("ragSearchExecuted")))
                + ", ragRetrievalState=" + FinalPromptDisplayValues.preview(String.valueOf(FinalPromptDisplayValues.firstPresent(rag,
                "ragRetrievalState", "retrievalStatus", "status")))
                + ", relatedDocumentCount=" + FinalPromptDisplayValues.preview(String.valueOf(FinalPromptDisplayValues.firstPresent(rag,
                "relatedDocumentCount", "documentCount", "authorizedDocumentCount")));
    }

    private String systemPrompt(FinalPromptMetricEvaluationContext context) {
        FinalPromptEvidenceContext evidence = context == null ? null : context.evidence();
        return evidence == null ? "" : evidence.systemPrompt();
    }

    private void collectRagTextEvidence(
            FinalPromptMetricRule rule,
            FinalPromptMetricEvaluationContext context,
            String operator,
            EvidenceCollector collector) {
        String ragText = ragText(context == null ? null : context.prompt(), rule);
        if (!StringUtils.hasText(ragText)) {
            collector.add("ragText=empty");
            return;
        }
        if ("RAG_TEXT_FORBIDDEN_TERMS_ABSENT".equals(operator)) {
            for (String term : rule.forbiddenTerms()) {
                collector.add(ragTermEvidence(ragText, term, term));
            }
            return;
        }
        if ("RAG_TEXT_TERM_GROUPS_PRESENT_WHEN_RAG_PRESENT".equals(operator)) {
            for (List<String> group : rule.labelGroups()) {
                for (String term : group) {
                    collector.add(ragTermEvidence(ragText, term, term));
                }
            }
            return;
        }
        if ("RAG_BLOCKED_DOCUMENT_EXCLUDED".equals(operator)) {
            for (String term : rule.terms()) {
                collector.add(ragTermEvidence(ragText, term, term));
            }
            for (String term : rule.thenTerms()) {
                collector.add(ragTermEvidence(ragText, term, term));
            }
        }
    }

    private String ragApplicabilityEvidence(FinalPromptMetricEvaluationContext context, FinalPromptMetricRule rule) {
        FinalPromptEvidenceContext evidence = context == null ? null : context.evidence();
        Map<String, Object> rag = evidence == null ? Map.of() : evidence.ragResults();
        String ragText = ragText(context == null ? null : context.prompt(), rule);
        if ((rag == null || rag.isEmpty()) && !StringUtils.hasText(ragText)) {
            return "ragApplicability=NO_RAG_CONTEXT";
        }
        int count = retrievedDocumentCount(rag);
        String state = String.valueOf(FinalPromptDisplayValues.firstPresent(rag, "ragRetrievalState", "retrievalStatus", "status"));
        if (containsIgnoreCase(state, "timeout") || containsIgnoreCase(state, "error")
                || asBoolean(FinalPromptDisplayValues.firstPresent(rag, "ragTimedOut", "searchTimedOut", "providerError", "vectorError"))) {
            return "ragApplicability=RETRIEVAL_FAILED";
        }
        if (count <= 0) {
            return "ragApplicability=ZERO_RESULTS_NO_DOCUMENTS";
        }
        return "ragApplicability=DOCUMENTS_RETRIEVED";
    }

    private String ragTermEvidence(String ragText, String term, String label) {
        if (!StringUtils.hasText(term)) {
            return "";
        }
        return FinalPromptDisplayValues.firstNonBlank(label, term) + "=" + (containsIgnoreCase(ragText, term) ? "present" : "absent");
    }

    private String ragText(FinalPromptSnapshot prompt, FinalPromptMetricRule rule) {
        if (prompt == null) {
            return "";
        }
        if (rule == null || rule.sections().isEmpty()) {
            throw new IllegalStateException("RAG metric evidence requires contract-defined sections.");
        }
        StringBuilder builder = new StringBuilder();
        for (String section : rule.sections()) {
            prompt.fields().stream()
                    .filter(field -> sameSection(field.section(), section))
                    .forEach(field -> builder.append(field.label()).append(' ').append(field.value()).append('\n'));
            prompt.bullets().stream()
                    .filter(bullet -> sameSection(bullet.section(), section))
                    .forEach(bullet -> builder.append(bullet.text()).append('\n'));
            prompt.narrativeLines().stream()
                    .filter(line -> sameSection(line.section(), section))
                    .forEach(line -> builder.append(line.text()).append('\n'));
        }
        return builder.toString();
    }

    private int retrievedDocumentCount(Map<String, Object> rag) {
        Object value = FinalPromptDisplayValues.firstPresent(rag,
                "retrievedDocumentCount",
                "authorizedDocumentCount",
                "allowedDocumentCount",
                "relatedDocumentCount",
                "documentCount");
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value == null) {
            return 0;
        }
        try {
            return Integer.parseInt(String.valueOf(value).trim());
        }
        catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private boolean asBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        return value != null && "true".equalsIgnoreCase(String.valueOf(value).trim());
    }

    private boolean containsIgnoreCase(String text, String term) {
        return StringUtils.hasText(text) && StringUtils.hasText(term)
                && text.toLowerCase(Locale.ROOT).contains(term.toLowerCase(Locale.ROOT));
    }

    private boolean sameSection(String actual, String expected) {
        return FinalPromptSnapshot.normalizeSection(actual)
                .equals(FinalPromptSnapshot.normalizeSection(expected));
    }

    private String preflightEvidence(FinalPromptEvidenceContext evidence) {
        if (evidence == null) {
            return "preflight=missing";
        }
        FinalPromptPreflightResult preflight = evidence.preflight();
        String ready = preflight == null ? "unknown" : String.valueOf(preflight.ready());
        String violations = preflight == null ? "unknown" : String.valueOf(preflight.violations().size());
        return "preflightReady=" + ready
                + ", violations=" + violations
                + ", promptHash=" + FinalPromptDisplayValues.presentText(evidence.promptHash(), messageResolver)
                + ", userPromptHash=" + FinalPromptDisplayValues.presentText(evidence.userPromptHash(), messageResolver);
    }

    private boolean placeholderConsistencyValue(String value) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        return !StringUtils.hasText(normalized)
                || normalized.equals("unknown")
                || normalized.equals("n/a")
                || normalized.equals("na")
                || normalized.equals("null")
                || normalized.equals("none")
                || normalized.equals("-")
                || normalized.equals("missing")
                || normalized.contains("missing")
                || normalized.contains("not available")
                || normalized.contains("unavailable")
                || normalized.equals("누락됨")
                || normalized.contains("누락")
                || normalized.equals("값 없음")
                || normalized.equals("없음")
                || normalized.contains("placeholder")
                || normalized.contains("to be populated");
    }

    private String normalizeComparableValue(String value) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (!normalized.startsWith("/") && normalized.matches("^[a-z][a-z0-9 ._-]*/[0-9].*")) {
            normalized = normalized.substring(0, normalized.indexOf('/'));
        }
        return normalized.replace("windows", "window").replaceAll("\\s+", " ");
    }

    private String normalizeBooleanComparable(String value) {
        String normalized = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
        if ("TRUE".equals(normalized) || "FALSE".equals(normalized)) {
            return normalized;
        }
        return "";
    }

    private String previewList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return "none";
        }
        List<String> clipped = values.stream()
                .filter(StringUtils::hasText)
                .limit(8)
                .map(FinalPromptDisplayValues::preview)
                .toList();
        int remaining = values.size() - clipped.size();
        return remaining > 0
                ? String.join(", ", clipped) + " and " + remaining + " more"
                : String.join(", ", clipped);
    }

    private static final class EvidenceCollector {
        private static final int MAX_ITEMS = 10;
        private final Set<String> values = new LinkedHashSet<>();

        void add(String value) {
            if (values.size() >= MAX_ITEMS || !StringUtils.hasText(value)) {
                return;
            }
            values.add(value.trim());
        }

        String summary() {
            if (values.isEmpty()) {
                return "";
            }
            return String.join("; ", values);
        }

        List<String> values() {
            return List.copyOf(values);
        }
    }

    private String stableCheckCode(String checkName) {
        String suffix = checkName == null ? "CHECK" : checkName.trim()
                .replaceAll("[^A-Za-z0-9]+", "_")
                .replaceAll("^_+|_+$", "")
                .toUpperCase(Locale.ROOT);
        return metricCode() + "_" + (suffix.isBlank() ? "CHECK" : suffix);
    }

    private static String normalizeMetric(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private static String normalizeCheckName(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private String message(String key, Object... args) {
        return messageResolver.resolve(key, args);
    }
}
