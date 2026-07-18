package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricCheckContract;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

final class OfficialMetricPurposeNarrative {

    private final OfficialPromptEvidenceFormatter evidenceFormatter;
    private final OfficialCustomerPurposeEvidenceParser evidenceParser;
    private final OfficialCustomerPurposeEvidenceValidator evidenceValidator;
    private final OfficialRuntimeEvidenceCheckInterpreter checkInterpreter;
    private final CustomerDisplayPayloadFactory payloadFactory = new CustomerDisplayPayloadFactory();

    OfficialMetricPurposeNarrative(
            OfficialPromptEvidenceFormatter evidenceFormatter,
            OfficialCustomerPurposeEvidenceParser evidenceParser,
            OfficialCustomerPurposeEvidenceValidator evidenceValidator,
            OfficialRuntimeEvidenceCheckInterpreter checkInterpreter) {
        this.evidenceFormatter = evidenceFormatter;
        this.evidenceParser = evidenceParser;
        this.evidenceValidator = evidenceValidator;
        this.checkInterpreter = checkInterpreter;
    }

    String actualProblemState(
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract contract) {
        if (check != null && StringUtils.hasText(check.purposeVersion())) {
            return customerDisplayPayload(check, contract).evidenceText();
        }
        String concrete = evidenceFormatter.concreteDetectedSignalSummary(check);
        if (StringUtils.hasText(concrete)) {
            return evidenceValidator.requireText(evidenceFormatter.displayValue(concrete), check, "purpose.actual_value");
        }
        if (check != null && StringUtils.hasText(check.actualValue())) {
            return evidenceValidator.requireText(check.actualValue().trim(), check, "purpose.actual_value");
        }
        return contract == null ? "" : contract.failureMessage();
    }

    String actualValue(
            RuntimeEvidenceCheckResult check,
            boolean customerVisible,
            FinalPromptMetricCheckContract contract) {
        if (!customerVisible) {
            return evidenceFormatter.concreteMetricActualValue(check);
        }
        if (check == null || !StringUtils.hasText(check.purposeVersion())) {
            return legacyActualValue(check);
        }
        return customerDisplayPayload(check, contract).evidenceText();
    }

    String expectedValue(
            RuntimeEvidenceCheckResult check,
            boolean customerVisible,
            FinalPromptMetricCheckContract contract) {
        if (!customerVisible) {
            return check == null ? "" : check.expectedValue();
        }
        if (contract != null && StringUtils.hasText(contract.expectedMessage())) {
            return evidenceValidator.requireText(contract.expectedMessage(), check, "purpose.expected_value");
        }
        if (check == null || !StringUtils.hasText(check.purposeVersion())) {
            return legacyExpectedValue(check);
        }
        throw contractError("Customer-visible purpose check has no contract expected message.", check);
    }

    String decisionUtility(
            RuntimeEvidenceCheckResult check,
            boolean customerVisible,
            FinalPromptMetricCheckContract contract) {
        String utility = check == null ? "" : check.decisionUtility();
        if (!customerVisible) {
            return utility;
        }
        if (contract != null && StringUtils.hasText(contract.whyItMatters())) {
            return evidenceValidator.requireText(contract.whyItMatters(), check, "purpose.decision_utility");
        }
        if (check == null || !StringUtils.hasText(check.purposeVersion())) {
            String legacy = firstNonBlank(
                    utility, check == null ? null : check.whyItMatters(),
                    check == null ? null : check.operatorReason(), check == null ? null : check.expectedValue(),
                    check == null ? null : check.label());
            return evidenceValidator.requireText(
                    evidenceFormatter.displayValue(legacy), check, "purpose.decision_utility");
        }
        throw contractError("Customer-visible purpose check has no contract decision utility.", check);
    }

    CustomerDisplayPayloadFactory.Payload customerDisplayPayload(
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract contract) {
        if (check == null) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload requires a metric check.");
        }
        List<CustomerPurposeEvidenceDisplay> displays = evidenceDisplays(check, contract);
        String title = displays.stream()
                .map(CustomerPurposeEvidenceDisplay::signalKey)
                .filter(StringUtils::hasText)
                .findFirst()
                .orElseGet(() -> evidenceValidator.requireText(firstNonBlank(
                                contract == null ? null : contract.problemTitle(),
                                contract == null ? null : contract.passMessage(),
                                check.label(), check.expectedValue()),
                        check, "customer_display.title"));
        String evidenceText = joinedText(
                displays.stream().map(CustomerPurposeEvidenceDisplay::evidenceValue).toList(),
                check, "purpose.actual_value");
        String purposeResult = checkInterpreter.purposeResult(check);
        String resolutionAction = "";
        String reverifyCondition = "";
        if (!"PURPOSE_PASSED".equals(purposeResult) && !"NOT_APPLICABLE".equals(purposeResult)) {
            resolutionAction = evidenceValidator.requireText(
                    firstNonBlank(contract == null ? null : contract.nextAction(), check.nextAction()),
                    check, "purpose.next_action");
            reverifyCondition = evidenceValidator.requireText(
                    firstNonBlank(contract == null ? null : contract.reverifyCriterion(), check.reverifyCriterion()),
                    check, "purpose.reverify_criterion");
        }
        return payloadFactory.create(new CustomerDisplayPayloadFactory.Request(
                title,
                displays.stream().map(display -> new CustomerDisplayPayloadFactory.EvidenceDisplay(
                        display.signalKey(), display.evidenceValue())).toList(),
                evidenceValidator.requireText(firstNonBlank(
                        contract == null ? null : contract.whyItMatters(), check.whyItMatters(), title),
                        check, "customer_display.why_it_matters"),
                resolutionAction, reverifyCondition, purposeResult));
    }

    String nextAction(
            RuntimeEvidenceCheckResult check,
            boolean customerVisible,
            FinalPromptMetricCheckContract contract) {
        if (!customerVisible) {
            return check == null ? "" : check.nextAction();
        }
        String result = checkInterpreter.purposeResult(check);
        if ("PURPOSE_PASSED".equals(result) || "NOT_APPLICABLE".equals(result)) {
            return "";
        }
        if (check == null || !StringUtils.hasText(check.purposeVersion())) {
            if (contract != null && StringUtils.hasText(contract.nextAction())) {
                return evidenceValidator.requireText(contract.nextAction(), check, "purpose.next_action");
            }
            throw contractError("Customer-visible purpose check has no contract next action.", check);
        }
        return customerDisplayPayload(check, contract).resolutionAction();
    }

    String reverifyCriterion(
            RuntimeEvidenceCheckResult check,
            boolean customerVisible,
            FinalPromptMetricCheckContract contract) {
        if (!customerVisible) {
            return check == null ? "" : check.reverifyCriterion();
        }
        String result = checkInterpreter.purposeResult(check);
        if ("PURPOSE_PASSED".equals(result) || "NOT_APPLICABLE".equals(result)) {
            return "";
        }
        if (check == null || !StringUtils.hasText(check.purposeVersion())) {
            if (contract != null && StringUtils.hasText(contract.reverifyCriterion())) {
                return evidenceValidator.requireText(
                        contract.reverifyCriterion(), check, "purpose.reverify_criterion");
            }
            throw contractError("Customer-visible purpose check has no contract reverify criterion.", check);
        }
        return customerDisplayPayload(check, contract).reverifyCondition();
    }

    private String legacyExpectedValue(RuntimeEvidenceCheckResult check) {
        String text = stripPrefix(firstNonBlank(
                check == null ? null : check.expectedValue(), check == null ? null : check.decisionUtility(),
                check == null ? null : check.whyItMatters(), check == null ? null : check.label()));
        return !StringUtils.hasText(text) ? "" : evidenceValidator.requireText(
                evidenceFormatter.displayValue(text), check, "purpose.expected_value");
    }

    private String legacyActualValue(RuntimeEvidenceCheckResult check) {
        List<CustomerPurposeEvidenceDisplay> displays = evidenceDisplays(check, null);
        if (!displays.isEmpty()) {
            return joinedText(displays.stream().map(CustomerPurposeEvidenceDisplay::evidenceValue).toList(),
                    check, "purpose.actual_value");
        }
        String concrete = evidenceFormatter.concreteDetectedSignalSummary(
                evidenceParser.visibleSignals(checkInterpreter.detectedSignals(check), check, true));
        if (StringUtils.hasText(concrete)) {
            return evidenceValidator.requireText(
                    evidenceFormatter.displayValue(concrete), check, "purpose.actual_value");
        }
        List<String> fragments = evidenceFormatter.evidenceFragments(check == null ? "" : check.actualValue());
        if (!fragments.isEmpty()) {
            return evidenceValidator.requireText(
                    evidenceFormatter.message(
                            "enterprise.pqa.runtimeVerification.customerPurpose.evidenceSentence",
                            evidenceFormatter.joinFragments(fragments)),
                    check, "purpose.actual_value");
        }
        String fallback = firstNonBlank(
                check == null ? null : check.actualValue(), check == null ? null : check.operatorReason(),
                check == null ? null : check.expectedValue(), check == null ? null : check.decisionUtility(),
                check == null ? null : check.whyItMatters());
        if (StringUtils.hasText(fallback) && !evidenceFormatter.technicalText(fallback)) {
            return evidenceValidator.requireText(fallback, check, "purpose.actual_value");
        }
        throw contractError("Customer-visible purpose actual value is not contract-backed.", check);
    }

    private List<CustomerPurposeEvidenceDisplay> evidenceDisplays(
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract contract) {
        if (check == null) {
            return List.of();
        }
        List<String> signals = evidenceParser.visibleSignals(checkInterpreter.detectedSignals(check), check, true);
        if (signals.isEmpty() && StringUtils.hasText(check.purposeVersion())) {
            throw contractError("Customer-visible metric purpose evidence is missing.", check);
        }
        List<CustomerPurposeEvidenceDisplay> displays = new ArrayList<>();
        for (String signal : signals) {
            CustomerPurposeEvidenceDisplay display = evidenceParser.display(signal, check, contract);
            if (display != null) {
                evidenceValidator.validate(display, check, contract);
                displays.add(display);
            }
        }
        if (displays.isEmpty() && StringUtils.hasText(check.purposeVersion())) {
            throw contractError("Customer-visible metric purpose evidence did not produce display payload.", check);
        }
        return List.copyOf(displays);
    }

    private String joinedText(
            List<String> values,
            RuntimeEvidenceCheckResult check,
            String ledgerField) {
        List<String> cleaned = new ArrayList<>();
        for (String value : values == null ? List.<String>of() : values) {
            if (StringUtils.hasText(value)) {
                evidenceValidator.addUnique(cleaned, evidenceValidator.requireText(value, check, ledgerField));
            }
        }
        if (cleaned.isEmpty()) {
            throw contractError("Customer display payload has no customer evidence text. field=" + ledgerField, check);
        }
        return evidenceValidator.requireText(String.join(" ", cleaned), check, ledgerField);
    }

    private String stripPrefix(String value) {
        String text = safe(value);
        for (String prefix : List.of("문제:", "확인된 값:", "해결 방안:", "재검증 기준:")) {
            if (text.startsWith(prefix)) {
                return text.substring(prefix.length()).trim();
            }
        }
        return text;
    }

    private IllegalStateException contractError(String message, RuntimeEvidenceCheckResult check) {
        return new IllegalStateException("ENGINE_CONTRACT_ERROR: " + message
                + " metric=" + safe(check == null ? null : check.metricCode())
                + ", check=" + safe(check == null ? null : check.checkCode())
                + ", purposeVersion=" + safe(check == null ? null : check.purposeVersion()));
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
