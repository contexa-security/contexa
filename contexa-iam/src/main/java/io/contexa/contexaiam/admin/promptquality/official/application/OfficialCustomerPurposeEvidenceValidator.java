package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricCheckContract;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

final class OfficialCustomerPurposeEvidenceValidator {

    static final String SEPARATOR = " || ";

    private final OfficialVerificationSnapshotQueryService queryService;
    private final OfficialPromptEvidenceFormatter evidenceFormatter;

    OfficialCustomerPurposeEvidenceValidator(
            OfficialVerificationSnapshotQueryService queryService,
            OfficialPromptEvidenceFormatter evidenceFormatter) {
        this.queryService = queryService;
        this.evidenceFormatter = evidenceFormatter;
    }

    void validate(
            CustomerPurposeEvidenceDisplay display,
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract) {
        validateIdentity(display, check);
        if (check == null || !StringUtils.hasText(check.purposeVersion())) {
            return;
        }
        validateRuntimeFacts(display, check, checkContract);
        validateContextItems(display, check);
    }

    void validate(CustomerPurposeEvidenceDisplay display, RuntimeEvidenceCheckResult check) {
        validate(display, check, null);
    }

    String signalKey(String signal, RuntimeEvidenceCheckResult check) {
        if (StringUtils.hasText(signal)) {
            String text = signal.trim();
            if (!evidenceFormatter.technicalText(text)) {
                return requireText(text, check, "purpose.signal_key");
            }
            List<String> fragments = evidenceFormatter.evidenceFragments(text);
            if (!fragments.isEmpty()) {
                return requireText(evidenceFormatter.joinFragments(fragments), check, "purpose.signal_key");
            }
        }
        String contractText = check == null ? "" : firstNonBlank(
                check.label(), check.expectedValue(), check.decisionUtility(), check.whyItMatters());
        if (StringUtils.hasText(contractText)) {
            return requireText(contractText, check, "purpose.signal_key");
        }
        throw contractError("Customer-visible purpose signal is not contract-backed.", check);
    }

    String evidenceValue(String rawValue, RuntimeEvidenceCheckResult check, String excludedText) {
        List<String> candidates = new ArrayList<>();
        List<String> fragments = evidenceFormatter.evidenceFragments(rawValue);
        if (!fragments.isEmpty()) {
            addUnique(candidates, evidenceFormatter.joinFragments(fragments));
        }
        if (StringUtils.hasText(rawValue) && !evidenceFormatter.technicalText(rawValue)) {
            addUnique(candidates, rawValue.trim());
        }
        if (check != null) {
            addUnique(candidates, check.decisionUtility());
            addUnique(candidates, check.operatorReason());
            addUnique(candidates, check.whyItMatters());
            addUnique(candidates, check.expectedValue());
            addUnique(candidates, check.actualValue());
            addUnique(candidates, check.label());
        }
        return firstValidEvidenceValue(candidates, check, excludedText);
    }

    String requireText(String candidate, RuntimeEvidenceCheckResult check, String ledgerField) {
        if (!StringUtils.hasText(candidate)) {
            throw ledgerError("Customer-visible purpose ledger text is blank.", ledgerField, check);
        }
        String text = normalizeVocabulary(candidate.trim());
        if (!evidenceFormatter.technicalText(text) && !containsRawSymbol(text)) {
            return text;
        }
        List<String> fragments = evidenceFormatter.evidenceFragments(text);
        String converted = evidenceFormatter.joinFragments(fragments);
        if (!fragments.isEmpty() && StringUtils.hasText(converted)
                && !evidenceFormatter.technicalText(converted) && !containsRawSymbol(converted)) {
            return converted;
        }
        throw ledgerError(
                "Customer-visible purpose ledger text still contains raw technical evidence.", ledgerField, check);
    }

    boolean sameText(String left, String right) {
        return StringUtils.hasText(left) && StringUtils.hasText(right)
                && normalizeText(left).equals(normalizeText(right));
    }

    boolean containsRawSymbol(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String text = value.trim();
        return text.contains("=") || text.contains("|") || text.contains("...")
                || text.contains(SEPARATOR) || evidenceFormatter.technicalText(text);
    }

    void addUnique(List<String> values, String value) {
        if (values == null || !StringUtils.hasText(value)) {
            return;
        }
        String trimmed = value.trim();
        String key = normalizeDisplayKey(trimmed);
        boolean exists = values.stream()
                .filter(StringUtils::hasText)
                .map(this::normalizeDisplayKey)
                .anyMatch(key::equals);
        if (!exists) {
            values.add(trimmed);
        }
    }

    private void validateIdentity(CustomerPurposeEvidenceDisplay display, RuntimeEvidenceCheckResult check) {
        String metricCode = safe(check == null ? null : check.metricCode());
        String checkCode = safe(check == null ? null : check.checkCode());
        if (display == null || !StringUtils.hasText(display.signalKey())
                || !StringUtils.hasText(display.evidenceValue())) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence is incomplete. "
                    + "metric=" + metricCode + ", check=" + checkCode);
        }
        if (display.signalKey().contains(SEPARATOR) || display.evidenceValue().contains(SEPARATOR)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence separator leaked into DB fields. "
                    + "metric=" + metricCode + ", check=" + checkCode);
        }
        if (containsRawSymbol(display.signalKey()) || containsRawSymbol(display.evidenceValue())) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence contains raw technical symbols. "
                    + "metric=" + metricCode + ", check=" + checkCode
                    + ", signalKey=" + safe(display.signalKey())
                    + ", evidenceValue=" + safe(display.evidenceValue()));
        }
        if (sameText(display.signalKey(), display.evidenceValue())) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence repeats the same text. "
                    + "metric=" + metricCode + ", check=" + checkCode + ", text=" + safe(display.signalKey()));
        }
    }

    private void validateRuntimeFacts(
            CustomerPurposeEvidenceDisplay display,
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract) {
        if (display.runtimeFacts().isEmpty()) {
            throw contractError("Customer-visible purpose evidence is missing runtime facts.", check);
        }
        for (String runtimeFact : display.runtimeFacts()) {
            boolean repeatsDisplay = display.structured()
                    && (sameText(runtimeFact, display.signalKey()) || sameText(runtimeFact, display.evidenceValue()));
            if (genericWrapper(runtimeFact) || repeatsDisplay || repeatsContractText(runtimeFact, checkContract)) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible runtime fact repeats display text. "
                        + checkIdentity(check) + ", runtimeFact=" + safe(runtimeFact));
            }
        }
    }

    private void validateContextItems(CustomerPurposeEvidenceDisplay display, RuntimeEvidenceCheckResult check) {
        if (display.contextItems().isEmpty()) {
            throw contractError("Customer-visible purpose evidence is missing context items.", check);
        }
        if (containsDuplicates(display.runtimeFacts())) {
            throw contractError("Customer-visible runtime facts contain duplicate display text.", check);
        }
        if (containsDuplicates(display.contextItems())) {
            throw contractError("Customer-visible context items contain duplicate display text.", check);
        }
        for (String contextItem : display.contextItems()) {
            if (StringUtils.hasText(contextItem) && !queryService.contractedPromptSignal(contextItem)) {
                throw new IllegalStateException(
                        "ENGINE_CONTRACT_ERROR: Customer-visible context item is not a prompt field. "
                                + checkIdentity(check) + ", contextItem=" + safe(contextItem));
            }
        }
    }

    private boolean repeatsContractText(String runtimeFact, FinalPromptMetricCheckContract contract) {
        if (!StringUtils.hasText(runtimeFact) || contract == null) {
            return false;
        }
        return Stream.of(
                        contract.expectedMessage(), contract.passMessage(), contract.failureMessage(),
                        contract.problemTitle(), contract.shortProblem(), contract.qualityQuestion(),
                        contract.whyItMatters(), contract.meaning(), contract.securityRelevance(),
                        contract.interpretationLink())
                .anyMatch(text -> sameText(runtimeFact, text));
    }

    private String firstValidEvidenceValue(
            List<String> candidates,
            RuntimeEvidenceCheckResult check,
            String excludedText) {
        for (String candidate : candidates) {
            if (StringUtils.hasText(candidate)
                    && !sameText(candidate, excludedText)
                    && !evidenceFormatter.technicalText(candidate)) {
                return requireText(candidate.trim(), check, "purpose.evidence_value");
            }
        }
        throw contractError("Customer-visible purpose evidence is not contract-backed.", check);
    }

    private boolean containsDuplicates(List<String> values) {
        Set<String> seen = new LinkedHashSet<>();
        for (String value : values == null ? List.<String>of() : values) {
            if (StringUtils.hasText(value) && !seen.add(normalizeDisplayKey(value))) {
                return true;
            }
        }
        return false;
    }

    private boolean genericWrapper(String value) {
        return StringUtils.hasText(value)
                && (value.contains("실제 프롬프트에서 확인된 값은")
                || value.contains("검사 대상 항목은")
                || value.contains("검사 대상 컨텍스트 항목은"));
    }

    private String normalizeVocabulary(String value) {
        return value.trim()
                .replace("NO_DIRECT_PERSONAL_COMPARABLE", "no direct personal comparable history")
                .replace("NO_COMPARABLE", "no comparable history")
                .replace("ZERO_RESULTS_NO_DOCUMENTS", "no retrieved documents")
                .replace("NO_RAG_CONTEXT", "no RAG context")
                .replace("SEARCH_NOT_EXECUTED", "search not executed")
                .replace("ObjectiveAlignmentEvidence: UNKNOWN", "ObjectiveAlignmentEvidence state is unknown")
                .replace("Delegated: UNKNOWN", "Delegated state is unknown")
                .replace("confirmed context items:", "context items:");
    }

    private String normalizeDisplayKey(String value) {
        return !StringUtils.hasText(value) ? "" : value.trim()
                .replaceAll("[\\s\\x{00A0}]+", " ")
                .replaceAll("[.!?]+$", "")
                .toLowerCase(Locale.ROOT);
    }

    private String normalizeText(String value) {
        return value.trim().replaceAll("\\s+", " ")
                .replaceAll("[.!?]+$", "").toLowerCase(Locale.ROOT);
    }

    private IllegalStateException contractError(String message, RuntimeEvidenceCheckResult check) {
        return new IllegalStateException("ENGINE_CONTRACT_ERROR: " + message + " " + checkIdentity(check));
    }

    private IllegalStateException ledgerError(
            String message,
            String ledgerField,
            RuntimeEvidenceCheckResult check) {
        return new IllegalStateException(
                "ENGINE_CONTRACT_ERROR: " + message + " field=" + ledgerField + ", " + checkIdentity(check));
    }

    private String checkIdentity(RuntimeEvidenceCheckResult check) {
        return "metric=" + safe(check == null ? null : check.metricCode())
                + ", check=" + safe(check == null ? null : check.checkCode());
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
