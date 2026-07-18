package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricCheckContract;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

final class OfficialVerificationMetricNarrative {

    private static final int TEXT_MAX = 1200;

    private final OfficialFinalPromptMetricContractRegistry contractRegistry;
    private final OfficialRuntimeEvidenceCheckInterpreter checkInterpreter;
    private final OfficialPromptEvidenceFormatter evidenceFormatter;

    OfficialVerificationMetricNarrative(
            OfficialFinalPromptMetricContractRegistry contractRegistry,
            OfficialRuntimeEvidenceCheckInterpreter checkInterpreter,
            OfficialPromptEvidenceFormatter evidenceFormatter) {
        this.contractRegistry = contractRegistry;
        this.checkInterpreter = checkInterpreter;
        this.evidenceFormatter = evidenceFormatter;
    }

    RuntimeEvidenceCheckResult firstFailedCheck(RuntimeEvidenceMetricResult metric) {
        return metric == null || metric.checks() == null ? null : metric.checks().stream()
                .filter(check -> check != null && !check.pass()).findFirst().orElse(null);
    }

    RuntimeEvidenceCheckResult firstNotApplicableCheck(RuntimeEvidenceMetricResult metric) {
        return metric == null || metric.checks() == null ? null : metric.checks().stream()
                .filter(OfficialVerificationMetricClassifier::snapshotNotApplicableCheck)
                .findFirst().orElse(null);
    }

    String notApplicableMessage(RuntimeEvidenceCheckResult check) {
        if (check == null) {
            return "";
        }
        FinalPromptMetricCheckContract contract = contract(check);
        String message = firstNonBlank(
                contract == null ? null : contract.notApplicableMessage(),
                check.operatorReason(), check.actualValue());
        if (StringUtils.hasText(message)) {
            return concise(message, TEXT_MAX);
        }
        throw contractError("Not applicable metric check is missing contract message.", check.metricCode(), check);
    }

    String notApplicableReverify(RuntimeEvidenceCheckResult check) {
        if (check == null) {
            return "";
        }
        FinalPromptMetricCheckContract contract = contract(check);
        String criterion = firstNonBlank(
                contract == null ? null : contract.reverifyCriterion(),
                check.reverifyCriterion(), notApplicableMessage(check));
        if (StringUtils.hasText(criterion)) {
            return concise(criterion, TEXT_MAX);
        }
        throw contractError(
                "Not applicable metric check is missing contract reverify criterion.", check.metricCode(), check);
    }

    String snapshotFailureReason(
            RuntimeEvidenceMetricResult metric,
            RuntimeEvidenceCheckResult check,
            boolean inputReview,
            boolean gateReview) {
        if (check == null) {
            return "";
        }
        String missing = joinedSignals(check, "missing:");
        if (inputReview && StringUtils.hasText(missing)) {
            return concise(message(
                    "enterprise.pqa.runtimeVerification.metricNarrative.inputMissing",
                    missing), TEXT_MAX);
        }
        if (gateReview && StringUtils.hasText(missing)) {
            return concise(message(
                    "enterprise.pqa.runtimeVerification.metricNarrative.gateMissing",
                    missing), TEXT_MAX);
        }
        String present = gateReview ? joinedSignals(check, "present:") : "";
        if (StringUtils.hasText(present)) {
            return concise(message(
                    "enterprise.pqa.runtimeVerification.metricNarrative.gatePresent",
                    present), TEXT_MAX);
        }
        if (StringUtils.hasText(check.operatorReason())) {
            return concise(check.operatorReason(), TEXT_MAX);
        }
        throw contractError("Metric failure is missing DB-backed operator reason.",
                metric == null ? null : metric.metricCode(), check);
    }

    String snapshotNextAction(
            String metricCode,
            RuntimeEvidenceCheckResult check,
            boolean inputReview,
            boolean gateReview) {
        String base = nextAction(metricCode, check);
        String missing = joinedSignals(check, "missing:");
        if (inputReview && StringUtils.hasText(missing)) {
            return concise(message(
                    "enterprise.pqa.runtimeVerification.metricNarrative.actionMissing",
                    base,
                    missing), TEXT_MAX);
        }
        if (gateReview && StringUtils.hasText(missing)) {
            return concise(message(
                    "enterprise.pqa.runtimeVerification.metricNarrative.actionReview",
                    base,
                    missing), TEXT_MAX);
        }
        return base;
    }

    String snapshotReverify(
            String metricCode,
            RuntimeEvidenceCheckResult check,
            boolean inputReview,
            boolean gateReview) {
        String base = reverifyCriterion(metricCode, check);
        String missing = joinedSignals(check, "missing:");
        return (inputReview || gateReview) && StringUtils.hasText(missing)
                ? concise(message(
                        "enterprise.pqa.runtimeVerification.metricNarrative.reverifyItems",
                        base,
                        missing), TEXT_MAX)
                : base;
    }

    String nextAction(String metricCode, RuntimeEvidenceCheckResult check) {
        FinalPromptMetricCheckContract contract = contract(metricCode, check);
        String action = firstNonBlank(contract == null ? null : contract.nextAction(),
                check == null ? null : check.nextAction());
        if (StringUtils.hasText(action)) {
            return concise(action, TEXT_MAX);
        }
        throw contractError("Metric check is missing contract next action.", metricCode, check);
    }

    String reverifyCriterion(String metricCode, RuntimeEvidenceCheckResult check) {
        FinalPromptMetricCheckContract contract = contract(metricCode, check);
        String criterion = firstNonBlank(contract == null ? null : contract.reverifyCriterion(),
                check == null ? null : check.reverifyCriterion());
        if (StringUtils.hasText(criterion)) {
            return concise(criterion, TEXT_MAX);
        }
        throw contractError("Metric check is missing contract reverify criterion.", metricCode, check);
    }

    String checkLabel(String metricCode, RuntimeEvidenceCheckResult check) {
        if (check != null && StringUtils.hasText(check.label())) {
            return check.label().trim();
        }
        throw contractError("Metric check is missing contract label.", metricCode, check);
    }

    boolean hasCustomerPromptQualityFailure(RuntimeEvidenceMetricResult metric) {
        return metric != null && metric.checks() != null && metric.checks().stream()
                .anyMatch(check -> OfficialVerificationMetricClassifier.customerPromptQualityCheck(check)
                        && !check.pass()
                        && !checkInterpreter.inputNotReady(check)
                        && "BLOCKING".equalsIgnoreCase(safe(check.severity())));
    }

    String ownerDisplayName(String owner) {
        String normalized = normalize(owner);
        if (!StringUtils.hasText(normalized)
                || normalized.contains("PQA_RUNTIME")
                || normalized.contains("OFFICIAL_VERIFICATION")) {
            return message("enterprise.pqa.officialNarrative.owner.official");
        }
        if (normalized.contains("PROMPT_ASSEMBLER")) {
            return message("enterprise.pqa.officialNarrative.owner.promptAssembler");
        }
        if (normalized.contains("REQUEST_CONTEXT")) {
            return message("enterprise.pqa.officialNarrative.owner.requestContext");
        }
        if (normalized.contains("AUTH_CONTEXT") || normalized.contains("AUTHORIZATION")) {
            return message("enterprise.pqa.officialNarrative.owner.authContext");
        }
        if (normalized.contains("CONTEXT_PRODUCER")) {
            return message("enterprise.pqa.officialNarrative.owner.contextProducer");
        }
        if (normalized.contains("CONTEXT_ASSEMBLER")) {
            return message("enterprise.pqa.officialNarrative.owner.contextAssembler");
        }
        if (normalized.contains("PROMPT_CAPTURE")) {
            return message("enterprise.pqa.officialNarrative.owner.promptCapture");
        }
        if (normalized.contains("PROMPT_HASH") || normalized.contains("TRACEABILITY")) {
            return message("enterprise.pqa.officialNarrative.owner.promptTraceability");
        }
        if (normalized.contains("PROMPT_TEMPLATE")) {
            return message("enterprise.pqa.officialNarrative.owner.promptTemplate");
        }
        if (normalized.contains("PROMPT_GOVERNANCE")) {
            return message("enterprise.pqa.officialNarrative.owner.promptGovernance");
        }
        if (normalized.contains("EVIDENCE")) {
            return message("enterprise.pqa.officialNarrative.owner.evidence");
        }
        if (normalized.contains("RAG")) {
            return message("enterprise.pqa.officialNarrative.owner.rag");
        }
        if (normalized.contains("LEARNING") || normalized.contains("BASELINE")) {
            return message("enterprise.pqa.officialNarrative.owner.learningBaseline");
        }
        if (normalized.contains("BEHAVIOR")) {
            return message("enterprise.pqa.officialNarrative.owner.behavior");
        }
        if (normalized.contains("PROTECTABLE")) {
            return message("enterprise.pqa.officialNarrative.owner.protectable");
        }
        if (normalized.contains("OFFICIAL_LEDGER")) {
            return message("enterprise.pqa.officialNarrative.owner.officialLedger");
        }
        return hasHangul(owner) && !OfficialPromptQualityNarrativeCatalog.containsBrokenText(owner)
                ? owner.trim()
                : message("enterprise.pqa.officialNarrative.owner.official");
    }

    private String joinedSignals(RuntimeEvidenceCheckResult check, String prefix) {
        return checkInterpreter.detectedSignals(check).stream()
                .filter(value -> value != null && value.startsWith(prefix))
                .map(value -> displaySignal(value.substring(prefix.length())))
                .filter(StringUtils::hasText).distinct().limit(6)
                .collect(Collectors.joining(", "));
    }

    private String displaySignal(String value) {
        String normalized = safe(value);
        for (String prefix : List.of("field:", "label:")) {
            if (normalized.startsWith(prefix)) {
                return normalized.substring(prefix.length());
            }
        }
        return normalized;
    }

    private FinalPromptMetricCheckContract contract(RuntimeEvidenceCheckResult check) {
        return contract(check == null ? null : check.metricCode(), check);
    }

    private FinalPromptMetricCheckContract contract(String metricCode, RuntimeEvidenceCheckResult check) {
        return check != null && StringUtils.hasText(check.purposeVersion()) && StringUtils.hasText(check.checkCode())
                ? contractRegistry.checkOrNull(metricCode, check) : null;
    }

    private String message(String key, Object... args) {
        return evidenceFormatter.message(key, args);
    }

    private String concise(String value, int maxLength) {
        if (!StringUtils.hasText(value)) {
            return value;
        }
        String cleaned = value.trim().replaceAll("\\s+", " ");
        return cleaned.length() <= maxLength ? cleaned : cleaned.substring(0, maxLength).trim();
    }

    private IllegalStateException contractError(
            String message,
            String metricCode,
            RuntimeEvidenceCheckResult check) {
        return new IllegalStateException("ENGINE_CONTRACT_ERROR: " + message
                + " metricCode=" + safe(metricCode)
                + ", checkCode=" + safe(check == null ? null : check.checkCode()));
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

    private boolean hasHangul(String value) {
        if (value == null) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            if (value.charAt(index) >= 0xAC00 && value.charAt(index) <= 0xD7A3) {
                return true;
            }
        }
        return false;
    }
}
