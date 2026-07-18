package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricCheckContract;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialMetricPurposeEvidence;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunCheckDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

final class OfficialRunMetricEvidenceMapper {

    private final OfficialRunMetricContractView metricContractView;
    private final OfficialRunDetailPresentation presentation;

    OfficialRunMetricEvidenceMapper(
            OfficialRunMetricContractView metricContractView,
            OfficialRunDetailPresentation presentation) {
        this.metricContractView = Objects.requireNonNull(metricContractView, "metricContractView");
        this.presentation = Objects.requireNonNull(presentation, "presentation");
    }

    Map<String, String> sealedEvidenceFacts(RuntimeEvidencePackageDetail sealedEvidence) {
        Map<String, String> facts = new LinkedHashMap<>();
        if (sealedEvidence == null) {
            return Map.of();
        }
        if (sealedEvidence.summary() != null) {
            putIfText(facts, "packageId", sealedEvidence.summary().packageId());
            putIfText(facts, "requestId", firstNonBlank(
                    objectText(sealedEvidence.requestFacts(), "requestId"), sealedEvidence.summary().correlationId()));
            putIfText(facts, "correlationId", sealedEvidence.summary().correlationId());
            putIfText(facts, "tenantId", sealedEvidence.summary().tenantId());
            putIfText(facts, "userId", sealedEvidence.summary().userId());
            putIfText(facts, "requestPath", sealedEvidence.summary().requestPath());
            putIfText(facts, "resourceId", sealedEvidence.summary().resourceId());
            putIfText(facts, "httpMethod", sealedEvidence.summary().httpMethod());
            putIfText(facts, "promptHash", sealedEvidence.summary().promptHash());
        }
        putIfText(facts, "authorizationEffect", objectText(sealedEvidence.authState(), "authorizationEffect"));
        putIfText(facts, "decisionAction", objectText(sealedEvidence.decision(), "action"));
        return Map.copyOf(facts);
    }

    Map<String, String> sealedEvidencePromptFacts(
            RuntimeEvidencePackageDetail sealedEvidence,
            OperatorSnapshot operatorSnapshot) {
        Map<String, String> facts = new LinkedHashMap<>();
        if (sealedEvidence != null && sealedEvidence.summary() != null) {
            putIfText(facts, "promptHash", sealedEvidence.summary().promptHash());
        }
        if (operatorSnapshot != null && operatorSnapshot.available()) {
            putIfText(facts, "promptHash", operatorSnapshot.batch().promptHash());
            putIfText(facts, "contextHash", operatorSnapshot.batch().contextHash());
            putIfText(facts, "contextHashState", operatorSnapshot.batch().contextHashState());
        }
        return Map.copyOf(facts);
    }

    void putIfObjectText(Map<String, Object> target, String key, String value) {
        if (target != null && StringUtils.hasText(key) && StringUtils.hasText(value)) {
            target.put(key, value.trim());
        }
    }

    OperatorMetricSnapshot operatorMetric(OperatorSnapshot snapshot, String metricCode) {
        if (snapshot == null || !snapshot.available()) {
            return null;
        }
        return snapshot.metrics().stream()
                .filter(Objects::nonNull)
                .filter(metric -> same(metric.metricCode(), metricCode))
                .findFirst()
                .orElse(null);
    }

    List<OfficialRunCheckDetail> checks(OfficialVerificationRunView run) {
        List<? extends OfficialVerificationCheckResultView> source = run.checks();
        if (source == null || source.isEmpty()) {
            return List.of();
        }
        List<OfficialRunCheckDetail> result = new ArrayList<>();
        for (int i = 0; i < source.size(); i++) {
            OfficialVerificationCheckResultView check = source.get(i);
            if (check == null || !check.customerVisible()
                    || "INTERNAL_REFERENCE".equals(normalize(check.readinessScope()))
                    || "NOT_APPLICABLE".equals(normalize(check.readinessScope()))
                    || "NOT_APPLICABLE".equals(normalize(check.purposeResult()))) {
                continue;
            }
            result.add(checkDetail(i + 1, run.endpointKey(), check));
        }
        return List.copyOf(result);
    }

    List<OfficialRunCheckDetail> customerVisibleChecks(
            String metricCode,
            List<OfficialRunCheckDetail> checks,
            List<OfficialMetricPurposeEvidence> purposeEvidence) {
        if (checks == null || checks.isEmpty() || purposeEvidence == null || purposeEvidence.isEmpty()) {
            return checks == null ? List.of() : checks;
        }
        String metric = normalize(metricCode);
        return checks.stream()
                .filter(Objects::nonNull)
                .filter(check -> visiblePurposeCheck(metric, check, purposeEvidence))
                .toList();
    }

    List<OfficialRunCheckDetail> mergePurposeEvidenceChecks(
            String metricCode,
            List<OfficialRunCheckDetail> checks,
            List<OfficialMetricPurposeEvidence> purposeEvidence) {
        List<OfficialRunCheckDetail> base = checks == null ? List.of() : checks;
        if (purposeEvidence == null || purposeEvidence.isEmpty()) {
            return base;
        }
        String metric = normalize(metricCode);
        List<OfficialRunCheckDetail> result = new ArrayList<>(base);
        Set<String> existing = result.stream()
                .filter(Objects::nonNull)
                .map(check -> normalize(stripMetricPrefix(metric, check.checkCode())))
                .filter(StringUtils::hasText)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        int sequence = result.size() + 1;
        for (OfficialMetricPurposeEvidence evidence : purposeEvidence) {
            if (evidence == null) {
                continue;
            }
            String checkCode = normalize(stripMetricPrefix(metric, evidence.checkCode()));
            if (StringUtils.hasText(checkCode) && !existing.contains(checkCode)) {
                result.add(purposeEvidenceCheck(sequence++, evidence));
                existing.add(checkCode);
            }
        }
        return List.copyOf(result);
    }

    private OfficialRunCheckDetail checkDetail(
            int sequence,
            String metricCode,
            OfficialVerificationCheckResultView check) {
        String evidenceSource = StringUtils.hasText(check.source()) ? check.source().trim() : "MISSING_SOURCE";
        FinalPromptMetricCheckContract contract = metricContractView.metricCheckContract(metricCode, check.checkCode());
        String label = firstNonBlank(contract == null ? null : contract.qualityQuestion(), check.label());
        String expected = firstNonBlank(contract == null ? null : contract.expectedMessage(), check.expectedValue());
        String actual = check.pass()
                ? firstNonBlank(contract == null ? null : contract.passMessage(), check.actualValue())
                : firstNonBlank(check.actualValue(), contract == null ? null : contract.failureMessage());
        String nextAction = firstNonBlank(contract == null ? null : contract.nextAction(), check.nextAction());
        String reverify = firstNonBlank(contract == null ? null : contract.reverifyCriterion(), check.reverifyCriterion());
        String whyItMatters = firstNonBlank(contract == null ? null : contract.whyItMatters(), check.whyItMatters());
        return new OfficialRunCheckDetail(
                sequence, check.checkCode(), label,
                OfficialRunDetailValueSanitizer.detailCheckText(expected),
                OfficialRunDetailValueSanitizer.detailCheckText(actual),
                check.pass(), evidenceSource, check.severity(),
                firstNonBlank(contract == null ? null : contract.failureType(), check.failureType()),
                firstNonBlank(contract == null ? null : contract.remediationOwner(), check.remediationOwner()),
                OfficialRunDetailValueSanitizer.detailCheckText(firstNonBlank(check.operatorReason(), actual)),
                nextAction, presentation.sourceMeaning(evidenceSource),
                firstNonBlank(nextAction, presentation.remediationHint(label, evidenceSource)),
                firstNonBlank(reverify, presentation.reverifyCriterion(label)),
                check.decisionUtility(), OfficialRunDetailValueSanitizer.detailCheckText(whyItMatters));
    }

    private boolean visiblePurposeCheck(
            String metric,
            OfficialRunCheckDetail check,
            List<OfficialMetricPurposeEvidence> purposeEvidence) {
        List<OfficialMetricPurposeEvidence> matched = purposeEvidence.stream()
                .filter(Objects::nonNull)
                .filter(evidence -> (!StringUtils.hasText(metric) || same(evidence.metricCode(), metric))
                        && metricCheckCodesMatch(metric, check.checkCode(), evidence.checkCode()))
                .toList();
        if (matched.isEmpty()) {
            return true;
        }
        return matched.stream().anyMatch(OfficialMetricPurposeEvidence::customerVisible)
                && matched.stream().noneMatch(evidence ->
                "INTERNAL_REFERENCE".equals(normalize(evidence.readinessScope()))
                        || "NOT_APPLICABLE".equals(normalize(evidence.readinessScope()))
                        || "NOT_APPLICABLE".equals(normalize(evidence.purposeResult())));
    }

    private OfficialRunCheckDetail purposeEvidenceCheck(int sequence, OfficialMetricPurposeEvidence evidence) {
        boolean passed = purposeEvidencePassed(evidence.purposeResult());
        FinalPromptMetricCheckContract contract = metricContractView.metricCheckContract(
                evidence.metricCode(), evidence.checkCode());
        String label = firstNonBlank(
                contract == null ? null : contract.qualityQuestion(), evidence.signalKey(), evidence.checkCode());
        String expected = firstNonBlank(contract == null ? null : contract.expectedMessage(), label);
        String actual = firstNonBlank(
                passed ? contract == null ? null : contract.passMessage()
                        : contract == null ? null : contract.failureMessage(),
                evidence.evidenceValue(), String.join(" ", evidence.runtimeFacts()));
        String source = firstNonBlank(evidence.promptLocation(), evidence.readinessScope(), "purposeEvidence");
        return new OfficialRunCheckDetail(
                sequence, evidence.checkCode(), label,
                OfficialRunDetailValueSanitizer.detailCheckText(expected),
                OfficialRunDetailValueSanitizer.detailCheckText(actual),
                passed, source,
                firstNonBlank(contract == null ? null : contract.severity(), passed ? "INFO" : "BLOCKING"),
                firstNonBlank(contract == null ? null : contract.failureType(), passed ? "" : "OFFICIAL_CHECK_FAILED"),
                firstNonBlank(contract == null ? null : contract.remediationOwner(), evidence.readinessScope(), "PQA_RUNTIME"),
                OfficialRunDetailValueSanitizer.detailCheckText(actual),
                firstNonBlank(contract == null ? null : contract.nextAction(), ""), "",
                firstNonBlank(contract == null ? null : contract.nextAction(), ""),
                firstNonBlank(contract == null ? null : contract.reverifyCriterion(), ""), "",
                OfficialRunDetailValueSanitizer.detailCheckText(firstNonBlank(
                        contract == null ? null : contract.whyItMatters(),
                        evidence.interpretation(), evidence.evidenceValue())));
    }

    private void putIfText(Map<String, String> target, String key, String value) {
        if (target != null && StringUtils.hasText(key) && StringUtils.hasText(value)) {
            target.put(key, value.trim());
        }
    }

    private String objectText(Map<String, Object> source, String key) {
        if (source == null || !StringUtils.hasText(key) || source.get(key) == null) {
            return null;
        }
        String text = String.valueOf(source.get(key)).trim();
        return StringUtils.hasText(text) ? text : null;
    }

    private boolean purposeEvidencePassed(String purposeResult) {
        String result = normalize(purposeResult);
        return "PURPOSE_PASSED".equals(result) || "PASSED".equals(result) || "PASS".equals(result);
    }

    private boolean metricCheckCodesMatch(String metricCode, String runCheckCode, String evidenceCheckCode) {
        String runCode = normalize(runCheckCode);
        String evidenceCode = normalize(evidenceCheckCode);
        if (!StringUtils.hasText(runCode) || !StringUtils.hasText(evidenceCode)) {
            return false;
        }
        return runCode.equals(evidenceCode)
                || StringUtils.hasText(normalize(metricCode))
                && stripMetricPrefix(metricCode, runCode).equals(stripMetricPrefix(metricCode, evidenceCode));
    }

    private String stripMetricPrefix(String metricCode, String checkCode) {
        String metric = normalize(metricCode);
        String code = normalize(checkCode);
        String prefix = metric + "_";
        return StringUtils.hasText(metric) && code.startsWith(prefix) ? code.substring(prefix.length()) : code;
    }

    private boolean same(String left, String right) {
        return StringUtils.hasText(left) && StringUtils.hasText(right) && left.trim().equalsIgnoreCase(right.trim());
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

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }
}