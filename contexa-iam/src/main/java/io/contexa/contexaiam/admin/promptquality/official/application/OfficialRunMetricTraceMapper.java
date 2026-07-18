package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexacore.verification.runtime.OfficialVerificationEventItemView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialMetricPurposeEvidence;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunCheckDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunEventDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

final class OfficialRunMetricTraceMapper {

    private final OfficialRunMetricContractView contractView;
    private final OfficialRunMetricEvidenceMapper evidenceMapper;
    private final OfficialRunMetricSummaryCalculator summaryCalculator;
    private final OfficialRunOperatorSnapshotMapper operatorSnapshotMapper;
    private final OfficialRunDetailPresentation presentation;

    OfficialRunMetricTraceMapper(
            OfficialRunMetricContractView contractView,
            OfficialRunMetricEvidenceMapper evidenceMapper,
            OfficialRunMetricSummaryCalculator summaryCalculator,
            OfficialRunOperatorSnapshotMapper operatorSnapshotMapper,
            OfficialRunDetailPresentation presentation) {
        this.contractView = Objects.requireNonNull(contractView, "contractView");
        this.evidenceMapper = Objects.requireNonNull(evidenceMapper, "evidenceMapper");
        this.summaryCalculator = Objects.requireNonNull(summaryCalculator, "summaryCalculator");
        this.operatorSnapshotMapper = Objects.requireNonNull(operatorSnapshotMapper, "operatorSnapshotMapper");
        this.presentation = Objects.requireNonNull(presentation, "presentation");
    }

    OfficialVerificationMetricTrace toMetricDetail(
            OfficialVerificationRunView run,
            RuntimeEvidencePackageDetail sealedEvidence,
            OperatorSnapshot operatorSnapshot) {
        OfficialVerificationMetricDefinition metric = contractView.metric(run.endpointKey());
        OperatorMetricSnapshot storedMetric = evidenceMapper.operatorMetric(operatorSnapshot, run.endpointKey());
        List<OfficialMetricPurposeEvidence> purposeEvidence = contractView.purposeEvidenceForMetric(
                operatorSnapshot, run.endpointKey());
        List<OfficialRunCheckDetail> checks = evidenceMapper.customerVisibleChecks(
                run.endpointKey(),
                evidenceMapper.mergePurposeEvidenceChecks(
                        run.endpointKey(), evidenceMapper.checks(run), purposeEvidence),
                purposeEvidence);
        int totalChecks = summaryCalculator.detailTotalChecks(
                checks,
                run.checks() != null && !run.checks().isEmpty()
                        ? checks.size()
                        : storedMetric == null ? run.totalChecks() : storedMetric.totalChecks());
        int passedChecks = summaryCalculator.detailPassedChecks(
                checks,
                run.checks() != null && !run.checks().isEmpty()
                        ? (int) checks.stream().filter(OfficialRunCheckDetail::pass).count()
                        : storedMetric == null ? run.passedChecks() : storedMetric.passedChecks());
        List<OfficialRunFailureCause> operatorFailures = operatorSnapshotMapper.failureCauses(operatorSnapshot).stream()
                .filter(cause -> same(cause.metricCode(), run.endpointKey()))
                .toList();
        List<OfficialRunFailureCause> checkFailures = checks.stream()
                .filter(check -> !check.pass())
                .map(check -> failure(run, metric, check))
                .toList();
        List<OfficialRunFailureCause> failures = operatorFailures.isEmpty() ? checkFailures : operatorFailures;
        return new OfficialVerificationMetricTrace(
                normalize(run.endpointKey()),
                metric == null ? run.endpointKey() : metric.metricName(),
                presentation.groupName(metric == null ? null : metric.category()),
                contractView.metricPurpose(run.endpointKey()),
                contractView.metricQualityQuestion(run.endpointKey()),
                firstNonBlank(storedMetric == null ? null : storedMetric.officialRunId(), run.runId()),
                run.requestId(), run.endpointLabel(),
                firstNonBlank(storedMetric == null ? null : storedMetric.state(), run.state()),
                presentation.stateLabel(firstNonBlank(storedMetric == null ? null : storedMetric.state(), run.state())),
                storedMetric == null ? run.score() : storedMetric.score(),
                passedChecks, totalChecks, run.processingTimeMs(), run.startedAt(), run.completedAt(), checks,
                safeMap(run.requestFacts()), safeMap(run.eventFacts()),
                OfficialRunDetailValueSanitizer.detailStringMap(run.promptFacts()), safeMap(run.analysisFacts()),
                events(run), OfficialRunDetailValueSanitizer.limitedObjectMap(run.rawEvidence()), List.of(),
                summaryCalculator.actualPromptProblemsForMetric(operatorSnapshot, run.endpointKey()),
                failures, purposeEvidence,
                valueOrEmpty(storedMetric == null ? null : storedMetric.operatorTitle()),
                valueOrEmpty(storedMetric == null ? null : storedMetric.operatorSummary()),
                valueOrEmpty(storedMetric == null ? null : storedMetric.primaryFailureReason()),
                valueOrEmpty(storedMetric == null ? null : storedMetric.remediationOwner()),
                valueOrEmpty(storedMetric == null ? null : storedMetric.nextAction()),
                valueOrEmpty(storedMetric == null ? null : storedMetric.reverifyCriterion()));
    }

    OfficialVerificationMetricTrace toMetricDetail(
            OperatorMetricSnapshot storedMetric,
            RuntimeEvidencePackageDetail sealedEvidence,
            OperatorSnapshot operatorSnapshot) {
        String metricCode = normalize(storedMetric.metricCode());
        OfficialVerificationMetricDefinition metric = contractView.metric(metricCode);
        List<OfficialMetricPurposeEvidence> purposeEvidence = contractView.purposeEvidenceForMetric(operatorSnapshot, metricCode);
        List<OfficialRunCheckDetail> checks = evidenceMapper.mergePurposeEvidenceChecks(metricCode, List.of(), purposeEvidence);
        List<OfficialRunFailureCause> failures = operatorSnapshotMapper.failureCauses(operatorSnapshot).stream()
                .filter(cause -> same(cause.metricCode(), metricCode))
                .toList();
        Map<String, String> requestFacts = evidenceMapper.sealedEvidenceFacts(sealedEvidence);
        Map<String, Object> rawEvidence = rawEvidence(operatorSnapshot);
        return new OfficialVerificationMetricTrace(
                metricCode,
                firstNonBlank(storedMetric.metricName(), metric == null ? metricCode : metric.metricName()),
                firstNonBlank(storedMetric.metricGroup(), presentation.groupName(metric == null ? null : metric.category())),
                contractView.metricPurpose(metricCode), contractView.metricQualityQuestion(metricCode),
                storedMetric.officialRunId(), requestFacts.get("requestId"),
                firstNonBlank(
                        operatorSnapshot != null && operatorSnapshot.available()
                                ? operatorSnapshot.batch().actualRequestPath() : null,
                        sealedEvidence == null || sealedEvidence.summary() == null
                                ? null : sealedEvidence.summary().requestPath()),
                storedMetric.state(), presentation.stateLabel(storedMetric.state()), storedMetric.score(),
                summaryCalculator.detailPassedChecks(checks, storedMetric.passedChecks()),
                summaryCalculator.detailTotalChecks(checks, storedMetric.totalChecks()),
                null,
                storedMetric.createdAt() == null ? null : storedMetric.createdAt().toString(),
                storedMetric.createdAt() == null ? null : storedMetric.createdAt().toString(),
                checks, requestFacts, Map.of(), evidenceMapper.sealedEvidencePromptFacts(sealedEvidence, operatorSnapshot),
                Map.of("sourceMode", "OFFICIAL_OPERATOR_SNAPSHOT", "metricCode", metricCode),
                List.of(), Map.copyOf(rawEvidence), List.of(),
                summaryCalculator.actualPromptProblemsForMetric(operatorSnapshot, metricCode),
                failures, purposeEvidence,
                valueOrEmpty(storedMetric.operatorTitle()), valueOrEmpty(storedMetric.operatorSummary()),
                valueOrEmpty(storedMetric.primaryFailureReason()), valueOrEmpty(storedMetric.remediationOwner()),
                valueOrEmpty(storedMetric.nextAction()), valueOrEmpty(storedMetric.reverifyCriterion()));
    }

    private Map<String, Object> rawEvidence(OperatorSnapshot operatorSnapshot) {
        Map<String, Object> rawEvidence = new LinkedHashMap<>();
        if (operatorSnapshot != null && operatorSnapshot.available()) {
            evidenceMapper.putIfObjectText(rawEvidence, "aggregateRunId", operatorSnapshot.batch().aggregateRunId());
            evidenceMapper.putIfObjectText(rawEvidence, "packageId", operatorSnapshot.batch().packageId());
            evidenceMapper.putIfObjectText(rawEvidence, "promptHash", operatorSnapshot.batch().promptHash());
            evidenceMapper.putIfObjectText(rawEvidence, "contextHash", operatorSnapshot.batch().contextHash());
            evidenceMapper.putIfObjectText(rawEvidence, "actualRequestPath", operatorSnapshot.batch().actualRequestPath());
            evidenceMapper.putIfObjectText(rawEvidence, "actualResourceId", operatorSnapshot.batch().actualResourceId());
            evidenceMapper.putIfObjectText(rawEvidence, "httpMethod", operatorSnapshot.batch().httpMethod());
        }
        return rawEvidence;
    }

    private List<OfficialRunEventDetail> events(OfficialVerificationRunView run) {
        List<? extends OfficialVerificationEventItemView> source = run.events();
        if (source == null || source.isEmpty()) {
            return List.of();
        }
        List<OfficialRunEventDetail> result = new ArrayList<>();
        for (int i = 0; i < source.size(); i++) {
            OfficialVerificationEventItemView event = source.get(i);
            result.add(new OfficialRunEventDetail(i + 1, event.type(), event.layer(), event.status(), event.requestPath()));
        }
        return List.copyOf(result);
    }

    private OfficialRunFailureCause failure(
            OfficialVerificationRunView run,
            OfficialVerificationMetricDefinition metric,
            OfficialRunCheckDetail check) {
        return new OfficialRunFailureCause(
                normalize(run.endpointKey()), metric == null ? run.endpointKey() : metric.metricName(), run.runId(),
                check.checkCode(), check.label(), check.expectedValue(), check.actualValue(), check.source(),
                check.remediationOwner(), check.label(), presentation.rootCause(check), check.remediationOwner(),
                firstNonBlank(check.operatorReason(), presentation.rootCause(check)),
                check.remediationHint(), check.reverifyCriterion());
    }

    private Map<String, String> safeMap(Map<String, String> raw) {
        return raw == null ? Map.of() : Map.copyOf(raw);
    }

    private boolean same(String left, String right) {
        return StringUtils.hasText(left) && StringUtils.hasText(right) && left.trim().equalsIgnoreCase(right.trim());
    }

    private String valueOrEmpty(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
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