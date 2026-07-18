package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.metric.OfficialContextHashStateResolver;
import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContract;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class OfficialVerificationMetricOutputRecorder {

    private final ObjectMapper objectMapper;
    private final OfficialVerificationSnapshotCommandWriters writers;
    private final OfficialVerificationMetricNarrative metricNarrative;
    private final OfficialActualPromptProblemNarrative problemNarrative;
    private final OfficialVerificationCustomerTextPolicy customerText;
    private final OfficialRuntimeEvidenceCheckInterpreter checkInterpreter;
    private final OfficialPromptExecutionMetadataReader metadataReader;
    private final OfficialFinalPromptMetricContractRegistry contractRegistry;
    private final OfficialPromptQualityNarrativeCatalog narrativeCatalog = new OfficialPromptQualityNarrativeCatalog();

    OfficialVerificationMetricOutputRecorder(
            ObjectMapper objectMapper,
            OfficialVerificationSnapshotCommandWriters writers,
            OfficialVerificationMetricNarrative metricNarrative,
            OfficialActualPromptProblemNarrative problemNarrative,
            OfficialVerificationCustomerTextPolicy customerText,
            OfficialRuntimeEvidenceCheckInterpreter checkInterpreter,
            OfficialPromptExecutionMetadataReader metadataReader,
            OfficialFinalPromptMetricContractRegistry contractRegistry) {
        this.objectMapper = objectMapper;
        this.writers = writers;
        this.metricNarrative = metricNarrative;
        this.problemNarrative = problemNarrative;
        this.customerText = customerText;
        this.checkInterpreter = checkInterpreter;
        this.metadataReader = metadataReader;
        this.contractRegistry = contractRegistry;
    }

    void recordBatch(
            String aggregateRunId,
            SealedEvidencePackage evidence,
            String requestPath,
            String resourceId,
            String httpMethod,
            String promptHash,
            String contextHash,
            String certificateId,
            String caseId,
            List<RuntimeEvidenceMetricResult> metrics,
            Map<String, List<OfficialActualPromptProblem>> problemsByMetric) {
        OfficialVerificationRunBatchWriter.MetricCounts counts = metricCounts(metrics, problemsByMetric);
        boolean blocked = counts.failed() > 0 || counts.insufficient() > 0 || counts.total() <= 0;
        Map<String, Object> requestFacts = jsonMap(evidence.getRequestFactsJson());
        Map<String, Object> promptMetadata = metadataReader.read(evidence.getPromptExecutionMetadataJson());
        OfficialContextHashStateResolver.Resolution contextResolution = OfficialContextHashStateResolver.resolve(
                requestFacts, promptMetadata, evidence.getCanonicalContextJson());
        OfficialVerificationRunBatchWriter.EvidenceIdentity identity =
                new OfficialVerificationRunBatchWriter.EvidenceIdentity(
                        promptHash, firstNonBlank(contextHash, contextResolution.contextHash()),
                        contextResolution.state(), requestFact(evidence, "protectableResourceId"), resourceId,
                        requestFact(evidence, "protectableResourceUrl"), requestPath, httpMethod);
        writers.runBatch().insert(new OfficialVerificationRunBatchWriter.RunBatchCommand(
                aggregateRunId, evidence.getPackageId(), evidence.getTenantId(), certificateId, caseId,
                counts, blocked ? "BLOCKED" : "CERTIFIABLE", blocked,
                blockReasonSummary(metrics, problemsByMetric), identity));
    }

    void recordMetric(
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            RuntimeEvidenceMetricResult metric,
            List<OfficialActualPromptProblem> metricProblems) {
        List<OfficialActualPromptProblem> problems = safeList(metricProblems);
        MetricSituation situation = metricSituation(metric, problems);
        MetricNarrative narrative = metricSnapshotNarrative(metric, situation);
        List<String> problemIds = problems.stream()
                .map(OfficialActualPromptProblem::problemId).filter(StringUtils::hasText).distinct().toList();
        writers.metricSnapshot().insert(new OfficialVerificationMetricSnapshotWriter.MetricSnapshotCommand(
                new OfficialVerificationMetricSnapshotWriter.MetricIdentity(
                        aggregateRunId, safe(metric.officialRunId()), packageId, certificateId, caseId,
                        situation.metricCode(), situation.metricName(), safe(metric.groupName())),
                new OfficialVerificationMetricSnapshotWriter.MetricAssessment(
                        metric.score(), situation.state(), situation.severity(),
                        OfficialVerificationMetricClassifier.snapshotPassedCheckCount(metric),
                        OfficialVerificationMetricClassifier.snapshotTotalCheckCount(metric),
                        OfficialVerificationMetricClassifier.snapshotFailedCheckCount(metric)),
                new OfficialVerificationMetricSnapshotWriter.OperatorNarrative(
                        customerText.require("metricSnapshot.operatorTitle", narrative.title()),
                        customerText.require("metricSnapshot.operatorSummary", narrative.summary()),
                        customerText.optional("metricSnapshot.primaryFailureReason", narrative.failureReason()),
                        customerText.require("metricSnapshot.remediationOwner", narrative.owner()),
                        customerText.require("metricSnapshot.nextAction", narrative.nextAction()),
                        customerText.require("metricSnapshot.reverifyCriterion", narrative.reverifyCriterion())),
                problemIds, problemIds));
        recordFindings(aggregateRunId, packageId, certificateId, caseId, metric, problems);
    }

    void updateExecutionReferences(
            String aggregateRunId,
            String packageId,
            String tenantId,
            List<RuntimeEvidenceMetricResult> metrics,
            Map<String, List<OfficialActualPromptProblem>> problemsByMetric) {
        if (!StringUtils.hasText(aggregateRunId) || !StringUtils.hasText(packageId)
                || !StringUtils.hasText(tenantId) || metrics == null || metrics.isEmpty()) {
            return;
        }
        for (RuntimeEvidenceMetricResult metric : metrics) {
            if (metric == null || !StringUtils.hasText(metric.metricCode())) {
                continue;
            }
            String metricCode = normalize(metric.metricCode());
            List<String> problemIds = safeList(problemsByMetric.get(metricCode)).stream()
                    .map(OfficialActualPromptProblem::problemId).filter(StringUtils::hasText).distinct().toList();
            writers.execution().metricExecutionReference().update(
                    new OfficialVerificationMetricExecutionReferenceWriter.Command(
                            aggregateRunId, metricCode, packageId.trim(), tenantId.trim(),
                            writeJson(problemIds), writeJson(problemIds)));
        }
    }

    void assertCustomerFailuresHaveProblems(
            String aggregateRunId,
            List<RuntimeEvidenceMetricResult> metrics,
            Map<String, List<OfficialActualPromptProblem>> problemsByMetric) {
        for (RuntimeEvidenceMetricResult metric : safeList(metrics)) {
            if (metric == null
                    || !OfficialVerificationMetricClassifier.snapshotMetricFailed(metric)
                    || OfficialVerificationMetricClassifier.internalGateMetric(metric.metricCode())
                    || !metricNarrative.hasCustomerPromptQualityFailure(metric)) {
                continue;
            }
            if (safeList(problemsByMetric.get(normalize(metric.metricCode()))).isEmpty()) {
                throw new IllegalStateException(
                        "ENGINE_CONTRACT_ERROR: Customer-facing metric failed without an actual final userPrompt issue. "
                                + "aggregateRunId=" + aggregateRunId
                                + ", metricCode=" + safe(metric.metricCode())
                                + ", state=" + safe(metric.state()));
            }
        }
    }

    private OfficialVerificationRunBatchWriter.MetricCounts metricCounts(
            List<RuntimeEvidenceMetricResult> metrics,
            Map<String, List<OfficialActualPromptProblem>> problemsByMetric) {
        List<RuntimeEvidenceMetricResult> values = safeList(metrics);
        int failed = (int) values.stream().filter(metric -> actualPromptBlocked(metric, problemsByMetric)).count();
        int notApplicable = (int) values.stream()
                .filter(metric -> "NOT_APPLICABLE".equals(OfficialVerificationMetricClassifier.snapshotState(metric))).count();
        int passed = (int) values.stream()
                .filter(OfficialVerificationMetricClassifier::snapshotMetricPassed).count();
        int insufficient = (int) values.stream()
                .filter(metric -> !actualPromptBlocked(metric, problemsByMetric))
                .filter(metric -> !"NOT_APPLICABLE".equals(OfficialVerificationMetricClassifier.snapshotState(metric)))
                .filter(metric -> !OfficialVerificationMetricClassifier.snapshotMetricPassed(metric)).count();
        return new OfficialVerificationRunBatchWriter.MetricCounts(
                values.size(), passed, failed, insufficient, notApplicable);
    }

    private String blockReasonSummary(
            List<RuntimeEvidenceMetricResult> metrics,
            Map<String, List<OfficialActualPromptProblem>> problemsByMetric) {
        String summary = safeList(metrics).stream()
                .filter(metric -> actualPromptBlocked(metric, problemsByMetric))
                .map(metric -> narrativeCatalog.metricName(metric.metricCode()) + ": "
                        + metricBlockReason(metric, problemsByMetric))
                .filter(StringUtils::hasText).limit(5)
                .reduce((left, right) -> left + " / " + right).orElse("");
        return customerText.optional("runBatch.blockReasonSummary", summary);
    }

    private MetricSituation metricSituation(
            RuntimeEvidenceMetricResult metric,
            List<OfficialActualPromptProblem> problems) {
        String metricCode = safe(metric.metricCode());
        OfficialActualPromptProblem firstProblem = problems.isEmpty() ? null : problems.get(0);
        boolean failed = OfficialVerificationMetricClassifier.snapshotMetricFailed(metric);
        RuntimeEvidenceCheckResult firstFailure = failed ? metricNarrative.firstFailedCheck(metric) : null;
        boolean notApplicable = "NOT_APPLICABLE".equals(OfficialVerificationMetricClassifier.snapshotState(metric));
        boolean inputReview = metricInputNotReady(metric);
        boolean gateReview = failed && (OfficialVerificationMetricClassifier.internalGateMetric(metricCode)
                || (problems.isEmpty() && !inputReview && !notApplicable));
        inputReview = !gateReview && inputReview;
        boolean blocked = !problems.isEmpty();
        String state = blocked ? "BLOCKED" : gateReview ? "GATE_REVIEW"
                : inputReview ? "INPUT_NOT_READY" : notApplicable ? "NOT_APPLICABLE" : "SUCCESS";
        String severity = blocked ? "BLOCKING" : gateReview ? "GATE" : inputReview ? "INPUT" : "INFO";
        return new MetricSituation(
                metricCode, narrativeCatalog.metricName(metricCode), state, severity,
                notApplicable, inputReview, gateReview, firstProblem, firstFailure,
                notApplicable ? metricNarrative.firstNotApplicableCheck(metric) : null);
    }

    private MetricNarrative metricSnapshotNarrative(
            RuntimeEvidenceMetricResult metric,
            MetricSituation situation) {
        FinalPromptMetricContract contract = contractRegistry.metricOrNull(situation.metricCode());
        String purpose = firstNonBlank(
                contract == null ? null : contract.qualityQuestion(), contract == null ? null : contract.purpose(),
                metric.metricName(), narrativeCatalog.metricPurpose(situation.metricCode()));
        String failureReason = situation.firstProblem() != null
                ? problemNarrative.summary(situation.firstProblem())
                : situation.notApplicable() && situation.firstNotApplicable() != null
                ? metricNarrative.notApplicableMessage(situation.firstNotApplicable())
                : metricNarrative.snapshotFailureReason(
                        metric, situation.firstFailure(), situation.inputReview(), situation.gateReview());
        String summary = "BLOCKED".equals(situation.state()) ? failureReason
                : situation.notApplicable() && situation.firstNotApplicable() != null
                ? metricNarrative.notApplicableMessage(situation.firstNotApplicable()) : purpose;
        return new MetricNarrative(
                situation.firstProblem() == null ? situation.metricName() : problemNarrative.title(situation.firstProblem()),
                summary, failureReason, metricOwner(situation), metricAction(situation, purpose),
                metricReverify(situation, purpose));
    }

    private String metricOwner(MetricSituation situation) {
        return situation.firstProblem() != null
                ? metricNarrative.ownerDisplayName(situation.firstProblem().remediationOwner())
                : situation.firstFailure() == null
                ? problemNarrative.message("enterprise.pqa.officialNarrative.owner.official") : metricNarrative.ownerDisplayName(situation.firstFailure().remediationOwner());
    }

    private String metricAction(MetricSituation situation, String purpose) {
        if (situation.firstProblem() != null) return problemNarrative.action(situation.firstProblem());
        if (situation.notApplicable() && situation.firstNotApplicable() != null)
            return metricNarrative.notApplicableMessage(situation.firstNotApplicable());
        return situation.firstFailure() == null ? purpose : metricNarrative.snapshotNextAction(
                situation.metricCode(), situation.firstFailure(), situation.inputReview(), situation.gateReview());
    }

    private String metricReverify(MetricSituation situation, String purpose) {
        if (situation.firstProblem() != null) return problemNarrative.reverify(situation.firstProblem());
        if (situation.notApplicable() && situation.firstNotApplicable() != null)
            return metricNarrative.notApplicableReverify(situation.firstNotApplicable());
        return situation.firstFailure() == null ? purpose : metricNarrative.snapshotReverify(
                situation.metricCode(), situation.firstFailure(), situation.inputReview(), situation.gateReview());
    }

    private void recordFindings(
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            RuntimeEvidenceMetricResult metric,
            List<OfficialActualPromptProblem> problems) {
        for (OfficialActualPromptProblem problem : problems) {
            if (problem != null && StringUtils.hasText(problem.problemId())) {
                writers.finding().insert(findingCommand(
                        aggregateRunId, packageId, certificateId, caseId, metric, problem));
            }
        }
    }

    private OfficialVerificationFindingWriter.FindingCommand findingCommand(
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            RuntimeEvidenceMetricResult metric,
            OfficialActualPromptProblem problem) {
        String rootCause = customerText.require("finding.rootCause", problemNarrative.rootCause(problem));
        String target = customerText.require(
                "finding.affectedTarget", metricNarrative.ownerDisplayName(problem.remediationOwner()));
        return new OfficialVerificationFindingWriter.FindingCommand(
                new OfficialVerificationFindingWriter.FindingIdentity(
                        aggregateRunId, safe(metric.officialRunId()), packageId, certificateId, caseId,
                        problem.problemId(), safe(metric.metricCode()), problem.problemId()),
                new OfficialVerificationFindingWriter.FindingClassification(
                        safe(problem.severity(), "BLOCKING"), problem.sealedEvidencePath(),
                        safe(problem.expectedState()), safe(problem.actualState()),
                        firstNonBlank(problemNarrative.processStep(problem), "OFFICIAL_VERIFICATION"),
                        problem.fieldKey(), problem.problemType(), problem.promptSection()),
                new OfficialVerificationFindingWriter.FindingNarrative(
                        customerText.require("finding.operatorTitle", problemNarrative.title(problem)),
                        customerText.require("finding.operatorSummary", problemNarrative.summary(problem)),
                        customerText.require("finding.problemStatement", problemNarrative.statement(problem)),
                        rootCause, target, customerText.require("finding.operatorReason", rootCause),
                        customerText.require("finding.evidenceSummary", problemNarrative.evidence(problem)),
                        customerText.require("finding.expectedResult", problemNarrative.expectedResult(problem)),
                        customerText.require("finding.actualResult", problemNarrative.actualResult(problem)),
                        customerText.require("finding.impact", problemNarrative.rootCause(problem)),
                        customerText.require("finding.remediationOwner", target),
                        customerText.require("finding.nextAction", problemNarrative.action(problem)),
                        customerText.require("finding.reverifyCriterion", problemNarrative.reverify(problem)),
                        customerText.require("finding.customerVisibleSeverity",
                                problemNarrative.severityLabel(problem.severity()))));
    }

    private boolean actualPromptBlocked(
            RuntimeEvidenceMetricResult metric,
            Map<String, List<OfficialActualPromptProblem>> problemsByMetric) {
        return metric != null && !safeList(problemsByMetric.get(normalize(metric.metricCode()))).isEmpty();
    }

    private String metricBlockReason(
            RuntimeEvidenceMetricResult metric,
            Map<String, List<OfficialActualPromptProblem>> problemsByMetric) {
        List<OfficialActualPromptProblem> problems = safeList(problemsByMetric.get(normalize(metric.metricCode())));
        if (!problems.isEmpty()) {
            return problemNarrative.firstReason(problems);
        }
        RuntimeEvidenceCheckResult failedCheck = metricNarrative.firstFailedCheck(metric);
        if (failedCheck != null && StringUtils.hasText(failedCheck.operatorReason())) {
            return failedCheck.operatorReason().trim();
        }
        return problemNarrative.message("enterprise.pqa.runtimeVerification.metricNarrative.blockReasonMissing");
    }

    private boolean metricInputNotReady(RuntimeEvidenceMetricResult metric) {
        return metric != null && ("INPUT_NOT_READY".equals(OfficialVerificationMetricClassifier.snapshotState(metric))
                || safeList(metric.checks()).stream().anyMatch(checkInterpreter::inputNotReady));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> jsonMap(String json) {
        if (!StringUtils.hasText(json)) return Map.of();
        try {
            return objectMapper.readValue(json, LinkedHashMap.class);
        } catch (Exception ignored) {
            return Map.of();
        }
    }

    private String requestFact(SealedEvidencePackage evidence, String key) {
        Object value = jsonMap(evidence == null ? null : evidence.getRequestFactsJson()).get(key);
        return value == null ? "" : String.valueOf(value).trim();
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalStateException("Official metric output JSON serialization failed.", ex);
        }
    }

    private String firstNonBlank(String... values) {
        for (String value : values) if (StringUtils.hasText(value)) return value.trim();
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

    private record MetricSituation(
            String metricCode, String metricName, String state, String severity,
            boolean notApplicable, boolean inputReview, boolean gateReview,
            OfficialActualPromptProblem firstProblem,
            RuntimeEvidenceCheckResult firstFailure,
            RuntimeEvidenceCheckResult firstNotApplicable) {
    }

    private record MetricNarrative(
            String title, String summary, String failureReason,
            String owner, String nextAction, String reverifyCriterion) {
    }
}
