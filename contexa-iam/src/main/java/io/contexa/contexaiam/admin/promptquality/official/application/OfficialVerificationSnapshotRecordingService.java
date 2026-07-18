package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import org.springframework.dao.DataAccessException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

final class OfficialVerificationSnapshotRecordingService {

    private final OfficialVerificationSnapshotCleanupRepository cleanupRepository;
    private final OfficialVerificationSnapshotQueryService queryService;
    private final OfficialVerificationCurrentResultCoordinator currentResultCoordinator;
    private final OfficialVerificationSnapshotCommandWriters commandWriters;
    private final OfficialVerificationLedgerWriters ledgerWriters;
    private final OfficialFinalPromptMetricContractRegistry contractRegistry;
    private final OfficialVerificationSnapshotRecorders recorders;

    OfficialVerificationSnapshotRecordingService(
            OfficialVerificationSnapshotCleanupRepository cleanupRepository,
            OfficialVerificationSnapshotQueryService queryService,
            OfficialVerificationCurrentResultCoordinator currentResultCoordinator,
            OfficialVerificationSnapshotCommandWriters commandWriters,
            OfficialVerificationLedgerWriters ledgerWriters,
            OfficialFinalPromptMetricContractRegistry contractRegistry,
            OfficialVerificationSnapshotRecorders recorders) {
        this.cleanupRepository = cleanupRepository;
        this.queryService = queryService;
        this.currentResultCoordinator = currentResultCoordinator;
        this.commandWriters = commandWriters;
        this.ledgerWriters = ledgerWriters;
        this.contractRegistry = contractRegistry;
        this.recorders = recorders;
    }

    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    void record(
            String aggregateRunId,
            SealedEvidencePackage evidencePackage,
            String requestPath,
            String resourceId,
            String httpMethod,
            String promptHash,
            String contextHash,
            String certificateId,
            String caseId,
            List<RuntimeEvidenceMetricResult> metrics,
            List<OfficialVerificationPromptComparison> promptComparisons) {
        if (!StringUtils.hasText(aggregateRunId)
                || evidencePackage == null || metrics == null || metrics.isEmpty()) {
            return;
        }
        validateMetricCodes(metrics);
        requirePersistedPackage(evidencePackage.getPackageId(), evidencePackage.getTenantId());
        RecordingCommand command = new RecordingCommand(
                aggregateRunId, evidencePackage, requestPath, resourceId, httpMethod,
                promptHash, contextHash, certificateId, caseId, metrics, safeList(promptComparisons));
        try {
            recordSnapshot(command);
        }
        catch (DataAccessException ex) {
            throw new IllegalStateException(
                    "Official verification snapshot persistence failed: " + databaseMessage(ex), ex);
        }
    }

    private void recordSnapshot(RecordingCommand command) {
        SealedEvidencePackage evidence = command.evidence();
        currentResultCoordinator.acquireWriteLock(
                evidence.getPackageId(), evidence.getTenantId(),
                command.requestPath(), command.resourceId(), command.httpMethod());
        if (queryService.completeSnapshotExists(command.aggregateRunId())) {
            return;
        }
        PreparedSnapshot prepared = prepare(command);
        recordPurposeAndProblems(command, prepared);
        currentResultCoordinator.supersedeCurrent(
                command.aggregateRunId(), evidence.getTenantId(),
                command.requestPath(), command.resourceId(), command.httpMethod());
        recorders.metricOutput().recordBatch(
                command.aggregateRunId(), evidence, command.requestPath(), command.resourceId(), command.httpMethod(),
                command.promptHash(), command.contextHash(), command.certificateId(), command.caseId(),
                command.metrics(), prepared.problemsByMetric());
        recordMetrics(command, prepared);
        recordFinalOutputs(command, prepared);
    }

    private PreparedSnapshot prepare(RecordingCommand command) {
        SealedEvidencePackage evidence = command.evidence();
        contractRegistry.assertDefinitionsRegistered(command.metrics());
        cleanupRepository.deleteAggregateSnapshot(
                evidence.getTenantId(), evidence.getPackageId(), command.aggregateRunId());
        commandWriters.promptFieldDefinition().upsertFrom(evidence);
        List<OfficialActualPromptProblem> problems = recorders.actualPromptProblems().collect(
                command.aggregateRunId(), evidence.getPackageId(),
                command.metrics(), command.promptComparisons());
        Map<String, List<OfficialActualPromptProblem>> byMetric =
                recorders.actualPromptProblems().byMetric(problems);
        recorders.metricOutput().assertCustomerFailuresHaveProblems(
                command.aggregateRunId(), command.metrics(), byMetric);
        return new PreparedSnapshot(problems, byMetric);
    }

    private void recordPurposeAndProblems(RecordingCommand command, PreparedSnapshot prepared) {
        SealedEvidencePackage evidence = command.evidence();
        recorders.promptSignal().recordParsed(
                command.aggregateRunId(), evidence.getPackageId(), evidence, contractRegistry.catalog());
        recorders.metricPurpose().record(
                command.aggregateRunId(), evidence.getPackageId(), command.metrics());
        recorders.metricPurpose().assertCustomerDisplayComplete(command.aggregateRunId());
        ledgerWriters.actualPromptProblem().insert(
                command.aggregateRunId(), evidence.getPackageId(),
                prepared.problems().stream().map(this::problemCommand).toList());
        linkProblems(command.aggregateRunId(), evidence);
    }

    private void recordMetrics(RecordingCommand command, PreparedSnapshot prepared) {
        String packageId = command.evidence().getPackageId();
        for (RuntimeEvidenceMetricResult metric : command.metrics()) {
            List<OfficialActualPromptProblem> problems = prepared.problemsByMetric()
                    .getOrDefault(normalize(metric.metricCode()), List.of());
            recorders.metricOutput().recordMetric(
                    command.aggregateRunId(), packageId, command.certificateId(), command.caseId(), metric, problems);
        }
        recorders.metricOutput().updateExecutionReferences(
                command.aggregateRunId(), packageId, command.evidence().getTenantId(),
                command.metrics(), prepared.problemsByMetric());
    }

    private void recordFinalOutputs(RecordingCommand command, PreparedSnapshot prepared) {
        SealedEvidencePackage evidence = command.evidence();
        recorders.remediationGroup().record(
                command.aggregateRunId(), evidence.getPackageId(), command.certificateId(), command.caseId(),
                prepared.problems());
        recorders.promptComparison().record(
                command.aggregateRunId(), evidence.getPackageId(), command.promptComparisons(), prepared.problems());
        recorders.promptLineage().record(
                command.aggregateRunId(), evidence.getPackageId(), evidence,
                command.promptHash(), command.contextHash());
        recorders.promptFieldState().record(command.aggregateRunId(), evidence.getPackageId(), evidence);
        linkProblems(command.aggregateRunId(), evidence);
        ledgerWriters.promptQualityIssue().synchronize(
                evidence.getTenantId(), evidence.getPackageId(), command.aggregateRunId());
        assertIntegrity(command.aggregateRunId());
    }

    private OfficialVerificationActualPromptProblemWriter.Command problemCommand(
            OfficialActualPromptProblem problem) {
        return new OfficialVerificationActualPromptProblemWriter.Command(
                problem.problemId(), problem.fieldKey(), problem.problemType(), problem.promptSection(),
                problem.promptLabel(), problem.promptValue(), problem.sourceFieldPath(), problem.sealedEvidencePath(),
                problem.expectedState(), problem.actualState(), problem.severity(), problem.metricCodes(),
                problem.remediationOwner(), problem.qualityQuestion(), problem.whyItMatters(),
                problem.fixAction(), problem.reverifyCriterionDetail());
    }

    private void linkProblems(String aggregateRunId, SealedEvidencePackage evidence) {
        ledgerWriters.actualPromptProblemLinker().link(
                aggregateRunId, evidence.getPackageId(), evidence.getTenantId());
    }

    private void assertIntegrity(String aggregateRunId) {
        queryService.assertPromptFieldDefinitionsCoverStateLedger(aggregateRunId);
        queryService.assertCustomerVisiblePurposeLedgersClean(aggregateRunId);
        queryService.assertPromptComparisonLinksComplete(aggregateRunId);
        queryService.assertActualPromptProblemLedgerAligned(aggregateRunId);
        queryService.assertActualPromptProblemLedgerReferences(aggregateRunId);
        queryService.assertMetricSnapshotComplete(aggregateRunId);
    }

    private void validateMetricCodes(List<RuntimeEvidenceMetricResult> metrics) {
        Set<String> metricCodes = new LinkedHashSet<>();
        for (RuntimeEvidenceMetricResult metric : metrics) {
            if (metric == null || !StringUtils.hasText(metric.metricCode())) {
                throw new IllegalStateException(
                        "Official prompt quality inspection metric result must provide a metric code.");
            }
            String metricCode = normalize(metric.metricCode());
            if (!metricCodes.add(metricCode)) {
                throw new IllegalStateException(
                        "Official prompt quality inspection metric results must be unique. duplicate=" + metricCode);
            }
        }
    }

    private void requirePersistedPackage(String packageId, String tenantId) {
        if (!StringUtils.hasText(packageId) || !StringUtils.hasText(tenantId)) {
            throw new IllegalStateException(
                    "ENGINE_CONTRACT_ERROR: official verification requires a tenant-scoped sealed evidence package.");
        }
        if (!queryService.sealedEvidencePackageExists(packageId.trim(), tenantId.trim())) {
            throw new IllegalStateException(
                    "ENGINE_CONTRACT_ERROR: official verification package is not linked to tenant-scoped sealed evidence."
                            + " packageId=" + packageId.trim() + ", tenantId=" + tenantId.trim());
        }
    }

    private String databaseMessage(DataAccessException ex) {
        Throwable cause = ex.getMostSpecificCause();
        return cause == null || !StringUtils.hasText(cause.getMessage())
                ? ex.getClass().getSimpleName() : cause.getMessage();
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private <T> List<T> safeList(List<T> values) {
        return values == null ? List.of() : values;
    }

    private record RecordingCommand(
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
            List<OfficialVerificationPromptComparison> promptComparisons) {
    }

    private record PreparedSnapshot(
            List<OfficialActualPromptProblem> problems,
            Map<String, List<OfficialActualPromptProblem>> problemsByMetric) {
    }
}
