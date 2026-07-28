package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorFinding;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorRemediationGroup;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorReverificationResult;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorRunBatch;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import org.springframework.dao.DataAccessException;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class OfficialVerificationSnapshotQueryService {

    private final OfficialVerificationSnapshotRepository batchRepository;
    private final OfficialVerificationSnapshotReadModel readModel;
    private final OfficialVerificationSnapshotAssembler assembler;
    private final String diagnosticCatalogVersion;
    private final OfficialVerificationSnapshotIntegrityRepositories integrityRepositories;

    public OfficialVerificationSnapshotQueryService(
            OfficialVerificationSnapshotRepository batchRepository,
            OfficialVerificationSnapshotReadModel readModel,
            OfficialVerificationSnapshotAssembler assembler,
            String diagnosticCatalogVersion,
            OfficialVerificationSnapshotIntegrityRepositories integrityRepositories) {
        this.batchRepository = Objects.requireNonNull(batchRepository, "batchRepository");
        this.readModel = Objects.requireNonNull(readModel, "readModel");
        this.assembler = Objects.requireNonNull(assembler, "assembler");
        this.diagnosticCatalogVersion = Objects.requireNonNull(diagnosticCatalogVersion, "diagnosticCatalogVersion");
        this.integrityRepositories = Objects.requireNonNull(integrityRepositories, "integrityRepositories");
    }

    public boolean sealedEvidencePackageExists(String packageId, String tenantId) {
        return integrityRepositories.completion().sealedEvidencePackageExists(packageId, tenantId);
    }

    public boolean completeSnapshotExists(String aggregateRunId) {
        return integrityRepositories.completion().completeSnapshotExists(aggregateRunId);
    }

    public boolean executionRecordExists(String aggregateRunId) {
        return integrityRepositories.completion().executionRecordExists(aggregateRunId);
    }

    public boolean actualPromptProblemExists(String packageId, String aggregateRunId, String problemId) {
        return integrityRepositories.completion().actualPromptProblemExists(packageId, aggregateRunId, problemId);
    }
    public void assertMetricSnapshotComplete(String aggregateRunId) {
        integrityRepositories.relation().assertMetricSnapshotComplete(aggregateRunId);
    }

    public void assertPromptComparisonLinksComplete(String aggregateRunId) {
        integrityRepositories.relation().assertPromptComparisonLinksComplete(aggregateRunId);
    }

    public void assertActualPromptProblemLedgerAligned(String aggregateRunId) {
        integrityRepositories.relation().assertActualPromptProblemLedgerAligned(aggregateRunId);
    }

    public void assertPromptFieldDefinitionsCoverStateLedger(String aggregateRunId) {
        integrityRepositories.relation().assertPromptFieldDefinitionsCoverStateLedger(aggregateRunId);
    }

    public void assertCustomerVisiblePurposeLedgersClean(String aggregateRunId) {
        integrityRepositories.customerPurpose().assertClean(aggregateRunId);
    }
    public void assertCustomerDisplayPayloadComplete(String aggregateRunId) {
        integrityRepositories.customerDisplay().assertPayloadComplete(aggregateRunId);
    }

    public void assertCustomerDisplayContractRole(
            String purposeVersion, String metricCode, String checkCode, String displayRole) {
        integrityRepositories.customerDisplay().assertContractRole(
                purposeVersion, metricCode, checkCode, displayRole);
    }

    public boolean contractedPromptSignal(String item) {
        return integrityRepositories.customerDisplay().contractedPromptSignal(item);
    }
    public void assertActualPromptProblemLedgerReferences(String aggregateRunId) {
        integrityRepositories.contractLink().assertActualPromptProblemLedgerReferences(aggregateRunId);
    }

    public Set<String> registeredMetricCodes() {
        return integrityRepositories.contractLink().registeredMetricCodes();
    }

    public Set<String> registeredMetricCheckCodes() {
        return integrityRepositories.contractLink().registeredMetricCheckCodes();
    }

    public Optional<OfficialVerificationContractLinkIntegrityRepository.CheckDefinitionLink> findMetricCheckDefinition(
            String metricCode, String checkCode) {
        return integrityRepositories.contractLink().findMetricCheckDefinition(metricCode, checkCode);
    }

    public Optional<OfficialVerificationContractLinkIntegrityRepository.CheckDefinitionLink> findActualPromptProblemLink(
            String aggregateRunId, String problemId, String issueKey, String contractIssueKey, String source) {
        return integrityRepositories.contractLink().findActualPromptProblemLink(
                aggregateRunId, problemId, issueKey, contractIssueKey, source);
    }
    public OperatorSnapshot findLatest(String packageId, String aggregateRunId) {
        OperatorRunBatch batch = currentBatch(packageId, aggregateRunId);
        return assemble(batch);
    }

    public OperatorSnapshot findPublished(String packageId, String aggregateRunId) {
        OperatorRunBatch batch = currentBatch(packageId, aggregateRunId);
        if (batch == null
                || !integrityRepositories.completion().publishableSnapshotExists(batch.aggregateRunId())) {
            return OperatorSnapshot.empty();
        }
        return assemble(batch);
    }

    private OperatorSnapshot assemble(OperatorRunBatch batch) {
        if (batch == null) {
            return OperatorSnapshot.empty();
        }
        return assembler.assemble(
                batch,
                readModel.metrics(batch.aggregateRunId()),
                readModel.findings(batch.aggregateRunId()),
                readModel.remediationGroups(batch.aggregateRunId()),
                readModel.actualPromptProblems(batch.aggregateRunId()),
                readModel.purposeEvidence(batch.aggregateRunId()),
                readModel.auditSnapshots(batch.aggregateRunId()));
    }

    public List<OfficialVerificationPromptComparison> promptComparisons(
            String packageId,
            String aggregateRunId) {
        OperatorRunBatch batch = currentBatch(packageId, aggregateRunId);
        return batch == null
                ? List.of()
                : readModel.promptComparisons(batch.packageId(), batch.aggregateRunId());
    }

    public List<OfficialActualPromptProblem> actualPromptProblems(
            String packageId,
            String aggregateRunId) {
        OperatorRunBatch batch = currentBatch(packageId, aggregateRunId);
        if (batch == null) {
            return List.of();
        }
        return readModel.actualPromptProblems(batch.aggregateRunId()).stream()
                .filter(problem -> batch.packageId().equals(problem.packageId()))
                .toList();
    }

    public List<OperatorSnapshot> recentSnapshots(int limit) {
        int rowLimit = Math.max(1, Math.min(limit <= 0 ? 10 : limit, 50));
        List<OperatorRunBatch> batches = batchRepository.findRecentCurrentBatches(
                diagnosticCatalogVersion,
                rowLimit);
        return assembleAll(batches);
    }

    public List<OperatorSnapshot> recentPublishedSnapshots(int limit) {
        int rowLimit = Math.max(1, Math.min(limit <= 0 ? 10 : limit, 50));
        List<OperatorRunBatch> batches = batchRepository.findRecentCurrentBatches(
                        diagnosticCatalogVersion,
                        rowLimit).stream()
                .filter(batch -> integrityRepositories.completion()
                        .publishableSnapshotExists(batch.aggregateRunId()))
                .toList();
        return assembleAll(batches);
    }

    private List<OperatorSnapshot> assembleAll(List<OperatorRunBatch> batches) {
        if (batches.isEmpty()) {
            return List.of();
        }
        List<String> runIds = batches.stream()
                .map(OperatorRunBatch::aggregateRunId)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        return assembler.assembleAll(
                batches,
                grouped(readModel.metrics(runIds), OperatorMetricSnapshot::aggregateRunId),
                grouped(readModel.findings(runIds), OperatorFinding::aggregateRunId),
                grouped(readModel.remediationGroups(runIds), OperatorRemediationGroup::aggregateRunId),
                grouped(readModel.actualPromptProblems(runIds), OfficialActualPromptProblem::aggregateRunId),
                grouped(readModel.purposeEvidence(runIds), OperatorPurposeEvidence::aggregateRunId),
                grouped(readModel.auditSnapshots(runIds), OperatorAuditSnapshot::aggregateRunId));
    }

    public List<OperatorReverificationResult> reverificationResults(
            String sourcePackageId,
            String sourceAggregateRunId) {
        if (!StringUtils.hasText(sourcePackageId)) {
            return List.of();
        }
        try {
            return readModel.reverificationResults(
                    sourcePackageId.trim(),
                    StringUtils.hasText(sourceAggregateRunId) ? sourceAggregateRunId.trim() : null);
        }
        catch (DataAccessException ignored) {
            return List.of();
        }
    }

    List<OperatorFinding> findings(String aggregateRunId) {
        return readModel.findings(aggregateRunId);
    }

    List<OperatorRemediationGroup> remediationGroups(String aggregateRunId) {
        return readModel.remediationGroups(aggregateRunId);
    }

    private OperatorRunBatch currentBatch(String packageId, String aggregateRunId) {
        if (!StringUtils.hasText(packageId)) {
            return null;
        }
        return batchRepository.findCurrentBatch(
                        packageId.trim(),
                        StringUtils.hasText(aggregateRunId) ? aggregateRunId.trim() : null,
                        diagnosticCatalogVersion)
                .orElse(null);
    }

    private <T> Map<String, List<T>> grouped(List<T> rows, Function<T, String> aggregateRunId) {
        return rows.stream().collect(Collectors.groupingBy(
                aggregateRunId,
                LinkedHashMap::new,
                Collectors.toList()));
    }
}
