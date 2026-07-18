package io.contexa.contexaiam.admin.promptquality.official.application;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractCatalogWriter;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationCurrentResultCoordinator;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationSnapshotRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationSnapshotCompletionRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationSnapshotRelationIntegrityRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationCustomerPurposeIntegrityRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationCustomerDisplayIntegrityRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationContractLinkIntegrityRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationSnapshotCleanupRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationActualPromptProblemRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationActualPromptProblemWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPromptQualityIssueSynchronizer;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationMetricPurposeWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationMetricPurposeEvidenceWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPromptSignalWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationActualPromptProblemLinker;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPromptLineageWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPromptFieldStateWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationAuditSnapshotRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationAuditSnapshotWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationFindingRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationFindingWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationMetricSnapshotRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationMetricSnapshotWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPromptComparisonRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPromptComparisonWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialPromptFieldDefinitionWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationReverificationWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationMetricExecutionReferenceWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationPurposeEvidenceRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationRemediationGroupRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationRemediationGroupWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationReverificationResultRepository;
import io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcOfficialVerificationRunBatchWriter;
import io.contexa.contexaiam.admin.promptquality.official.persistence.OfficialVerificationSnapshotRowMapper;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityIssue;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyFindingResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import org.springframework.dao.DataAccessException;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class OfficialVerificationOperatorSnapshotService {

    public static final String DIAGNOSTIC_CATALOG_VERSION = OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION;
    public static final String ACTUAL_PROMPT_PROBLEM_LEDGER_CONTRACT_VERSION =
            DIAGNOSTIC_CATALOG_VERSION + "-ACTUAL-PROMPT-PROBLEM-LEDGER-2026.05.13.2";
    private final OfficialVerificationSnapshotCleanupRepository snapshotCleanupRepository;
    private final OfficialVerificationSnapshotQueryService snapshotQueryService;
    private final OfficialVerificationSnapshotCommandWriters commandWriters;
    private final OfficialVerificationSnapshotRecordingService snapshotRecordingService;
    private final OfficialVerificationReverificationResultRecorder reverificationResultRecorder;

    public OfficialVerificationOperatorSnapshotService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this(
                jdbcTemplate,
                objectMapper,
                defaultContractCatalogWriter(jdbcTemplate, objectMapper),
                new JdbcOfficialVerificationSnapshotCleanupRepository(jdbcTemplate),
                new JdbcOfficialVerificationSnapshotRepository(jdbcTemplate),
                new OfficialVerificationSnapshotAssembler(),
                new JdbcOfficialVerificationCurrentResultCoordinator(jdbcTemplate));
    }

    public OfficialVerificationOperatorSnapshotService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            OfficialMetricPurposeContractWriter contractCatalogWriter) {
        this(
                jdbcTemplate,
                objectMapper,
                contractCatalogWriter,
                new JdbcOfficialVerificationSnapshotCleanupRepository(jdbcTemplate),
                new JdbcOfficialVerificationSnapshotRepository(jdbcTemplate),
                new OfficialVerificationSnapshotAssembler(),
                new JdbcOfficialVerificationCurrentResultCoordinator(jdbcTemplate));
    }

    public OfficialVerificationOperatorSnapshotService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            OfficialVerificationSnapshotRepository snapshotRepository,
            OfficialVerificationSnapshotAssembler snapshotAssembler) {
        this(
                jdbcTemplate,
                objectMapper,
                defaultContractCatalogWriter(jdbcTemplate, objectMapper),
                new JdbcOfficialVerificationSnapshotCleanupRepository(jdbcTemplate),
                snapshotRepository,
                snapshotAssembler,
                new JdbcOfficialVerificationCurrentResultCoordinator(jdbcTemplate));
    }

    public OfficialVerificationOperatorSnapshotService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            OfficialVerificationSnapshotRepository snapshotRepository,
            OfficialVerificationSnapshotAssembler snapshotAssembler,
            OfficialVerificationCurrentResultCoordinator currentResultCoordinator) {
        this(
                jdbcTemplate,
                objectMapper,
                defaultContractCatalogWriter(jdbcTemplate, objectMapper),
                new JdbcOfficialVerificationSnapshotCleanupRepository(jdbcTemplate),
                snapshotRepository,
                snapshotAssembler,
                currentResultCoordinator);
    }
    public OfficialVerificationOperatorSnapshotService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            OfficialMetricPurposeContractWriter contractCatalogWriter,
            OfficialVerificationSnapshotRepository snapshotRepository,
            OfficialVerificationSnapshotAssembler snapshotAssembler) {
        this(
                jdbcTemplate,
                objectMapper,
                contractCatalogWriter,
                new JdbcOfficialVerificationSnapshotCleanupRepository(jdbcTemplate),
                snapshotRepository,
                snapshotAssembler,
                new JdbcOfficialVerificationCurrentResultCoordinator(jdbcTemplate));
    }

    public OfficialVerificationOperatorSnapshotService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            OfficialMetricPurposeContractWriter contractCatalogWriter,
            OfficialVerificationSnapshotCleanupRepository snapshotCleanupRepository,
            OfficialVerificationSnapshotRepository snapshotRepository,
            OfficialVerificationSnapshotAssembler snapshotAssembler,
            OfficialVerificationCurrentResultCoordinator currentResultCoordinator) {
        this(
                objectMapper,
                contractCatalogWriter,
                snapshotCleanupRepository,
                defaultQueryService(jdbcTemplate, objectMapper, snapshotRepository, snapshotAssembler),
                new OfficialVerificationSnapshotCommandWriters(
                        new JdbcOfficialVerificationAuditSnapshotWriter(jdbcTemplate, objectMapper),
                        new JdbcOfficialVerificationRunBatchWriter(jdbcTemplate),
                        new JdbcOfficialVerificationMetricSnapshotWriter(jdbcTemplate, objectMapper),
                        new JdbcOfficialVerificationFindingWriter(jdbcTemplate),
                        new JdbcOfficialVerificationRemediationGroupWriter(jdbcTemplate),
                        new JdbcOfficialVerificationPromptComparisonWriter(jdbcTemplate),
                        new JdbcOfficialPromptFieldDefinitionWriter(jdbcTemplate, objectMapper),
                        new OfficialVerificationExecutionWriters(
                                new JdbcOfficialVerificationReverificationWriter(jdbcTemplate),
                                new JdbcOfficialVerificationMetricExecutionReferenceWriter(jdbcTemplate))),
                new OfficialVerificationLedgerWriters(
                        new JdbcOfficialVerificationActualPromptProblemWriter(jdbcTemplate),
                        new JdbcOfficialVerificationPromptQualityIssueSynchronizer(jdbcTemplate),
                        new JdbcOfficialVerificationMetricPurposeWriter(jdbcTemplate),
                        new JdbcOfficialVerificationMetricPurposeEvidenceWriter(jdbcTemplate),
                        new JdbcOfficialVerificationPromptSignalWriter(jdbcTemplate),
                        new JdbcOfficialVerificationActualPromptProblemLinker(jdbcTemplate),
                        new JdbcOfficialVerificationPromptLineageWriter(jdbcTemplate),
                        new JdbcOfficialVerificationPromptFieldStateWriter(jdbcTemplate)),
                currentResultCoordinator);
    }

    public OfficialVerificationOperatorSnapshotService(
            ObjectMapper objectMapper,
            OfficialMetricPurposeContractWriter contractCatalogWriter,
            OfficialVerificationSnapshotCleanupRepository snapshotCleanupRepository,
            OfficialVerificationSnapshotQueryService snapshotQueryService,
            OfficialVerificationSnapshotCommandWriters commandWriters,
            OfficialVerificationLedgerWriters ledgerWriters,
            OfficialVerificationCurrentResultCoordinator currentResultCoordinator) {
        this(
                objectMapper,
                contractCatalogWriter,
                snapshotCleanupRepository,
                snapshotQueryService,
                commandWriters,
                ledgerWriters,
                currentResultCoordinator,
                OfficialVerificationMessageResolver.classpath(Locale.KOREAN));
    }

    public OfficialVerificationOperatorSnapshotService(
            ObjectMapper objectMapper,
            OfficialMetricPurposeContractWriter contractCatalogWriter,
            OfficialVerificationSnapshotCleanupRepository snapshotCleanupRepository,
            OfficialVerificationSnapshotQueryService snapshotQueryService,
            OfficialVerificationSnapshotCommandWriters commandWriters,
            OfficialVerificationLedgerWriters ledgerWriters,
            OfficialVerificationCurrentResultCoordinator currentResultCoordinator,
            OfficialVerificationMessageResolver messageResolver) {

        OfficialPromptExecutionMetadataReader promptExecutionMetadataReader = new OfficialPromptExecutionMetadataReader(objectMapper);
        this.snapshotCleanupRepository = snapshotCleanupRepository;
        this.snapshotQueryService = snapshotQueryService;
        OfficialFinalPromptMetricContractRegistry metricContractRegistry = new OfficialFinalPromptMetricContractRegistry(
                objectMapper, contractCatalogWriter, snapshotQueryService);
        this.commandWriters = commandWriters;

        OfficialPromptEvidenceFormatter promptEvidenceFormatter =
                new OfficialPromptEvidenceFormatter(objectMapper, messageResolver);
        OfficialRuntimeEvidenceCheckInterpreter checkInterpreter = new OfficialRuntimeEvidenceCheckInterpreter(objectMapper);
        OfficialActualPromptProblemNarrative actualPromptProblemNarrative = new OfficialActualPromptProblemNarrative(promptEvidenceFormatter);
        OfficialCustomerPurposeEvidenceValidator customerPurposeEvidenceValidator = new OfficialCustomerPurposeEvidenceValidator(
                snapshotQueryService, promptEvidenceFormatter);
        OfficialCustomerPurposeEvidenceParser customerPurposeEvidenceParser = new OfficialCustomerPurposeEvidenceParser(
                objectMapper, promptEvidenceFormatter, customerPurposeEvidenceValidator, checkInterpreter);
        OfficialMetricPurposeNarrative metricPurposeNarrative = new OfficialMetricPurposeNarrative(
                promptEvidenceFormatter, customerPurposeEvidenceParser,
                customerPurposeEvidenceValidator, checkInterpreter);
        OfficialVerificationMetricNarrative metricNarrative = new OfficialVerificationMetricNarrative(
                metricContractRegistry, checkInterpreter, promptEvidenceFormatter);
        OfficialVerificationCustomerTextPolicy customerTextPolicy = new OfficialVerificationCustomerTextPolicy();
        OfficialVerificationMetricOutputRecorder metricOutputRecorder = new OfficialVerificationMetricOutputRecorder(
                objectMapper, commandWriters, metricNarrative, actualPromptProblemNarrative,
                customerTextPolicy, checkInterpreter, promptExecutionMetadataReader, metricContractRegistry);
        OfficialVerificationRemediationGroupRecorder remediationGroupRecorder = new OfficialVerificationRemediationGroupRecorder(
                commandWriters.remediationGroup(), actualPromptProblemNarrative,
                metricNarrative, customerTextPolicy);
        OfficialVerificationPromptComparisonRecorder promptComparisonRecorder = new OfficialVerificationPromptComparisonRecorder(
                commandWriters.promptComparison(), snapshotQueryService, actualPromptProblemNarrative);
        OfficialActualPromptProblemCollector actualPromptProblemCollector = new OfficialActualPromptProblemCollector(
                metricContractRegistry, metricPurposeNarrative, checkInterpreter, actualPromptProblemNarrative);
        OfficialPromptSignalLedgerRecorder promptSignalLedgerRecorder = new OfficialPromptSignalLedgerRecorder(ledgerWriters.promptSignal());
        OfficialMetricPurposeLedgerRecorder metricPurposeLedgerRecorder = new OfficialMetricPurposeLedgerRecorder(
                objectMapper, ledgerWriters, metricContractRegistry, metricPurposeNarrative,
                customerPurposeEvidenceParser, customerPurposeEvidenceValidator,
                checkInterpreter, promptSignalLedgerRecorder);
        OfficialPromptLineageRecorder promptLineageRecorder = new OfficialPromptLineageRecorder(
                ledgerWriters.promptLineage(), promptExecutionMetadataReader);
        OfficialPromptFieldStateLedgerRecorder promptFieldStateLedgerRecorder = new OfficialPromptFieldStateLedgerRecorder(
                objectMapper, ledgerWriters.promptFieldState());
        OfficialVerificationSnapshotRecorders recorders = new OfficialVerificationSnapshotRecorders(
                actualPromptProblemCollector, metricPurposeLedgerRecorder, metricOutputRecorder,
                remediationGroupRecorder, promptComparisonRecorder, promptSignalLedgerRecorder,
                promptLineageRecorder, promptFieldStateLedgerRecorder);
        this.snapshotRecordingService = new OfficialVerificationSnapshotRecordingService(
                snapshotCleanupRepository, snapshotQueryService, currentResultCoordinator,
                commandWriters, ledgerWriters, metricContractRegistry, recorders);
        this.reverificationResultRecorder = new OfficialVerificationReverificationResultRecorder(
                objectMapper, snapshotQueryService, commandWriters.execution().reverification(), messageResolver);

    }
    private static OfficialMetricPurposeContractWriter defaultContractCatalogWriter(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper) {
        return new OfficialMetricPurposeContractCatalogWriter(jdbcTemplate, objectMapper);
    }
    private static OfficialVerificationSnapshotQueryService defaultQueryService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            OfficialVerificationSnapshotRepository batchRepository,
            OfficialVerificationSnapshotAssembler snapshotAssembler) {
        OfficialVerificationSnapshotRowMapper rowMapper = new OfficialVerificationSnapshotRowMapper(objectMapper);
        OfficialVerificationSnapshotReadModel readModel = new OfficialVerificationSnapshotReadModel(
                new JdbcOfficialVerificationMetricSnapshotRepository(jdbcTemplate, rowMapper),
                new JdbcOfficialVerificationFindingRepository(jdbcTemplate, rowMapper),
                new JdbcOfficialVerificationRemediationGroupRepository(jdbcTemplate, rowMapper),
                new JdbcOfficialVerificationPromptComparisonRepository(jdbcTemplate, rowMapper),
                new JdbcOfficialVerificationActualPromptProblemRepository(jdbcTemplate, rowMapper),
                new JdbcOfficialVerificationPurposeEvidenceRepository(jdbcTemplate, rowMapper),
                new JdbcOfficialVerificationAuditSnapshotRepository(jdbcTemplate, rowMapper),
                new JdbcOfficialVerificationReverificationResultRepository(jdbcTemplate, rowMapper));
        return new OfficialVerificationSnapshotQueryService(
                batchRepository,
                readModel,
                snapshotAssembler,
                DIAGNOSTIC_CATALOG_VERSION,
                new OfficialVerificationSnapshotIntegrityRepositories(
                        new JdbcOfficialVerificationSnapshotCompletionRepository(jdbcTemplate),
                        new JdbcOfficialVerificationSnapshotRelationIntegrityRepository(jdbcTemplate),
                        new JdbcOfficialVerificationCustomerPurposeIntegrityRepository(jdbcTemplate),
                        new JdbcOfficialVerificationCustomerDisplayIntegrityRepository(jdbcTemplate),
                        new JdbcOfficialVerificationContractLinkIntegrityRepository(jdbcTemplate)));
    }
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public List<String> replaceDiagnosticsForQualityTarget(
            String tenantId,
            String currentPackageId,
            String actualResourceId,
            String actualRequestPath,
            String httpMethod) {
        if (!StringUtils.hasText(currentPackageId)) {
            return List.of();
        }
        if (!StringUtils.hasText(tenantId)) {
            throw new IllegalArgumentException("tenantId is required for official verification diagnostic mutation.");
        }
        snapshotCleanupRepository.deleteDiagnosticPackage(tenantId.trim(), currentPackageId.trim());
        return List.of();
    }

    public void record(
            String aggregateRunId,
            SealedEvidencePackage evidencePackage,
            String requestPath,
            String resourceId,
            String httpMethod,
            String promptHash,
            String contextHash,
            String certificateId,
            String caseId,
            List<PromptQualityIssue> issues,
            List<RuntimeEvidenceMetricResult> metrics,
            List<OfficialVerificationPromptComparison> promptComparisons) {
        snapshotRecordingService.record(
                aggregateRunId, evidencePackage, requestPath, resourceId, httpMethod,
                promptHash, contextHash, certificateId, caseId, metrics, promptComparisons);
    }
    public OperatorSnapshot findLatest(String packageId, String aggregateRunId) {
        return snapshotQueryService.findLatest(packageId, aggregateRunId);
    }

    public List<OfficialVerificationPromptComparison> promptComparisons(
            String packageId,
            String aggregateRunId) {
        if (!StringUtils.hasText(packageId)) {
            return List.of();
        }
        try {
            OperatorSnapshot snapshot = snapshotQueryService.findLatest(packageId, aggregateRunId);
            String resolvedAggregateRunId = snapshot.batch() == null
                    ? null
                    : snapshot.batch().aggregateRunId();
            if (!StringUtils.hasText(resolvedAggregateRunId)) {
                return List.of();
            }
            return snapshotQueryService.promptComparisons(packageId, resolvedAggregateRunId);
        }
        catch (DataAccessException ignored) {
            return List.of();
        }
    }

    public List<OfficialActualPromptProblem> actualPromptProblems(
            String packageId,
            String aggregateRunId) {
        try {
            return snapshotQueryService.actualPromptProblems(packageId, aggregateRunId);
        }
        catch (DataAccessException ignored) {
            return List.of();
        }
    }

    public List<OperatorSnapshot> recentSnapshots(int limit) {
        return snapshotQueryService.recentSnapshots(limit);
    }

    public List<OperatorReverificationResult> reverificationResults(
            String sourcePackageId,
            String sourceAggregateRunId) {
        return snapshotQueryService.reverificationResults(sourcePackageId, sourceAggregateRunId);
    }
    public void recordAuditSnapshot(
            String tenantId,
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            String state,
            String stateLabel,
            int totalMetricCount,
            int failedMetricCount,
            boolean certificateIssued,
            String promptHash,
            String contextHash,
            List<String> blockingFindings,
            List<String> nextActions,
            Map<String, Object> payload,
            String operatorId) {
        commandWriters.auditSnapshot().record(new OfficialVerificationAuditSnapshotWriter.AuditSnapshotCommand(
                tenantId, aggregateRunId, packageId, certificateId, caseId, state, stateLabel,
                totalMetricCount, failedMetricCount, certificateIssued, promptHash, contextHash,
                blockingFindings, nextActions, payload, operatorId));
    }
    public List<RuntimeEvidenceReverifyFindingResult> recordReverificationResults(
            String sourcePackageId,
            String sourceAggregateRunId,
            List<String> findingIds,
            List<String> issueIds,
            RuntimeEvidenceVerificationRun fixedRun,
            String operatorId) {
        return reverificationResultRecorder.record(
                sourcePackageId, sourceAggregateRunId, findingIds, issueIds, fixedRun, operatorId);
    }
    public record OperatorSnapshot(
            OperatorRunBatch batch,
            List<OperatorMetricSnapshot> metrics,
            List<OperatorFinding> findings,
            List<OperatorRemediationGroup> remediationGroups,
            List<OfficialActualPromptProblem> actualPromptProblems,
            List<OperatorPurposeEvidence> purposeEvidence,
            List<OperatorAuditSnapshot> auditSnapshots) {
        public OperatorSnapshot(
                OperatorRunBatch batch,
                List<OperatorMetricSnapshot> metrics,
                List<OperatorFinding> findings,
                List<OperatorRemediationGroup> remediationGroups,
                List<OperatorAuditSnapshot> auditSnapshots) {
            this(batch, metrics, findings, remediationGroups, List.of(), List.of(), auditSnapshots);
        }

        public static OperatorSnapshot empty() {
            return new OperatorSnapshot(null, List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
        }

        public boolean available() {
            return batch != null;
        }
    }

    public record OperatorRunBatch(
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            String scopeType,
            int expectedMetricCount,
            int actualMetricCount,
            int passedMetricCount,
            int failedMetricCount,
            int insufficientMetricCount,
            int notApplicableMetricCount,
            String finalDecision,
            boolean blocked,
            String blockReasonSummary,
            String promptHash,
            String contextHash,
            String contextHashState,
            String templateResourceId,
            String actualResourceId,
            String resourceUrlTemplate,
            String actualRequestPath,
            String httpMethod,
            String diagnosticCatalogVersion,
            Instant createdAt) {
        public OperatorRunBatch(
                String aggregateRunId,
                String packageId,
                String certificateId,
                String caseId,
                String scopeType,
                int expectedMetricCount,
                int actualMetricCount,
                int passedMetricCount,
                int failedMetricCount,
                int insufficientMetricCount,
                int notApplicableMetricCount,
                String finalDecision,
                boolean blocked,
                String blockReasonSummary,
                String promptHash,
                String contextHash,
                String contextHashState,
                String templateResourceId,
                String actualResourceId,
                String resourceUrlTemplate,
                String actualRequestPath,
                String httpMethod,
                Instant createdAt) {
            this(
                    aggregateRunId,
                    packageId,
                    certificateId,
                    caseId,
                    scopeType,
                    expectedMetricCount,
                    actualMetricCount,
                    passedMetricCount,
                    failedMetricCount,
                    insufficientMetricCount,
                    notApplicableMetricCount,
                    finalDecision,
                    blocked,
                    blockReasonSummary,
                    promptHash,
                    contextHash,
                    contextHashState,
                    templateResourceId,
                    actualResourceId,
                    resourceUrlTemplate,
                    actualRequestPath,
                    httpMethod,
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }
    }

    public record OperatorMetricSnapshot(
            String aggregateRunId,
            String officialRunId,
            String packageId,
            String certificateId,
            String caseId,
            String metricCode,
            String metricName,
            String metricGroup,
            double score,
            String state,
            String severity,
            int passedChecks,
            int totalChecks,
            int failedCheckCount,
            String operatorTitle,
            String operatorSummary,
            String primaryFailureReason,
            String remediationOwner,
            String nextAction,
            String reverifyCriterion,
            String diagnosticCatalogVersion,
            Instant createdAt) {
        public OperatorMetricSnapshot(
                String aggregateRunId,
                String officialRunId,
                String packageId,
                String certificateId,
                String caseId,
                String metricCode,
                String metricName,
                String metricGroup,
                double score,
                String state,
                String severity,
                int passedChecks,
                int totalChecks,
                int failedCheckCount,
                String operatorTitle,
                String operatorSummary,
                String primaryFailureReason,
                String remediationOwner,
                String nextAction,
                String reverifyCriterion,
                Instant createdAt) {
            this(
                    aggregateRunId,
                    officialRunId,
                    packageId,
                    certificateId,
                    caseId,
                    metricCode,
                    metricName,
                    metricGroup,
                    score,
                    state,
                    severity,
                    passedChecks,
                    totalChecks,
                    failedCheckCount,
                    operatorTitle,
                    operatorSummary,
                    primaryFailureReason,
                    remediationOwner,
                    nextAction,
                    reverifyCriterion,
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }
    }

    public record OperatorPurposeEvidence(
            String aggregateRunId,
            String packageId,
            String metricCode,
            String checkCode,
            String contractVersion,
            String signalKey,
            String promptLocation,
            String evidenceValue,
            String evidenceHash,
            String interpretation,
            String purposeResult,
            boolean customerVisible,
            String readinessScope,
            List<String> runtimeFacts,
            List<String> contextItems,
            Instant createdAt) {
        public OperatorPurposeEvidence {
            runtimeFacts = runtimeFacts == null ? List.of() : List.copyOf(runtimeFacts);
            contextItems = contextItems == null ? List.of() : List.copyOf(contextItems);
        }
    }

    public record OperatorFinding(
            String findingId,
            String aggregateRunId,
            String officialRunId,
            String packageId,
            String certificateId,
            String caseId,
            String issueId,
            String metricCode,
            String checkCode,
            String severity,
            String operatorTitle,
            String operatorSummary,
            String problemStatement,
            String rootCause,
            String affectedTarget,
            String operatorReason,
            String evidenceSummary,
            String evidencePath,
            String expectedValue,
            String actualValue,
            String expectedResult,
            String actualResult,
            String impact,
            String remediationOwner,
            String nextAction,
            String reverifyCriterion,
            String customerVisibleSeverity,
            String relatedProcessStep,
            String comparisonFieldKey,
            String comparisonState,
            String promptLocation,
            String diagnosticCatalogVersion,
            Instant createdAt) {
        public OperatorFinding(
                String findingId,
                String aggregateRunId,
                String officialRunId,
                String packageId,
                String certificateId,
                String caseId,
                String issueId,
                String metricCode,
                String checkCode,
                String severity,
                String operatorTitle,
                String operatorSummary,
                String problemStatement,
                String rootCause,
                String affectedTarget,
                String operatorReason,
                String evidenceSummary,
                String evidencePath,
                String expectedValue,
                String actualValue,
                String expectedResult,
                String actualResult,
                String impact,
                String remediationOwner,
                String nextAction,
                String reverifyCriterion,
                String customerVisibleSeverity,
                String relatedProcessStep,
                Instant createdAt) {
            this(
                    findingId, aggregateRunId, officialRunId,
                    packageId, certificateId, caseId,
                    issueId, metricCode, checkCode,

                    severity,
                    operatorTitle,
                    operatorSummary,
                    problemStatement,
                    rootCause,
                    affectedTarget,
                    operatorReason,
                    evidenceSummary,
                    evidencePath,
                    expectedValue,
                    actualValue,
                    expectedResult,
                    actualResult,
                    impact,
                    remediationOwner,
                    nextAction,
                    reverifyCriterion,
                    customerVisibleSeverity,
                    relatedProcessStep,
                    "",
                    "",
                    "",
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }

        public OperatorFinding(
                String findingId,
                String aggregateRunId,
                String officialRunId,
                String packageId,
                String certificateId,
                String caseId,
                String issueId,
                String metricCode,
                String checkCode,
                String severity,
                String operatorTitle,
                String operatorReason,
                String evidenceSummary,
                String evidencePath,
                String expectedValue,
                String actualValue,
                String impact,
                String remediationOwner,
                String nextAction,
                String reverifyCriterion,
                String relatedProcessStep,
                Instant createdAt) {
            this(
                    findingId, aggregateRunId, officialRunId,
                    packageId, certificateId, caseId,
                    issueId, metricCode, checkCode,

                    severity,
                    operatorTitle,
                    operatorReason,
                    operatorReason,
                    operatorReason,
                    remediationOwner,
                    operatorReason,
                    evidenceSummary,
                    evidencePath,
                    expectedValue,
                    actualValue,
                    expectedValue,
                    actualValue,
                    impact,
                    remediationOwner,
                    nextAction,
                    reverifyCriterion,
                    severity,
                    relatedProcessStep,
                    "",
                    "",
                    "",
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }
    }

    public record OperatorRemediationGroup(
            String groupId,
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            String rootCauseKey,
            String remediationOwner,
            String operatorTitle,
            String operatorReason,
            String nextAction,
            String reverifyCriterion,
            List<String> affectedMetricCodes,
            List<String> affectedCheckCodes,
            int findingCount,
            String relatedProcessStep,
            List<String> comparisonFieldKeys,
            List<String> promptLocations,
            String diagnosticCatalogVersion,
            Instant createdAt) {
        public OperatorRemediationGroup {
            affectedMetricCodes = affectedMetricCodes == null ? List.of() : List.copyOf(affectedMetricCodes);
            affectedCheckCodes = affectedCheckCodes == null ? List.of() : List.copyOf(affectedCheckCodes);
            comparisonFieldKeys = comparisonFieldKeys == null ? List.of() : List.copyOf(comparisonFieldKeys);
            promptLocations = promptLocations == null ? List.of() : List.copyOf(promptLocations);
        }

        public OperatorRemediationGroup(
                String groupId,
                String aggregateRunId,
                String packageId,
                String certificateId,
                String caseId,
                String rootCauseKey,
                String remediationOwner,
                String operatorTitle,
                String operatorReason,
                String nextAction,
                String reverifyCriterion,
                List<String> affectedMetricCodes,
                List<String> affectedCheckCodes,
                int findingCount,
                String relatedProcessStep,
                Instant createdAt) {
            this(
                    groupId,
                    aggregateRunId,
                    packageId,
                    certificateId,
                    caseId,
                    rootCauseKey,
                    remediationOwner,
                    operatorTitle,
                    operatorReason,
                    nextAction,
                    reverifyCriterion,
                    affectedMetricCodes,
                    affectedCheckCodes,
                    findingCount,
                    relatedProcessStep,
                    List.of(),
                    List.of(),
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }
    }

    public record OperatorAuditSnapshot(
            String snapshotId,
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            String state,
            String stateLabel,
            int totalMetricCount,
            int failedMetricCount,
            boolean certificateIssued,
            String promptHash,
            String contextHash,
            List<String> blockingFindings,
            List<String> nextActions,
            String payloadJson,
            String createdBy,
            String diagnosticCatalogVersion,
            Instant createdAt) {
        public OperatorAuditSnapshot {
            blockingFindings = blockingFindings == null ? List.of() : List.copyOf(blockingFindings);
            nextActions = nextActions == null ? List.of() : List.copyOf(nextActions);
        }

        public OperatorAuditSnapshot(
                String snapshotId,
                String aggregateRunId,
                String packageId,
                String certificateId,
                String caseId,
                String state,
                String stateLabel,
                int totalMetricCount,
                int failedMetricCount,
                boolean certificateIssued,
                String promptHash,
                String contextHash,
                List<String> blockingFindings,
                List<String> nextActions,
                String payloadJson,
                String createdBy,
                Instant createdAt) {
            this(
                    snapshotId,
                    aggregateRunId,
                    packageId,
                    certificateId,
                    caseId,
                    state,
                    stateLabel,
                    totalMetricCount,
                    failedMetricCount,
                    certificateIssued,
                    promptHash,
                    contextHash,
                    blockingFindings,
                    nextActions,
                    payloadJson,
                    createdBy,
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }
    }

    public record OperatorReverificationResult(
            String resultId,
            String sourcePackageId,
            String sourceAggregateRunId,
            String fixedPackageId,
            String fixedAggregateRunId,
            String sourceFindingId,
            String issueId,
            String metricCode,
            String checkCode,
            String reverifyCriterion,
            String sourceOperatorReason,
            String sourceExpectedValue,
            String sourceActualValue,
            String fixedActualValue,
            boolean resolved,
            String resolutionState,
            String operatorSummary,
            String createdBy,
            String diagnosticCatalogVersion,
            Instant createdAt) {
        public OperatorReverificationResult(
                String resultId,
                String sourcePackageId,
                String sourceAggregateRunId,
                String fixedPackageId,
                String fixedAggregateRunId,
                String sourceFindingId,
                String issueId,
                String metricCode,
                String checkCode,
                String reverifyCriterion,
                String sourceOperatorReason,
                String sourceExpectedValue,
                String sourceActualValue,
                String fixedActualValue,
                boolean resolved,
                String resolutionState,
                String operatorSummary,
                String createdBy,
                Instant createdAt) {
            this(
                    resultId,
                    sourcePackageId,
                    sourceAggregateRunId,
                    fixedPackageId,
                    fixedAggregateRunId,
                    sourceFindingId,
                    issueId,
                    metricCode,
                    checkCode,
                    reverifyCriterion,
                    sourceOperatorReason,
                    sourceExpectedValue,
                    sourceActualValue,
                    fixedActualValue,
                    resolved,
                    resolutionState,
                    operatorSummary,
                    createdBy,
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }
    }




}
