package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexacore.verification.persistence.VerificationLedgerService;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationEventItemView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricCheckContract;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContract;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationResult;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRuntime;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityAssuranceCaseService;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceCase;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceScope;
import io.contexa.contexaiam.admin.promptquality.official.process.NoopPromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessCodes;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessEventSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessHistorySnapshot;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessScope;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessStepSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorFinding;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunAttemptSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunCheckDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunEventDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunLedgerConsistency;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunMetricSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageListItem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunTechnicalLedger;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunRemediationGroup;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunSummaryCounts;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialMetricPurposeEvidence;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityCertificateService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityCertificateService.PromptQualityCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.concurrent.ConcurrentHashMap;
import java.util.LinkedHashSet;

public class DefaultPromptQualityOfficialRunDetailService implements PromptQualityOfficialRunDetailService {

    private static final Logger log = LoggerFactory.getLogger(DefaultPromptQualityOfficialRunDetailService.class);
    private static final Duration DETAIL_CACHE_TTL = Duration.ofSeconds(30);
    private static final int DETAIL_CACHE_MAX_SIZE = 128;
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final int PROMPT_PREVIEW_LIMIT = 900;
    private static final int TECHNICAL_LEDGER_MAP_ENTRY_LIMIT = 40;
    private static final int TECHNICAL_LEDGER_LIST_ENTRY_LIMIT = 20;
    private static final int TECHNICAL_LEDGER_STRING_LIMIT = 2000;
    private static final String LIGHTWEIGHT_EVIDENCE_SQL = """
            SELECT package_id,
                   correlation_id,
                   tenant_id,
                   user_id,
                   captured_at,
                   request_facts_json,
                   auth_state_json,
                   baseline_snapshot_json,
                   rag_results_json,
                   raw_system_prompt,
                   raw_user_prompt,
                   system_prompt_text,
                   user_prompt_text,
                   prompt_hash,
                   system_prompt_hash,
                   user_prompt_hash,
                   raw_system_prompt_hash,
                   raw_user_prompt_hash,
                   seal_state,
                   seal_failure_reason,
                   decision_json,
                   package_hash,
                   schema_version,
                   sealed,
                   expires_at,
                   created_at
              FROM sealed_evidence_package
             WHERE package_id = ?
            """;

    private static final Set<String> PASS_STATES = Set.of("SUCCESS", "PASS", "PASSED");
    private static final Set<String> NOT_APPLICABLE_STATES = Set.of("NOT_APPLICABLE", "NOT_APPLICABLE_METRIC");

    private final OfficialSealedEvidenceVerificationRuntime officialRuntime;
    private final VerificationLedgerService verificationLedgerService;
    private final PromptQualityRuntimeEvidenceService evidenceService;
    private final PromptQualityOfficialMetricCatalog metricCatalog;
    private final PromptQualityMessageResolver messageResolver;
    private final PromptQualityCertificateService certificateService;
    private final PromptQualityAssuranceCaseService assuranceCaseService;
    private final PromptQualityProcessRunService processRunService;
    private final OfficialVerificationOperatorSnapshotService operatorSnapshotService;
    private final JdbcOperations jdbcOperations;
    private final ObjectMapper objectMapper;
    private final RuntimeEvidencePromptConsistencyGate lightweightPromptConsistencyGate;
    private final FinalPromptMetricContractCatalog finalPromptMetricContracts =
            FinalPromptMetricContractCatalog.load(new ObjectMapper());
    private final ConcurrentHashMap<String, CachedOfficialRunPackageDetail> detailCache = new ConcurrentHashMap<>();

    public DefaultPromptQualityOfficialRunDetailService(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService verificationLedgerService,
            PromptQualityRuntimeEvidenceService evidenceService,
            PromptQualityOfficialMetricCatalog metricCatalog) {
        this(officialRuntime, verificationLedgerService, evidenceService, metricCatalog, null);
    }

    public DefaultPromptQualityOfficialRunDetailService(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService verificationLedgerService,
            PromptQualityRuntimeEvidenceService evidenceService,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityMessageResolver messageResolver) {
        this(officialRuntime, verificationLedgerService, evidenceService, metricCatalog, messageResolver, null, null);
    }

    public DefaultPromptQualityOfficialRunDetailService(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService verificationLedgerService,
            PromptQualityRuntimeEvidenceService evidenceService,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityMessageResolver messageResolver,
            PromptQualityCertificateService certificateService,
            PromptQualityAssuranceCaseService assuranceCaseService) {
        this(officialRuntime,
                verificationLedgerService,
                evidenceService,
                metricCatalog,
                messageResolver,
                certificateService,
                assuranceCaseService,
                null);
    }

    public DefaultPromptQualityOfficialRunDetailService(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService verificationLedgerService,
            PromptQualityRuntimeEvidenceService evidenceService,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityMessageResolver messageResolver,
            PromptQualityCertificateService certificateService,
            PromptQualityAssuranceCaseService assuranceCaseService,
            PromptQualityProcessRunService processRunService) {
        this(officialRuntime,
                verificationLedgerService,
                evidenceService,
                metricCatalog,
                messageResolver,
                certificateService,
                assuranceCaseService,
                processRunService,
                null);
    }

    public DefaultPromptQualityOfficialRunDetailService(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService verificationLedgerService,
            PromptQualityRuntimeEvidenceService evidenceService,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityMessageResolver messageResolver,
            PromptQualityCertificateService certificateService,
            PromptQualityAssuranceCaseService assuranceCaseService,
            PromptQualityProcessRunService processRunService,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService) {
        this(
                officialRuntime,
                verificationLedgerService,
                evidenceService,
                metricCatalog,
                messageResolver,
                certificateService,
                assuranceCaseService,
                processRunService,
                operatorSnapshotService,
                null);
    }

    public DefaultPromptQualityOfficialRunDetailService(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService verificationLedgerService,
            PromptQualityRuntimeEvidenceService evidenceService,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityMessageResolver messageResolver,
            PromptQualityCertificateService certificateService,
            PromptQualityAssuranceCaseService assuranceCaseService,
            PromptQualityProcessRunService processRunService,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            JdbcOperations jdbcOperations) {
        this.officialRuntime = officialRuntime;
        this.verificationLedgerService = verificationLedgerService;
        this.evidenceService = evidenceService;
        this.metricCatalog = metricCatalog;
        this.messageResolver = messageResolver;
        this.certificateService = certificateService;
        this.assuranceCaseService = assuranceCaseService;
        this.processRunService = processRunService == null ? new NoopPromptQualityProcessRunService() : processRunService;
        this.operatorSnapshotService = operatorSnapshotService;
        this.jdbcOperations = jdbcOperations;
        this.objectMapper = new ObjectMapper();
        this.lightweightPromptConsistencyGate = new DefaultRuntimeEvidencePromptConsistencyGate(
                this.objectMapper,
                null,
                messageResolver);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<OfficialRunPackageListItem> listRecentRunSummaries(int limit) {
        if (operatorSnapshotService == null) {
            return List.of();
        }
        return operatorSnapshotService.recentSnapshots(limit).stream()
                .filter(OperatorSnapshot::available)
                .map(snapshot -> listItem(snapshot.batch()))
                .toList();
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public OfficialRunPackageSummary findPackageSummary(String packageId, String aggregateRunId) {
        String normalizedPackageId = requireText(packageId, message(
                "enterprise.pqa.runtimeVerification.error.packageId.required",
                "Request evidence packageId is required."));
        OperatorSnapshot snapshot = operatorSnapshot(normalizedPackageId, aggregateRunId);
        if (snapshot.available()) {
            return summary(snapshot);
        }
        return OfficialRunPackageSummary.fromDetail(findPackageDetail(normalizedPackageId, aggregateRunId));
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<OfficialRunFailureCause> findFailureDetails(String packageId, String aggregateRunId) {
        String normalizedPackageId = requireText(packageId, message(
                "enterprise.pqa.runtimeVerification.error.packageId.required",
                "Request evidence packageId is required."));
        OperatorSnapshot snapshot = operatorSnapshot(normalizedPackageId, aggregateRunId);
        if (snapshot.available()) {
            return operatorFailureCauses(snapshot);
        }
        return findPackageDetail(normalizedPackageId, aggregateRunId).failureCauses();
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<OfficialRunAuditSnapshot> findAuditPayloads(String packageId, String aggregateRunId) {
        String normalizedPackageId = requireText(packageId, message(
                "enterprise.pqa.runtimeVerification.error.packageId.required",
                "Request evidence packageId is required."));
        OperatorSnapshot snapshot = operatorSnapshot(normalizedPackageId, aggregateRunId);
        if (snapshot.available()) {
            return snapshot.auditSnapshots().stream()
                    .map(this::storedAuditSnapshot)
                    .toList();
        }
        return findPackageDetail(normalizedPackageId, aggregateRunId).auditSnapshots();
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public OfficialRunPackageDetail findPackageDetail(String packageId) {
        return findPackageDetail(packageId, null);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public OfficialRunTechnicalLedger findTechnicalLedger(String packageId, String aggregateRunId) {
        return technicalLedger(findPackageDetail(packageId, aggregateRunId));
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public OfficialRunPackageDetail findPackageDetail(String packageId, String aggregateRunId) {
        String normalizedPackageId = requireText(packageId, message(
                "enterprise.pqa.runtimeVerification.error.packageId.required",
                "Request evidence packageId is required."));
        String normalizedAggregateRunId = StringUtils.hasText(aggregateRunId) ? aggregateRunId.trim() : null;
        String cacheKey = detailCacheKey(normalizedPackageId, normalizedAggregateRunId);
        OfficialRunPackageDetail cachedDetail = cachedDetail(cacheKey);
        if (cachedDetail != null) {
            return cachedDetail;
        }
        long startedNanos = System.nanoTime();
        long evidenceStartedNanos = startedNanos;
        RuntimeEvidencePackageDetail sealedEvidence = findOfficialEvidenceDetail(normalizedPackageId);
        long evidenceMs = elapsedMillis(evidenceStartedNanos);
        long ledgerStartedNanos = System.nanoTime();
        List<OfficialVerificationRunView> allPackageRuns =
                safeRunViews(verificationLedgerService.findMetricRunsByPackageId(normalizedPackageId));
        long ledgerMs = elapsedMillis(ledgerStartedNanos);
        long runtimeMs = 0L;
        OfficialSealedEvidenceVerificationResult officialResult = officialResultFromStoredRuns(
                normalizedPackageId,
                normalizedAggregateRunId,
                sealedEvidence,
                allPackageRuns);
        if (officialResult == null) {
            long runtimeStartedNanos = System.nanoTime();
            officialResult = officialRuntime.findByPackageId(normalizedPackageId);
            runtimeMs = elapsedMillis(runtimeStartedNanos);
        }
        if (StringUtils.hasText(normalizedAggregateRunId)) {
            List<OfficialVerificationRunView> selectedRuns = allPackageRuns.stream()
                    .filter(run -> same(normalizedAggregateRunId, firstNonBlank(raw(run.rawEvidence(), "aggregateRunId"), run.runId())))
                    .toList();
            if (!selectedRuns.isEmpty()) {
                officialResult = new OfficialSealedEvidenceVerificationResult(
                        normalizedAggregateRunId,
                        officialResult.packageId(),
                        officialResult.operatorId(),
                        officialResult.generatedAt(),
                        officialResult.integrityValid(),
                        selectedRuns);
            }
        }
        OperatorSnapshot operatorSnapshot = operatorSnapshot(
                normalizedPackageId,
                officialResult.aggregateRunId());
        List<? extends OfficialVerificationRunView> coreRuns = safeRuns(officialResult);
        final OperatorSnapshot selectedOperatorSnapshot = operatorSnapshot;
        String resolvedAggregateRunId = firstNonBlank(
                selectedOperatorSnapshot.available() ? selectedOperatorSnapshot.batch().aggregateRunId() : null,
                officialResult.aggregateRunId(),
                aggregateRunId);
        List<OperatorMetricSnapshot> operatorMetrics = safeOperatorMetrics(selectedOperatorSnapshot).stream()
                .filter(Objects::nonNull)
                .toList();
        List<OfficialVerificationMetricTrace> coreMetricRuns = coreRuns.stream()
                .sorted(Comparator.comparing(run -> normalize(run.endpointKey())))
                .map(run -> toMetricDetail(run, sealedEvidence, selectedOperatorSnapshot))
                .toList();
        List<OfficialVerificationMetricTrace> runs = operatorMetrics.size() > coreMetricRuns.size()
                ? operatorMetrics.stream()
                    .sorted(Comparator.comparing(metric -> normalize(metric.metricCode())))
                    .map(metric -> toMetricDetail(metric, sealedEvidence, selectedOperatorSnapshot))
                    .toList()
                : coreMetricRuns;
        List<OfficialRunFailureCause> runFailureCauses = runs.stream()
                .flatMap(run -> run.failureCauses().stream())
                .toList();
        List<OfficialRunFailureCause> operatorFailureCauses = operatorFailureCauses(selectedOperatorSnapshot);
        List<OfficialRunFailureCause> failureCauses = operatorFailureCauses.isEmpty()
                ? runFailureCauses
                : operatorFailureCauses;
        int passed = (int) runs.stream().filter(this::passed).count();
        int failed = (int) runs.stream().filter(this::failed).count();
        OfficialRunLedgerConsistency ledgerConsistency = ledgerConsistency(officialResult, runs);
        PromptQualityCertificate certificate = certificate(normalizedPackageId);
        PromptQualityAssuranceCase assuranceCase = assuranceCase(sealedEvidence, certificate);
        List<OfficialRunRemediationGroup> remediationGroups = operatorRemediationGroups(operatorSnapshot);
        List<String> nextActions = merge(
                groupNextActions(remediationGroups),
                merge(nextActions(failureCauses), certificate == null ? List.of() : certificate.recommendedActions()));
        PromptQualityProcessScope processScope = processScope(sealedEvidence, certificate);
        List<PromptQualityProcessStepSnapshot> processSteps = processRunService.steps(processScope);
        List<PromptQualityProcessHistorySnapshot> processHistory = processRunService.history(processScope);
        List<PromptQualityProcessEventSnapshot> processEvents = processRunService.events(processScope);
        List<OfficialRunAttemptSummary> attempts = attempts(
                allPackageRuns,
                resolvedAggregateRunId,
                normalizedPackageId);
        List<OfficialRunAuditSnapshot> auditSnapshots = auditSnapshots(
                normalizedPackageId,
                resolvedAggregateRunId,
                runs,
                sealedEvidence,
                certificate,
                assuranceCase,
                failureCauses,
                nextActions,
                processEvents,
                selectedOperatorSnapshot);
        List<OfficialVerificationPromptComparison> storedPromptComparisons =
                operatorSnapshotService == null
                        ? List.of()
                        : operatorSnapshotService.promptComparisons(normalizedPackageId, resolvedAggregateRunId);
        List<OfficialVerificationPromptComparison> promptComparisons = storedPromptComparisons == null
                ? List.of()
                : storedPromptComparisons;
        List<OfficialActualPromptProblem> actualPromptProblems = actualPromptProblems(selectedOperatorSnapshot);
        OfficialRunSummaryCounts summaryCounts = summaryCounts(runs, actualPromptProblems);
        String nextActionHref = nextActionHref(normalizedPackageId, resolvedAggregateRunId, summaryCounts);
        OfficialRunPackageDetail detail = new OfficialRunPackageDetail(
                normalizedPackageId,
                resolvedAggregateRunId,
                officialResult.integrityValid(),
                runs.size(),
                passed,
                failed,
                ledgerConsistency,
                sealedEvidence,
                runs,
                promptComparisons,
                actualPromptProblems,
                failureCauses,
                nextActions,
                nextActionHref,
                summaryCounts,
                remediationGroups,
                assuranceCase == null ? null : assuranceCase.caseId(),
                certificate == null ? null : certificate.certificateId(),
                certificate == null ? null : certificate.state(),
                certificate == null ? null : certificate.stateLabel(),
                certificate != null && certificate.usableForLlmZeroTrust(),
                certificate == null ? null : certificate.summary(),
                actualPromptProblemSummaries(actualPromptProblems),
                attempts,
                processSteps,
                processHistory,
                processEvents,
                auditSnapshots);
        cacheDetail(cacheKey, detail);
        logSlowPackageDetail(normalizedPackageId, resolvedAggregateRunId, startedNanos, evidenceMs, ledgerMs, runtimeMs, runs.size());
        return detail;
    }

    private OfficialRunTechnicalLedger technicalLedger(OfficialRunPackageDetail detail) {
        List<OfficialRunTechnicalLedger.Run> runs = detail.runs().stream()
                .map(run -> new OfficialRunTechnicalLedger.Run(
                        run.metricCode(),
                        run.officialRunId(),
                        run.state(),
                        run.passedChecks(),
                        run.totalChecks(),
                        limitedStringMap(run.requestFacts()),
                        limitedStringMap(run.promptFacts()),
                        limitedStringMap(run.analysisFacts()),
                        limitedObjectMap(run.rawEvidence())))
                .toList();
        return new OfficialRunTechnicalLedger(
                detail.packageId(),
                detail.aggregateRunId(),
                detail.totalRunCount(),
                true,
                runs);
    }

    private Map<String, String> limitedStringMap(Map<String, String> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        Map<String, String> result = new LinkedHashMap<>();
        int count = 0;
        for (Map.Entry<String, String> entry : source.entrySet()) {
            if (count++ >= TECHNICAL_LEDGER_MAP_ENTRY_LIMIT) {
                result.put("_truncated", "true");
                break;
            }
            result.put(entry.getKey(), truncateTechnicalValue(entry.getValue()));
        }
        return result;
    }

    private Map<String, Object> limitedObjectMap(Map<String, Object> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        return limitedObjectMap(source, 0);
    }

    private Map<String, Object> limitedObjectMap(Map<?, ?> source, int depth) {
        Map<String, Object> result = new LinkedHashMap<>();
        int count = 0;
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (count++ >= TECHNICAL_LEDGER_MAP_ENTRY_LIMIT) {
                result.put("_truncated", true);
                break;
            }
            result.put(String.valueOf(entry.getKey()), limitedTechnicalValue(entry.getValue(), depth + 1));
        }
        return result;
    }

    private Object limitedTechnicalValue(Object value, int depth) {
        if (value == null || value instanceof Number || value instanceof Boolean) {
            return value;
        }
        if (value instanceof CharSequence sequence) {
            return truncateTechnicalValue(sequence.toString());
        }
        if (depth >= 2) {
            return truncateTechnicalValue(String.valueOf(value));
        }
        if (value instanceof Map<?, ?> map) {
            return limitedObjectMap(map, depth);
        }
        if (value instanceof List<?> list) {
            List<Object> result = new ArrayList<>();
            int count = 0;
            for (Object item : list) {
                if (count++ >= TECHNICAL_LEDGER_LIST_ENTRY_LIMIT) {
                    result.add("[truncated " + (list.size() - TECHNICAL_LEDGER_LIST_ENTRY_LIMIT) + " items]");
                    break;
                }
                result.add(limitedTechnicalValue(item, depth + 1));
            }
            return result;
        }
        return truncateTechnicalValue(String.valueOf(value));
    }

    private String truncateTechnicalValue(String value) {
        if (value == null || value.length() <= TECHNICAL_LEDGER_STRING_LIMIT) {
            return value;
        }
        return value.substring(0, TECHNICAL_LEDGER_STRING_LIMIT) + "...[truncated "
                + (value.length() - TECHNICAL_LEDGER_STRING_LIMIT) + " chars]";
    }
    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public OfficialVerificationMetricTrace findRunDetail(String runId) {
        String normalizedRunId = requireText(runId, message(
                "enterprise.pqa.officialRun.error.runId.required",
                "Core official verification runId is required."));
        OfficialVerificationRunRecord record = verificationLedgerService.findRunRecord(null, normalizedRunId);
        if (record == null) {
            throw new IllegalArgumentException(message(
                    "enterprise.pqa.officialRun.error.run.notFoundTpl",
                    "Core official verification run was not found: {0}",
                    normalizedRunId));
        }
        OfficialVerificationRunView run = verificationLedgerService.findMetricRun(null, record.metricCode(), normalizedRunId);
        if (run == null) {
            throw new IllegalArgumentException(message(
                    "enterprise.pqa.officialRun.error.run.detailNotFoundTpl",
                    "Core official verification run detail was not found: {0}",
                    normalizedRunId));
        }
        String packageId = value(record.evidenceReferences(), "packageId");
        RuntimeEvidencePackageDetail sealedEvidence = StringUtils.hasText(packageId)
                ? findOfficialEvidenceDetail(packageId)
                : null;
        String aggregateRunId = firstNonBlank(raw(run.rawEvidence(), "aggregateRunId"), run.runId());
        OperatorSnapshot operatorSnapshot = StringUtils.hasText(packageId)
                ? operatorSnapshot(packageId, aggregateRunId)
                : OperatorSnapshot.empty();
        return toMetricDetail(run, sealedEvidence, operatorSnapshot);
    }

    private RuntimeEvidencePackageDetail findOfficialEvidenceDetail(String packageId) {
        if (jdbcOperations == null) {
            return evidenceService.findDetail(packageId);
        }
        try {
            SealedEvidencePackage pkg = jdbcOperations.queryForObject(
                    LIGHTWEIGHT_EVIDENCE_SQL,
                    lightweightEvidenceMapper(),
                    packageId);
            if (pkg == null) {
                return evidenceService.findDetail(packageId);
            }
            return toLightweightEvidenceDetail(pkg);
        }
        catch (DataAccessException exception) {
            log.warn("[PQA-OFFICIAL-DETAIL] Lightweight evidence lookup failed; falling back to full evidence detail. packageId={}",
                    packageId,
                    exception);
            return evidenceService.findDetail(packageId);
        }
    }

    private RowMapper<SealedEvidencePackage> lightweightEvidenceMapper() {
        return this::mapLightweightEvidence;
    }

    private SealedEvidencePackage mapLightweightEvidence(ResultSet rs, int rowNum) throws SQLException {
        SealedEvidencePackage pkg = new SealedEvidencePackage();
        pkg.setPackageId(rs.getString("package_id"));
        pkg.setCorrelationId(rs.getString("correlation_id"));
        pkg.setTenantId(rs.getString("tenant_id"));
        pkg.setUserId(rs.getString("user_id"));
        pkg.setCapturedAt(instant(rs, "captured_at"));
        pkg.setRequestFactsJson(rs.getString("request_facts_json"));
        pkg.setAuthStateJson(rs.getString("auth_state_json"));
        pkg.setBaselineSnapshotJson(rs.getString("baseline_snapshot_json"));
        pkg.setRagResultsJson(rs.getString("rag_results_json"));
        pkg.setRawSystemPrompt(rs.getString("raw_system_prompt"));
        pkg.setRawUserPrompt(rs.getString("raw_user_prompt"));
        pkg.setSystemPromptText(rs.getString("system_prompt_text"));
        pkg.setUserPromptText(rs.getString("user_prompt_text"));
        pkg.setPromptHash(rs.getString("prompt_hash"));
        pkg.setSystemPromptHash(rs.getString("system_prompt_hash"));
        pkg.setUserPromptHash(rs.getString("user_prompt_hash"));
        pkg.setRawSystemPromptHash(rs.getString("raw_system_prompt_hash"));
        pkg.setRawUserPromptHash(rs.getString("raw_user_prompt_hash"));
        pkg.setSealState(rs.getString("seal_state"));
        pkg.setSealFailureReason(rs.getString("seal_failure_reason"));
        pkg.setDecisionJson(rs.getString("decision_json"));
        pkg.setPackageHash(rs.getString("package_hash"));
        int schemaVersion = rs.getInt("schema_version");
        pkg.setSchemaVersion(rs.wasNull() ? 2 : schemaVersion);
        pkg.setSealed(rs.getBoolean("sealed"));
        pkg.setExpiresAt(instant(rs, "expires_at"));
        pkg.setCreatedAt(instant(rs, "created_at"));
        return pkg;
    }

    private RuntimeEvidencePackageDetail toLightweightEvidenceDetail(SealedEvidencePackage pkg) {
        Map<String, Object> requestFacts = parseJson(pkg.getRequestFactsJson());
        Map<String, Object> authState = parseJson(pkg.getAuthStateJson());
        Map<String, Object> promptMetadata = Map.of();
        Map<String, Object> decision = parseJson(pkg.getDecisionJson());
        Map<String, Object> baselineSnapshot = parseJson(pkg.getBaselineSnapshotJson());
        Map<String, Object> ragResults = parseJson(pkg.getRagResultsJson());
        boolean integrityValid = storedSealLooksValid(pkg);
        RuntimeEvidencePromptConsistencyResult promptConsistency = lightweightPromptConsistencyGate.evaluate(pkg);
        return new RuntimeEvidencePackageDetail(
                toLightweightSummary(pkg, requestFacts, promptMetadata, decision, integrityValid),
                StringUtils.hasText(pkg.getRawSystemPrompt()),
                StringUtils.hasText(pkg.getRawUserPrompt()),
                StringUtils.hasText(pkg.getSystemPromptText()),
                StringUtils.hasText(pkg.getUserPromptText()),
                StringUtils.hasText(pkg.getBaselineSnapshotJson()),
                StringUtils.hasText(pkg.getRagResultsJson()),
                promptPreview(pkg.getSystemPromptText()),
                promptPreview(pkg.getUserPromptText()),
                requestFacts,
                authState,
                promptMetadata,
                decision,
                baselineSnapshot,
                ragResults,
                List.of(),
                List.of(),
                qualityWarnings(pkg, integrityValid),
                promptConsistency,
                pkg.getSystemPromptText(),
                pkg.getUserPromptText());
    }

    private RuntimeEvidencePackageSummary toLightweightSummary(
            SealedEvidencePackage pkg,
            Map<String, Object> requestFacts,
            Map<String, Object> promptMetadata,
            Map<String, Object> decision,
            boolean integrityValid) {
        String requestPath = firstNonBlank(
                raw(requestFacts, "requestPath"),
                raw(requestFacts, "resourceUrl"),
                raw(requestFacts, "path"),
                raw(requestFacts, "uri"));
        String resourceId = firstNonBlank(
                raw(requestFacts, "protectableResourceId"),
                raw(promptMetadata, "protectableResourceId"),
                raw(requestFacts, "resourceId"),
                raw(requestFacts, "endpointKey"),
                raw(promptMetadata, "resourceId"),
                raw(promptMetadata, "endpointKey"),
                pkg.getPackageId());
        String httpMethod = firstNonBlank(raw(requestFacts, "httpMethod"), raw(requestFacts, "method"), "GET")
                .toUpperCase(Locale.ROOT);
        String stateLabel = integrityValid
                ? message("enterprise.pqa.runtimeEvidence.state.ready.label", "검사 가능")
                : message("enterprise.pqa.runtimeEvidence.state.integrityWarning.label", "증거 확인 필요");
        String nextAction = integrityValid
                ? message("enterprise.pqa.runtimeEvidence.state.ready.nextAction", "공식검사를 실행할 수 있습니다.")
                : message("enterprise.pqa.runtimeEvidence.state.integrityWarning.nextAction", "증거 봉인 상태를 확인하십시오.");
        return new RuntimeEvidencePackageSummary(
                pkg.getPackageId(),
                pkg.getCorrelationId(),
                pkg.getTenantId(),
                pkg.getUserId(),
                pkg.getCapturedAt(),
                requestPath,
                resourceId,
                httpMethod,
                firstNonBlank(raw(decision, "action"), raw(decision, "decisionAction")),
                doubleValue(decision, "confidence", "decisionConfidence"),
                pkg.isSealed(),
                integrityValid,
                pkg.getPromptHash(),
                promptTextLength(pkg),
                stateLabel,
                nextAction,
                integrityValid ? "READY" : "INTEGRITY_WARNING",
                null);
    }

    private List<String> qualityWarnings(SealedEvidencePackage pkg, boolean integrityValid) {
        return Stream.of(
                        StringUtils.hasText(pkg.getRawSystemPrompt()) ? null : message("enterprise.pqa.runtimeEvidence.warning.rawSystemPromptMissing", "Raw system prompt is not stored."),
                        StringUtils.hasText(pkg.getRawUserPrompt()) ? null : message("enterprise.pqa.runtimeEvidence.warning.rawUserPromptMissing", "Raw user prompt is not stored."),
                        StringUtils.hasText(pkg.getSystemPromptText()) ? null : message("enterprise.pqa.runtimeEvidence.warning.llmSystemPromptMissing", "System prompt sent to the LLM is missing."),
                        StringUtils.hasText(pkg.getUserPromptText()) ? null : message("enterprise.pqa.runtimeEvidence.warning.llmUserPromptMissing", "User prompt sent to the LLM is missing."),
                        integrityValid ? null : message("enterprise.pqa.runtimeEvidence.warning.integrityMismatch", "Evidence hash does not match."))
                .filter(StringUtils::hasText)
                .toList();
    }

    private Map<String, Object> parseJson(String json) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(json, MAP_TYPE);
            return parsed == null ? Map.of() : parsed;
        }
        catch (Exception ignored) {
            return Map.of();
        }
    }

    private Double doubleValue(Map<String, Object> map, String... keys) {
        if (map == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            Object value = map.get(key);
            if (value instanceof Number number) {
                return number.doubleValue();
            }
            if (value != null) {
                try {
                    return Double.parseDouble(String.valueOf(value));
                }
                catch (NumberFormatException ignored) {
                    // Try next key.
                }
            }
        }
        return null;
    }

    private int promptTextLength(SealedEvidencePackage pkg) {
        if (pkg == null) {
            return 0;
        }
        int systemLength = pkg.getSystemPromptText() == null ? 0 : pkg.getSystemPromptText().length();
        int userLength = pkg.getUserPromptText() == null ? 0 : pkg.getUserPromptText().length();
        return systemLength + userLength;
    }

    private String promptPreview(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String normalized = value.trim();
        return normalized.length() <= PROMPT_PREVIEW_LIMIT
                ? normalized
                : normalized.substring(0, PROMPT_PREVIEW_LIMIT) + "\n...";
    }

    private boolean storedSealLooksValid(SealedEvidencePackage pkg) {
        return pkg != null
                && pkg.isSealed()
                && StringUtils.hasText(pkg.getPackageHash())
                && !"FAILED".equalsIgnoreCase(firstNonBlank(pkg.getSealState(), "SEALED"));
    }

    private Instant instant(ResultSet rs, String column) throws SQLException {
        Timestamp timestamp = rs.getTimestamp(column);
        return timestamp == null ? null : timestamp.toInstant();
    }
    private OfficialSealedEvidenceVerificationResult officialResultFromStoredRuns(
            String packageId,
            String aggregateRunId,
            RuntimeEvidencePackageDetail sealedEvidence,
            List<OfficialVerificationRunView> allPackageRuns) {
        if (allPackageRuns == null || allPackageRuns.isEmpty()) {
            return null;
        }
        String resolvedAggregateRunId = null;
        List<OfficialVerificationRunView> selectedRuns = List.of();
        if (StringUtils.hasText(aggregateRunId)) {
            resolvedAggregateRunId = aggregateRunId.trim();
            String requestedAggregateRunId = resolvedAggregateRunId;
            selectedRuns = allPackageRuns.stream()
                    .filter(run -> same(requestedAggregateRunId, firstNonBlank(raw(run.rawEvidence(), "aggregateRunId"), run.runId())))
                    .toList();
        }
        if (selectedRuns.isEmpty()) {
            resolvedAggregateRunId = latestAggregateRunId(allPackageRuns);
            if (StringUtils.hasText(resolvedAggregateRunId)) {
                String latestRunId = resolvedAggregateRunId;
                selectedRuns = allPackageRuns.stream()
                        .filter(run -> same(latestRunId, firstNonBlank(raw(run.rawEvidence(), "aggregateRunId"), run.runId())))
                        .toList();
            }
            else {
                selectedRuns = List.copyOf(allPackageRuns);
            }
        }
        if (selectedRuns.isEmpty()) {
            return null;
        }
        RuntimeEvidencePackageSummary summary = sealedEvidence == null ? null : sealedEvidence.summary();
        boolean integrityValid = summary != null && summary.integrityValid();
        String operatorId = summary == null ? null : summary.userId();
        String generatedAt = selectedRuns.stream()
                .map(run -> firstNonBlank(run.completedAt(), run.startedAt()))
                .filter(StringUtils::hasText)
                .max(String::compareTo)
                .orElseGet(() -> Instant.now().toString());
        return new OfficialSealedEvidenceVerificationResult(
                resolvedAggregateRunId,
                packageId,
                firstNonBlank(operatorId, "stored-official-ledger"),
                generatedAt,
                integrityValid,
                selectedRuns);
    }

    private String latestAggregateRunId(List<OfficialVerificationRunView> runs) {
        if (runs == null || runs.isEmpty()) {
            return null;
        }
        String latestAggregateRunId = null;
        String latestCompletedAt = "";
        for (OfficialVerificationRunView run : runs) {
            if (run == null) {
                continue;
            }
            String aggregateRunId = firstNonBlank(raw(run.rawEvidence(), "aggregateRunId"), run.runId());
            String completedAt = firstNonBlank(run.completedAt(), run.startedAt());
            if (!StringUtils.hasText(latestAggregateRunId) || completedAt.compareTo(latestCompletedAt) >= 0) {
                latestAggregateRunId = aggregateRunId;
                latestCompletedAt = completedAt;
            }
        }
        return latestAggregateRunId;
    }

    private OfficialVerificationMetricTrace toMetricDetail(
            OfficialVerificationRunView run,
            RuntimeEvidencePackageDetail sealedEvidence,
            OperatorSnapshot operatorSnapshot) {
        OfficialVerificationMetricDefinition metric = metric(run.endpointKey());
        OperatorMetricSnapshot storedMetric = operatorMetric(operatorSnapshot, run.endpointKey());
        List<OfficialMetricPurposeEvidence> purposeEvidence = purposeEvidenceForMetric(operatorSnapshot, run.endpointKey());
        List<OfficialRunCheckDetail> checks = mergePurposeEvidenceChecks(
                run.endpointKey(),
                checks(run),
                purposeEvidence);
        int totalChecks = detailTotalChecks(
                checks,
                storedMetric == null ? run.totalChecks() : storedMetric.totalChecks());
        int passedChecks = detailPassedChecks(
                checks,
                storedMetric == null ? run.passedChecks() : storedMetric.passedChecks());
        List<OfficialRunFailureCause> operatorFailures = operatorFailureCauses(operatorSnapshot).stream()
                .filter(cause -> same(cause.metricCode(), run.endpointKey()))
                .toList();
        List<OfficialRunFailureCause> failures = operatorSnapshot != null && operatorSnapshot.available()
                ? operatorFailures
                : checks.stream()
                .filter(check -> !check.pass())
                .map(check -> failure(run, metric, check))
                .toList();
        return new OfficialVerificationMetricTrace(
                normalize(run.endpointKey()),
                metric == null ? run.endpointKey() : metric.metricName(),
                groupName(metric == null ? null : metric.category()),
                metricPurpose(run.endpointKey()),
                metricQualityQuestion(run.endpointKey()),
                firstNonBlank(storedMetric == null ? null : storedMetric.officialRunId(), run.runId()),
                run.requestId(),
                run.endpointLabel(),
                firstNonBlank(storedMetric == null ? null : storedMetric.state(), run.state()),
                stateLabel(firstNonBlank(storedMetric == null ? null : storedMetric.state(), run.state())),
                storedMetric == null ? run.score() : storedMetric.score(),
                passedChecks,
                totalChecks,
                run.processingTimeMs(),
                run.startedAt(),
                run.completedAt(),
                checks,
                safeMap(run.requestFacts()),
                safeMap(run.eventFacts()),
                safeMap(run.promptFacts()),
                safeMap(run.analysisFacts()),
                events(run),
                limitedObjectMap(run.rawEvidence()),
                comparisons(sealedEvidence, run, operatorSnapshot),
                actualPromptProblemsForMetric(operatorSnapshot, run.endpointKey()),
                failures,
                purposeEvidence,
                valueOrEmpty(storedMetric == null ? null : storedMetric.operatorTitle()),
                valueOrEmpty(storedMetric == null ? null : storedMetric.operatorSummary()),
                valueOrEmpty(storedMetric == null ? null : storedMetric.primaryFailureReason()),
                valueOrEmpty(storedMetric == null ? null : storedMetric.remediationOwner()),
                valueOrEmpty(storedMetric == null ? null : storedMetric.nextAction()),
                valueOrEmpty(storedMetric == null ? null : storedMetric.reverifyCriterion()));
    }

    private OfficialVerificationMetricTrace toMetricDetail(
            OperatorMetricSnapshot storedMetric,
            RuntimeEvidencePackageDetail sealedEvidence,
            OperatorSnapshot operatorSnapshot) {
        String metricCode = normalize(storedMetric.metricCode());
        OfficialVerificationMetricDefinition metric = metric(metricCode);
        List<OfficialMetricPurposeEvidence> purposeEvidence = purposeEvidenceForMetric(operatorSnapshot, metricCode);
        List<OfficialRunCheckDetail> checks = mergePurposeEvidenceChecks(metricCode, List.of(), purposeEvidence);
        List<OfficialRunFailureCause> failures = operatorFailureCauses(operatorSnapshot).stream()
                .filter(cause -> same(cause.metricCode(), metricCode))
                .toList();
        Map<String, String> requestFacts = sealedEvidenceFacts(sealedEvidence);
        Map<String, Object> rawEvidence = new LinkedHashMap<>();
        if (operatorSnapshot != null && operatorSnapshot.available()) {
            putIfObjectText(rawEvidence, "aggregateRunId", operatorSnapshot.batch().aggregateRunId());
            putIfObjectText(rawEvidence, "packageId", operatorSnapshot.batch().packageId());
            putIfObjectText(rawEvidence, "promptHash", operatorSnapshot.batch().promptHash());
            putIfObjectText(rawEvidence, "contextHash", operatorSnapshot.batch().contextHash());
            putIfObjectText(rawEvidence, "actualRequestPath", operatorSnapshot.batch().actualRequestPath());
            putIfObjectText(rawEvidence, "actualResourceId", operatorSnapshot.batch().actualResourceId());
            putIfObjectText(rawEvidence, "httpMethod", operatorSnapshot.batch().httpMethod());
        }
        return new OfficialVerificationMetricTrace(
                metricCode,
                firstNonBlank(storedMetric.metricName(), metric == null ? metricCode : metric.metricName()),
                firstNonBlank(storedMetric.metricGroup(), groupName(metric == null ? null : metric.category())),
                metricPurpose(metricCode),
                metricQualityQuestion(metricCode),
                storedMetric.officialRunId(),
                requestFacts.get("requestId"),
                firstNonBlank(
                        operatorSnapshot != null && operatorSnapshot.available() ? operatorSnapshot.batch().actualRequestPath() : null,
                        sealedEvidence == null || sealedEvidence.summary() == null ? null : sealedEvidence.summary().requestPath()),
                storedMetric.state(),
                stateLabel(storedMetric.state()),
                storedMetric.score(),
                detailPassedChecks(checks, storedMetric.passedChecks()),
                detailTotalChecks(checks, storedMetric.totalChecks()),
                null,
                storedMetric.createdAt() == null ? null : storedMetric.createdAt().toString(),
                storedMetric.createdAt() == null ? null : storedMetric.createdAt().toString(),
                checks,
                requestFacts,
                Map.of(),
                sealedEvidencePromptFacts(sealedEvidence, operatorSnapshot),
                Map.of(
                        "sourceMode", "OFFICIAL_OPERATOR_SNAPSHOT",
                        "metricCode", metricCode),
                List.of(),
                Map.copyOf(rawEvidence),
                comparisons(sealedEvidence, metricCode, operatorSnapshot),
                actualPromptProblemsForMetric(operatorSnapshot, metricCode),
                failures,
                purposeEvidence,
                valueOrEmpty(storedMetric.operatorTitle()),
                valueOrEmpty(storedMetric.operatorSummary()),
                valueOrEmpty(storedMetric.primaryFailureReason()),
                valueOrEmpty(storedMetric.remediationOwner()),
                valueOrEmpty(storedMetric.nextAction()),
                valueOrEmpty(storedMetric.reverifyCriterion()));
    }

    private int detailTotalChecks(List<OfficialRunCheckDetail> checks, int fallback) {
        if (checks != null && !checks.isEmpty()) {
            return checks.size();
        }
        return Math.max(fallback, 0);
    }

    private int detailPassedChecks(List<OfficialRunCheckDetail> checks, int fallback) {
        if (checks != null && !checks.isEmpty()) {
            return (int) checks.stream()
                    .filter(Objects::nonNull)
                    .filter(OfficialRunCheckDetail::pass)
                    .count();
        }
        return Math.max(fallback, 0);
    }

    private String metricPurpose(String metricCode) {
        try {
            FinalPromptMetricContract contract = finalPromptMetricContracts.metric(metricCode);
            return contract.purpose();
        }
        catch (RuntimeException exception) {
            return "";
        }
    }

    private String metricQualityQuestion(String metricCode) {
        try {
            FinalPromptMetricContract contract = finalPromptMetricContracts.metric(metricCode);
            return contract.qualityQuestion();
        }
        catch (RuntimeException exception) {
            return "";
        }
    }

    private FinalPromptMetricCheckContract metricCheckContract(String metricCode, String checkCode) {
        if (!StringUtils.hasText(metricCode) || !StringUtils.hasText(checkCode)) {
            return null;
        }
        try {
            return finalPromptMetricContracts.check(metricCode, checkCode);
        }
        catch (RuntimeException exception) {
            return null;
        }
    }

    private List<OfficialActualPromptProblem> actualPromptProblems(OperatorSnapshot snapshot) {
        if (snapshot == null || !snapshot.available()) {
            return List.of();
        }
        return snapshot.actualPromptProblems();
    }

    private List<String> actualPromptProblemSummaries(List<OfficialActualPromptProblem> problems) {
        if (problems == null || problems.isEmpty()) {
            return List.of();
        }
        return problems.stream()
                .filter(problem -> problem != null && "BLOCKING".equalsIgnoreCase(valueOrEmpty(problem.severity())))
                .map(problem -> firstNonBlank(problem.promptLabel(), problem.fieldKey(), "final userPrompt issue")
                        + ": " + firstNonBlank(problem.whyItMatters(), problem.actualState(), problem.problemType(), "review required"))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private List<OperatorMetricSnapshot> safeOperatorMetrics(OperatorSnapshot snapshot) {
        if (snapshot == null || !snapshot.available() || snapshot.metrics() == null) {
            return List.of();
        }
        return snapshot.metrics();
    }

    private List<OfficialActualPromptProblem> actualPromptProblemsForMetric(
            OperatorSnapshot snapshot,
            String metricCode) {
        String normalizedMetric = normalize(metricCode);
        if (!StringUtils.hasText(normalizedMetric)) {
            return List.of();
        }
        return actualPromptProblems(snapshot).stream()
                .filter(problem -> problem.metricCodes().stream().anyMatch(code -> same(code, normalizedMetric)))
                .toList();
    }

    private List<OfficialActualPromptProblem> actualPromptProblemsForMetric(
            List<OfficialActualPromptProblem> problems,
            String metricCode) {
        String normalizedMetric = normalize(metricCode);
        if (!StringUtils.hasText(normalizedMetric) || problems == null || problems.isEmpty()) {
            return List.of();
        }
        return problems.stream()
                .filter(Objects::nonNull)
                .filter(problem -> problem.metricCodes().stream().anyMatch(code -> same(code, normalizedMetric)))
                .toList();
    }

    private OfficialRunSummaryCounts summaryCounts(
            List<OfficialVerificationMetricTrace> runs,
            List<OfficialActualPromptProblem> actualPromptProblems) {
        List<OfficialVerificationMetricTrace> safeRuns = runs == null ? List.of() : runs.stream()
                .filter(Objects::nonNull)
                .toList();
        List<OfficialActualPromptProblem> safeProblems = actualPromptProblems == null ? List.of() : actualPromptProblems.stream()
                .filter(Objects::nonNull)
                .toList();
        Set<String> blockedMetricCodes = safeProblems.stream()
                .flatMap(problem -> problem.metricCodes().stream())
                .map(this::normalize)
                .filter(StringUtils::hasText)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        int technicalTotal = 0;
        int technicalPassed = 0;
        int criteriaFailed = 0;
        int gateConditions = 0;
        int inputReviewMetrics = 0;
        int inputReadinessChecks = 0;
        int gateMetrics = 0;
        int otherFailed = 0;
        int technicalFailed = 0;
        for (OfficialVerificationMetricTrace run : safeRuns) {
            int actualProblemCount = actualPromptProblemsForMetric(safeProblems, run.metricCode()).size();
            MetricSummarySplit split = metricSummarySplit(run, actualProblemCount);
            technicalTotal += split.technicalTotal();
            technicalPassed += split.technicalPassed();
            criteriaFailed += split.criteriaFailed();
            if (split.gateFailed() > 0) {
                gateConditions += split.gateFailed();
                gateMetrics += 1;
            }
            if (split.inputFailed() > 0) {
                inputReviewMetrics += 1;
                inputReadinessChecks += split.inputFailed();
            }
            otherFailed += split.otherFailed();
            technicalFailed += split.gateFailed() + split.otherFailed();
        }
        return new OfficialRunSummaryCounts(
                safeProblems.size(),
                blockedMetricCodes.size(),
                technicalTotal,
                technicalPassed,
                technicalFailed,
                gateConditions,
                inputReviewMetrics,
                inputReadinessChecks,
                criteriaFailed,
                gateMetrics,
                otherFailed);
    }

    private String nextActionHref(String packageId, String aggregateRunId, OfficialRunSummaryCounts counts) {
        if (!StringUtils.hasText(packageId) || counts == null) {
            return null;
        }
        String path = null;
        if (counts.actualProblems() > 0
                || counts.inputReviewMetrics() > 0
                || counts.inputReadinessChecks() > 0
                || counts.gateConditions() > 0
                || counts.gateMetrics() > 0) {
            path = "/contexa/admin/prompt-quality/verification/metrics";
        }
        if (!StringUtils.hasText(path)) {
            return null;
        }
        StringBuilder href = new StringBuilder(path)
                .append("?packageId=")
                .append(urlEncode(packageId));
        if (StringUtils.hasText(aggregateRunId)) {
            href.append("&aggregateRunId=").append(urlEncode(aggregateRunId));
        }
        return href.toString();
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private MetricSummarySplit metricSummarySplit(OfficialVerificationMetricTrace run, int actualProblemCount) {
        if (run == null || (metricNotApplicable(run) && actualProblemCount == 0)) {
            return MetricSummarySplit.empty();
        }
        List<OfficialRunCheckDetail> allChecks = run.checks() == null
                ? List.of()
                : run.checks().stream()
                        .filter(Objects::nonNull)
                        .toList();
        List<OfficialRunCheckDetail> checks = evaluatedChecks(run);
        int technicalTotal = Math.max(Math.max(run.totalChecks(), 0), allChecks.size());
        int allPassed = (int) allChecks.stream().filter(OfficialRunCheckDetail::pass).count();
        int technicalPassed = Math.max(Math.max(run.passedChecks(), 0), allPassed);
        int failed = Math.max(technicalTotal - technicalPassed, 0);
        int inputFailed = 0;
        int gateFailed = 0;
        int otherFailed = 0;
        int countedFailed = 0;
        for (OfficialRunCheckDetail check : checks) {
            if (check.pass()) {
                continue;
            }
            countedFailed++;
            List<OfficialMetricPurposeEvidence> evidence = purposeEvidenceForCheck(run, check);
            if (hasScope(evidence, "CUSTOMER_PROMPT_QUALITY", true)) {
                continue;
            }
            if (hasScope(evidence, "INPUT_READINESS", false)) {
                inputFailed++;
            } else if (hasScope(evidence, "INTERNAL_EXECUTION_GATE", false)) {
                gateFailed++;
            } else {
                otherFailed++;
            }
        }
        int fallbackFailed = Math.max(failed - countedFailed, 0);
        otherFailed += fallbackFailed;
        return new MetricSummarySplit(
                technicalTotal,
                technicalPassed,
                failed,
                inputFailed,
                gateFailed,
                otherFailed);
    }

    private boolean metricNotApplicable(OfficialVerificationMetricTrace run) {
        if (run == null) {
            return false;
        }
        String state = normalize(run.state());
        if ("NOT_APPLICABLE".equals(state) || "NOT_APPLICABLE_METRIC".equals(state)) {
            return true;
        }
        List<OfficialRunCheckDetail> checks = run.checks() == null ? List.of() : run.checks();
        if (checks.isEmpty()) {
            return false;
        }
        return checks.stream().filter(Objects::nonNull).anyMatch(check -> isNotApplicableCheck(run, check))
                && evaluatedChecks(run).isEmpty();
    }

    private List<OfficialRunCheckDetail> evaluatedChecks(OfficialVerificationMetricTrace run) {
        if (run == null || run.checks() == null || run.checks().isEmpty()) {
            return List.of();
        }
        return run.checks().stream()
                .filter(Objects::nonNull)
                .filter(check -> !isNotApplicableCheck(run, check))
                .filter(check -> purposeEvidenceForCheck(run, check).stream()
                        .noneMatch(evidence -> "INTERNAL_REFERENCE".equals(normalize(evidence.readinessScope()))))
                .toList();
    }

    private boolean isNotApplicableCheck(OfficialVerificationMetricTrace run, OfficialRunCheckDetail check) {
        List<OfficialMetricPurposeEvidence> evidence = purposeEvidenceForCheck(run, check);
        return !evidence.isEmpty() && evidence.stream()
                .allMatch(item -> "NOT_APPLICABLE".equals(normalize(item.purposeResult()))
                        || "NOT_APPLICABLE".equals(normalize(item.readinessScope())));
    }

    private List<OfficialMetricPurposeEvidence> purposeEvidenceForCheck(
            OfficialVerificationMetricTrace run,
            OfficialRunCheckDetail check) {
        String metricCode = normalize(run == null ? null : run.metricCode());
        String checkCode = normalize(check == null ? null : check.checkCode());
        if (run == null || run.purposeEvidence() == null || run.purposeEvidence().isEmpty()) {
            return List.of();
        }
        return run.purposeEvidence().stream()
                .filter(Objects::nonNull)
                .filter(evidence -> (!StringUtils.hasText(metricCode) || same(evidence.metricCode(), metricCode))
                        && (!StringUtils.hasText(checkCode)
                                || metricCheckCodesMatch(metricCode, checkCode, evidence.checkCode())))
                .toList();
    }

    private boolean hasScope(List<OfficialMetricPurposeEvidence> evidence, String scope, boolean customerVisibleRequired) {
        String normalizedScope = normalize(scope);
        return evidence != null && evidence.stream()
                .filter(Objects::nonNull)
                .anyMatch(item -> (!customerVisibleRequired || item.customerVisible())
                        && normalizedScope.equals(normalize(item.readinessScope())));
    }

    private boolean metricCheckCodesMatch(String metricCode, String runCheckCode, String evidenceCheckCode) {
        String runCode = normalize(runCheckCode);
        String evidenceCode = normalize(evidenceCheckCode);
        if (!StringUtils.hasText(runCode) || !StringUtils.hasText(evidenceCode)) {
            return false;
        }
        if (runCode.equals(evidenceCode)) {
            return true;
        }
        String metric = normalize(metricCode);
        return StringUtils.hasText(metric)
                && stripMetricPrefix(metric, runCode).equals(stripMetricPrefix(metric, evidenceCode));
    }

    private String stripMetricPrefix(String metricCode, String checkCode) {
        String metric = normalize(metricCode);
        String code = normalize(checkCode);
        String prefix = metric + "_";
        return StringUtils.hasText(metric) && code.startsWith(prefix) ? code.substring(prefix.length()) : code;
    }

    private record MetricSummarySplit(
            int technicalTotal,
            int technicalPassed,
            int criteriaFailed,
            int inputFailed,
            int gateFailed,
            int otherFailed) {

        static MetricSummarySplit empty() {
            return new MetricSummarySplit(0, 0, 0, 0, 0, 0);
        }
    }

    private List<OfficialMetricPurposeEvidence> purposeEvidenceForMetric(
            OperatorSnapshot snapshot,
            String metricCode) {
        String normalizedMetric = normalize(metricCode);
        if (snapshot == null || !snapshot.available() || !StringUtils.hasText(normalizedMetric)
                || snapshot.purposeEvidence() == null) {
            return List.of();
        }
        return snapshot.purposeEvidence().stream()
                .filter(evidence -> evidence != null
                        && same(evidence.metricCode(), normalizedMetric))
                .map(this::purposeEvidence)
                .toList();
    }

    private OfficialMetricPurposeEvidence purposeEvidence(OperatorPurposeEvidence evidence) {
        FinalPromptMetricCheckContract contract = metricCheckContract(evidence.metricCode(), evidence.checkCode());
        boolean passed = purposeEvidencePassed(evidence.purposeResult());
        return new OfficialMetricPurposeEvidence(
                valueOrEmpty(evidence.metricCode()),
                valueOrEmpty(evidence.checkCode()),
                valueOrEmpty(evidence.contractVersion()),
                firstNonBlank(contract == null ? null : contract.qualityQuestion(), evidence.signalKey()),
                valueOrEmpty(evidence.promptLocation()),
                firstNonBlank(
                        passed ? contract == null ? null : contract.passMessage() : contract == null ? null : contract.failureMessage(),
                        evidence.evidenceValue()),
                valueOrEmpty(evidence.evidenceHash()),
                firstNonBlank(contract == null ? null : contract.whyItMatters(), evidence.interpretation()),
                valueOrEmpty(evidence.purposeResult()),
                evidence.customerVisible(),
                valueOrEmpty(evidence.readinessScope()),
                evidence.runtimeFacts(),
                evidence.contextItems());
    }

    private Map<String, String> sealedEvidenceFacts(RuntimeEvidencePackageDetail sealedEvidence) {
        Map<String, String> facts = new LinkedHashMap<>();
        if (sealedEvidence == null) {
            return Map.of();
        }
        if (sealedEvidence.summary() != null) {
            putIfText(facts, "packageId", sealedEvidence.summary().packageId());
            putIfText(facts, "requestId", firstNonBlank(
                    objectText(sealedEvidence.requestFacts(), "requestId"),
                    sealedEvidence.summary().correlationId()));
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

    private Map<String, String> sealedEvidencePromptFacts(
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

    private void putIfText(Map<String, String> target, String key, String value) {
        if (target != null && StringUtils.hasText(key) && StringUtils.hasText(value)) {
            target.put(key, value.trim());
        }
    }

    private void putIfObjectText(Map<String, Object> target, String key, String value) {
        if (target != null && StringUtils.hasText(key) && StringUtils.hasText(value)) {
            target.put(key, value.trim());
        }
    }

    private String objectText(Map<String, Object> source, String key) {
        if (source == null || !StringUtils.hasText(key)) {
            return null;
        }
        Object value = source.get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return StringUtils.hasText(text) ? text : null;
    }

    private OperatorMetricSnapshot operatorMetric(OperatorSnapshot snapshot, String metricCode) {
        if (snapshot == null || !snapshot.available()) {
            return null;
        }
        return snapshot.metrics().stream()
                .filter(Objects::nonNull)
                .filter(metric -> same(metric.metricCode(), metricCode))
                .findFirst()
                .orElse(null);
    }

    private List<OfficialRunCheckDetail> checks(OfficialVerificationRunView run) {
        List<? extends OfficialVerificationCheckResultView> source = run.checks();
        if (source == null || source.isEmpty()) {
            return List.of();
        }
        List<OfficialRunCheckDetail> result = new ArrayList<>();
        for (int i = 0; i < source.size(); i++) {
            OfficialVerificationCheckResultView check = source.get(i);
            if (check == null) {
                continue;
            }
            String evidenceSource = StringUtils.hasText(check.source()) ? check.source().trim() : "MISSING_SOURCE";
            FinalPromptMetricCheckContract contract = metricCheckContract(run.endpointKey(), check.checkCode());
            String label = firstNonBlank(contract == null ? null : contract.qualityQuestion(), check.label());
            String expected = firstNonBlank(contract == null ? null : contract.expectedMessage(), check.expectedValue());
            String actual = check.pass()
                    ? firstNonBlank(contract == null ? null : contract.passMessage(), check.actualValue())
                    : firstNonBlank(check.actualValue(), contract == null ? null : contract.failureMessage());
            String nextAction = firstNonBlank(contract == null ? null : contract.nextAction(), check.nextAction());
            String reverify = firstNonBlank(contract == null ? null : contract.reverifyCriterion(), check.reverifyCriterion());
            String whyItMatters = firstNonBlank(contract == null ? null : contract.whyItMatters(), check.whyItMatters());
            result.add(new OfficialRunCheckDetail(
                    i + 1,
                    check.checkCode(),
                    label,
                    expected,
                    actual,
                    check.pass(),
                    evidenceSource,
                    check.severity(),
                    firstNonBlank(contract == null ? null : contract.failureType(), check.failureType()),
                    firstNonBlank(contract == null ? null : contract.remediationOwner(), check.remediationOwner()),
                    firstNonBlank(check.operatorReason(), actual),
                    nextAction,
                    sourceMeaning(evidenceSource),
                    firstNonBlank(nextAction, remediationHint(label, evidenceSource)),
                    firstNonBlank(reverify, reverifyCriterion(label)),
                    check.decisionUtility(),
                    whyItMatters));
        }
        return List.copyOf(result);
    }

    private List<OfficialRunCheckDetail> customerVisibleChecks(
            String metricCode,
            List<OfficialRunCheckDetail> checks,
            List<OfficialMetricPurposeEvidence> purposeEvidence) {
        if (checks == null || checks.isEmpty() || purposeEvidence == null || purposeEvidence.isEmpty()) {
            return checks == null ? List.of() : checks;
        }
        String metric = normalize(metricCode);
        return checks.stream()
                .filter(Objects::nonNull)
                .filter(check -> {
                    List<OfficialMetricPurposeEvidence> matchedEvidence = purposeEvidence.stream()
                            .filter(Objects::nonNull)
                            .filter(evidence -> (!StringUtils.hasText(metric) || same(evidence.metricCode(), metric))
                                    && metricCheckCodesMatch(metric, check.checkCode(), evidence.checkCode()))
                            .toList();
                    if (matchedEvidence.isEmpty()) {
                        return true;
                    }
                    return matchedEvidence.stream().anyMatch(OfficialMetricPurposeEvidence::customerVisible)
                            && matchedEvidence.stream()
                            .noneMatch(evidence -> "INTERNAL_REFERENCE".equals(normalize(evidence.readinessScope())));
                })
                .toList();
    }

    private List<OfficialRunCheckDetail> mergePurposeEvidenceChecks(
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
            if (!StringUtils.hasText(checkCode) || existing.contains(checkCode)) {
                continue;
            }
            result.add(purposeEvidenceCheck(sequence++, evidence));
            existing.add(checkCode);
        }
        return List.copyOf(result);
    }

    private OfficialRunCheckDetail purposeEvidenceCheck(int sequence, OfficialMetricPurposeEvidence evidence) {
        boolean passed = purposeEvidencePassed(evidence);
        FinalPromptMetricCheckContract contract = metricCheckContract(evidence.metricCode(), evidence.checkCode());
        String label = firstNonBlank(contract == null ? null : contract.qualityQuestion(), evidence.signalKey(), evidence.checkCode());
        String expectedValue = firstNonBlank(contract == null ? null : contract.expectedMessage(), label);
        String actualValue = firstNonBlank(
                passed ? contract == null ? null : contract.passMessage() : contract == null ? null : contract.failureMessage(),
                evidence.evidenceValue(),
                String.join(" ", evidence.runtimeFacts()));
        String source = firstNonBlank(evidence.promptLocation(), evidence.readinessScope(), "purposeEvidence");
        return new OfficialRunCheckDetail(
                sequence,
                evidence.checkCode(),
                label,
                expectedValue,
                actualValue,
                passed,
                source,
                firstNonBlank(contract == null ? null : contract.severity(), passed ? "INFO" : "BLOCKING"),
                firstNonBlank(contract == null ? null : contract.failureType(), passed ? "" : "OFFICIAL_CHECK_FAILED"),
                firstNonBlank(contract == null ? null : contract.remediationOwner(), evidence.readinessScope(), "PQA_RUNTIME"),
                actualValue,
                firstNonBlank(contract == null ? null : contract.nextAction(), ""),
                "",
                firstNonBlank(contract == null ? null : contract.nextAction(), ""),
                firstNonBlank(contract == null ? null : contract.reverifyCriterion(), ""),
                "",
                firstNonBlank(contract == null ? null : contract.whyItMatters(), evidence.interpretation(), evidence.evidenceValue()));
    }

    private boolean purposeEvidencePassed(OfficialMetricPurposeEvidence evidence) {
        return purposeEvidencePassed(evidence == null ? null : evidence.purposeResult());
    }

    private boolean purposeEvidencePassed(String purposeResult) {
        String result = normalize(purposeResult);
        return "PURPOSE_PASSED".equals(result) || "PASSED".equals(result) || "PASS".equals(result);
    }

    private List<OfficialVerificationPromptComparison> comparisons(
            RuntimeEvidencePackageDetail sealedEvidence,
            String metricCode,
            OperatorSnapshot operatorSnapshot) {
        if (operatorSnapshotService == null
                || sealedEvidence == null
                || sealedEvidence.summary() == null
                || !StringUtils.hasText(sealedEvidence.summary().packageId())) {
            return List.of();
        }
        String aggregateRunId = operatorSnapshot != null && operatorSnapshot.available()
                ? operatorSnapshot.batch().aggregateRunId()
                : null;
        List<OfficialVerificationPromptComparison> stored = operatorSnapshotService.promptComparisons(
                sealedEvidence.summary().packageId(),
                aggregateRunId);
        if (stored == null || stored.isEmpty()) {
            return List.of();
        }
        String normalizedMetric = normalize(metricCode);
        return stored.stream()
                .filter(comparison -> comparison.metricCodes().stream()
                        .anyMatch(code -> same(code, normalizedMetric)))
                .toList();
    }

    private List<OfficialRunEventDetail> events(OfficialVerificationRunView run) {
        List<? extends OfficialVerificationEventItemView> source = run.events();
        if (source == null || source.isEmpty()) {
            return List.of();
        }
        List<OfficialRunEventDetail> result = new ArrayList<>();
        for (int i = 0; i < source.size(); i++) {
            OfficialVerificationEventItemView event = source.get(i);
            result.add(new OfficialRunEventDetail(
                    i + 1,
                    event.type(),
                    event.layer(),
                    event.status(),
                    event.requestPath()));
        }
        return List.copyOf(result);
    }

    private List<OfficialVerificationPromptComparison> comparisons(
            RuntimeEvidencePackageDetail sealedEvidence,
            OfficialVerificationRunView run,
            OperatorSnapshot operatorSnapshot) {
        if (operatorSnapshotService != null
                && sealedEvidence != null
                && sealedEvidence.summary() != null
                && StringUtils.hasText(sealedEvidence.summary().packageId())) {
            String aggregateRunId = firstNonBlank(raw(run == null ? null : run.rawEvidence(), "aggregateRunId"),
                    run == null ? null : run.runId());
            List<OfficialVerificationPromptComparison> stored = operatorSnapshotService.promptComparisons(
                    sealedEvidence.summary().packageId(),
                    aggregateRunId);
            if (stored == null || stored.isEmpty()) {
                return List.of();
            }
            List<OfficialVerificationPromptComparison> metricScoped = stored.stream()
                    .filter(comparison -> comparison.metricCodes().stream()
                            .anyMatch(metricCode -> same(metricCode, run == null ? null : run.endpointKey())))
                    .toList();
            if (!metricScoped.isEmpty()) {
                return metricScoped;
            }
            if (!stored.isEmpty()) {
                return List.of();
            }
            return List.of();
        }
        return List.of();
    }

    private OfficialVerificationPromptComparison runComparison(
            String key,
            String label,
            String sealedValue,
            String officialValue,
            String promptValue,
            OfficialVerificationRunView run) {
        return compare(
                key,
                label,
                sealedValue,
                officialValue,
                promptValue,
                metricCodesFor(key, run),
                promptLocation(key),
                evidenceSource(key),
                recommendedOwner(key));
    }

    private OfficialVerificationPromptComparison compare(
            String key,
            String label,
            String sealedValue,
            String officialValue,
            String promptValue,
            List<String> metricCodes,
            String promptLocation,
            String evidenceSource,
            String recommendedOwner) {
        String sealed = clean(sealedValue);
        String official = clean(officialValue);
        String prompt = clean(promptValue);
        String state;
        if (!StringUtils.hasText(sealed) && !StringUtils.hasText(official) && !StringUtils.hasText(prompt)) {
            state = "NOT_APPLICABLE";
        }
        else if (StringUtils.hasText(sealed) && !StringUtils.hasText(prompt)) {
            state = "PROMPT_MISSING";
        }
        else if (StringUtils.hasText(sealed) && !StringUtils.hasText(official)) {
            state = "FACT_MISSING";
        }
        else if (StringUtils.hasText(sealed)
                && StringUtils.hasText(official)
                && StringUtils.hasText(prompt)
                && same(sealed, official)
                && same(sealed, prompt)) {
            state = "MATCH";
        }
        else {
            state = "VALUE_MISMATCH";
        }
        return new OfficialVerificationPromptComparison(
                key,
                label,
                display(sealed),
                display(prompt),
                display(official),
                state,
                comparisonLabel(state),
                comparisonMeaning(label, state),
                metricCodes == null ? List.of() : List.copyOf(metricCodes),
                promptLocation,
                evidenceSource,
                recommendedOwner);
    }

    private OfficialRunFailureCause failure(
            OfficialVerificationRunView run,
            OfficialVerificationMetricDefinition metric,
            OfficialRunCheckDetail check) {
        return new OfficialRunFailureCause(
                normalize(run.endpointKey()),
                metric == null ? run.endpointKey() : metric.metricName(),
                run.runId(),
                check.checkCode(),
                check.label(),
                check.expectedValue(),
                check.actualValue(),
                check.source(),
                check.remediationOwner(),
                check.label(),
                rootCause(check),
                check.remediationOwner(),
                firstNonBlank(check.operatorReason(), rootCause(check)),
                check.remediationHint(),
                check.reverifyCriterion());
    }

    private OfficialRunPackageListItem listItem(OfficialVerificationOperatorSnapshotService.OperatorRunBatch batch) {
        return new OfficialRunPackageListItem(
                batch.packageId(),
                batch.aggregateRunId(),
                batch.finalDecision(),
                batch.blocked(),
                batch.blockReasonSummary(),
                batch.expectedMetricCount(),
                batch.actualMetricCount(),
                batch.passedMetricCount(),
                batch.failedMetricCount(),
                batch.certificateId(),
                batch.caseId(),
                batch.promptHash(),
                batch.contextHash(),
                batch.contextHashState(),
                batch.templateResourceId(),
                batch.actualResourceId(),
                batch.resourceUrlTemplate(),
                batch.actualRequestPath(),
                batch.httpMethod(),
                batch.createdAt());
    }

    private OfficialRunPackageSummary summary(OperatorSnapshot snapshot) {
        OfficialVerificationOperatorSnapshotService.OperatorRunBatch batch = snapshot.batch();
        List<OfficialRunFailureCause> failures = operatorFailureCauses(snapshot);
        List<OfficialRunRemediationGroup> groups = operatorRemediationGroups(snapshot);
        List<String> actions = merge(groupNextActions(groups), nextActions(failures));
        return new OfficialRunPackageSummary(
                batch.packageId(),
                batch.aggregateRunId(),
                batch.finalDecision(),
                batch.blocked(),
                batch.blockReasonSummary(),
                batch.expectedMetricCount(),
                batch.actualMetricCount(),
                batch.passedMetricCount(),
                batch.failedMetricCount(),
                batch.certificateId(),
                batch.caseId(),
                batch.finalDecision(),
                stateLabel(batch.finalDecision()),
                StringUtils.hasText(batch.certificateId()) && !batch.blocked(),
                batch.blockReasonSummary(),
                batch.promptHash(),
                batch.contextHash(),
                batch.contextHashState(),
                batch.templateResourceId(),
                batch.actualResourceId(),
                batch.resourceUrlTemplate(),
                batch.actualRequestPath(),
                batch.httpMethod(),
                batch.createdAt(),
                snapshot.metrics().stream()
                        .filter(Objects::nonNull)
                        .map(this::metricSummary)
                        .toList(),
                failures,
                actions,
                null,
                groups,
                List.of(new OfficialRunAttemptSummary(
                        batch.aggregateRunId(),
                        batch.packageId(),
                        1,
                        batch.createdAt() == null ? "" : batch.createdAt().toString(),
                        batch.createdAt() == null ? "" : batch.createdAt().toString(),
                        batch.actualMetricCount(),
                        batch.passedMetricCount(),
                        batch.failedMetricCount(),
                        batch.finalDecision(),
                        stateLabel(batch.finalDecision()),
                        true)));
    }

    private OfficialRunMetricSummary metricSummary(OperatorMetricSnapshot metric) {
        return new OfficialRunMetricSummary(
                metric.metricCode(),
                metric.metricName(),
                metric.metricGroup(),
                metric.score(),
                metric.state(),
                metric.severity(),
                metric.passedChecks(),
                metric.totalChecks(),
                metric.failedCheckCount(),
                metric.operatorTitle(),
                metric.operatorSummary(),
                metric.primaryFailureReason(),
                metric.remediationOwner(),
                metric.nextAction(),
                metric.reverifyCriterion(),
                metric.officialRunId(),
                metric.createdAt());
    }

    private OperatorSnapshot operatorSnapshot(String packageId, String aggregateRunId) {
        if (operatorSnapshotService == null) {
            return OperatorSnapshot.empty();
        }
        return operatorSnapshotService.findLatest(packageId, aggregateRunId);
    }

    private List<OfficialRunFailureCause> operatorFailureCauses(OperatorSnapshot snapshot) {
        if (snapshot == null || !snapshot.available() || snapshot.findings().isEmpty()) {
            return List.of();
        }
        Map<String, OperatorMetricSnapshot> metricsByCode = snapshot.metrics().stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toMap(
                        metric -> normalize(metric.metricCode()),
                        metric -> metric,
                        (left, right) -> left,
                        LinkedHashMap::new));
        return snapshot.findings().stream()
                .filter(Objects::nonNull)
                .map(finding -> {
                    OperatorMetricSnapshot metric = metricsByCode.get(normalize(finding.metricCode()));
                    return new OfficialRunFailureCause(
                            normalize(finding.metricCode()),
                            metric == null ? finding.metricCode() : metric.metricName(),
                            finding.officialRunId(),
                            finding.checkCode(),
                            firstNonBlank(finding.operatorTitle(), finding.checkCode()),
                            firstNonBlank(finding.expectedResult(), finding.expectedValue()),
                            firstNonBlank(finding.actualResult(), finding.actualValue()),
                            firstNonBlank(finding.evidencePath(), "official_verification_operator_finding"),
                            firstNonBlank(finding.remediationOwner(), finding.affectedTarget()),
                            firstNonBlank(finding.problemStatement(), finding.operatorReason(), finding.operatorTitle()),
                            firstNonBlank(finding.rootCause(), finding.operatorReason(), finding.evidenceSummary()),
                            firstNonBlank(finding.affectedTarget(), finding.remediationOwner()),
                            firstNonBlank(finding.impact(), finding.operatorSummary(), finding.evidenceSummary()),
                            finding.nextAction(),
                            finding.reverifyCriterion(),
                            finding.issueId(),
                            finding.findingId(),
                            null);
                })
                .toList();
    }

    private List<OfficialRunRemediationGroup> operatorRemediationGroups(OperatorSnapshot snapshot) {
        if (snapshot == null || !snapshot.available() || snapshot.remediationGroups().isEmpty()) {
            return List.of();
        }
        return snapshot.remediationGroups().stream()
                .filter(Objects::nonNull)
                .map(group -> new OfficialRunRemediationGroup(
                        group.groupId(),
                        group.rootCauseKey(),
                        group.remediationOwner(),
                        group.operatorTitle(),
                        group.operatorReason(),
                        group.nextAction(),
                        group.reverifyCriterion(),
                        group.affectedMetricCodes(),
                        group.affectedCheckCodes(),
                        group.findingCount(),
                        group.relatedProcessStep()))
                .toList();
    }

    private List<String> groupNextActions(List<OfficialRunRemediationGroup> groups) {
        if (groups == null || groups.isEmpty()) {
            return List.of();
        }
        return groups.stream()
                .filter(Objects::nonNull)
                .map(OfficialRunRemediationGroup::nextAction)
                .filter(StringUtils::hasText)
                .distinct()
                .limit(5)
                .toList();
    }

    private List<String> nextActions(List<OfficialRunFailureCause> failures) {
        if (failures == null || failures.isEmpty()) {
            return List.of();
        }
        return failures.stream()
                .map(OfficialRunFailureCause::remediationHint)
                .filter(StringUtils::hasText)
                .distinct()
                .limit(5)
                .toList();
    }

    private List<String> merge(List<String> left, List<String> right) {
        List<String> result = new ArrayList<>();
        appendDistinct(result, left);
        appendDistinct(result, right);
        return List.copyOf(result);
    }

    private void appendDistinct(List<String> target, List<String> source) {
        if (source == null) {
            return;
        }
        for (String item : source) {
            if (StringUtils.hasText(item) && !target.contains(item.trim())) {
                target.add(item.trim());
            }
        }
    }

    private PromptQualityCertificate certificate(String packageId) {
        return certificateService == null
                ? null
                : certificateService.findLatestBySealedEvidencePackageId(packageId);
    }

    private PromptQualityAssuranceCase assuranceCase(
            RuntimeEvidencePackageDetail sealedEvidence,
            PromptQualityCertificate certificate) {
        if (assuranceCaseService == null) {
            return null;
        }
        PromptQualityAssuranceScope scope = assuranceScope(sealedEvidence, certificate);
        return scope == null ? null : assuranceCaseService.findCase(scope);
    }

    private PromptQualityAssuranceScope assuranceScope(
            RuntimeEvidencePackageDetail sealedEvidence,
            PromptQualityCertificate certificate) {
        if (certificate != null && certificate.scope() != null) {
            PromptQualityCertificateService.CertificateScope scope = certificate.scope();
            return new PromptQualityAssuranceScope(
                    scope.tenantId(),
                    scope.resourceUrl(),
                    scope.protectableResourceId(),
                    scope.httpMethod(),
                    scope.promptContractVersion(),
                    scope.modelProfile(),
                    scope.verifierVersion());
        }
        if (sealedEvidence == null || sealedEvidence.summary() == null) {
            return null;
        }
        return new PromptQualityAssuranceScope(
                sealedEvidence.summary().tenantId(),
                sealedEvidence.summary().requestPath(),
                sealedEvidence.summary().resourceId(),
                sealedEvidence.summary().httpMethod(),
                PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION,
                PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE,
                PromptQualityAssuranceScope.DEFAULT_VERIFIER_VERSION);
    }

    private PromptQualityProcessScope processScope(
            RuntimeEvidencePackageDetail sealedEvidence,
            PromptQualityCertificate certificate) {
        PromptQualityAssuranceScope scope = assuranceScope(sealedEvidence, certificate);
        if (scope == null) {
            return null;
        }
        return new PromptQualityProcessScope(
                scope.tenantId(),
                scope.resourceUrl(),
                scope.resourceId(),
                scope.httpMethod(),
                scope.promptContractVersion(),
                scope.modelProfile(),
                scope.verifierVersion());
    }

    private List<OfficialRunAttemptSummary> attempts(
            List<OfficialVerificationRunView> runs,
            String latestAggregateRunId,
            String packageId) {
        if (runs == null || runs.isEmpty()) {
            return List.of();
        }
        Map<String, List<OfficialVerificationRunView>> byAggregate = new LinkedHashMap<>();
        for (OfficialVerificationRunView run : runs) {
            if (run == null) {
                continue;
            }
            String aggregateRunId = firstNonBlank(raw(run.rawEvidence(), "aggregateRunId"), run.runId());
            byAggregate.computeIfAbsent(aggregateRunId, ignored -> new ArrayList<>()).add(run);
        }
        List<AttemptGroup> groups = byAggregate.entrySet().stream()
                .map(entry -> attemptGroup(entry.getKey(), packageId, entry.getValue(), latestAggregateRunId))
                .sorted(Comparator.comparing(AttemptGroup::completedAt).thenComparing(AttemptGroup::aggregateRunId))
                .toList();
        List<OfficialRunAttemptSummary> result = new ArrayList<>();
        for (int i = 0; i < groups.size(); i++) {
            AttemptGroup group = groups.get(i);
            result.add(new OfficialRunAttemptSummary(
                    group.aggregateRunId(),
                    group.packageId(),
                    i + 1,
                    group.startedAt(),
                    group.completedAt(),
                    group.totalRunCount(),
                    group.passedRunCount(),
                    group.failedRunCount(),
                    group.state(),
                    group.stateLabel(),
                    group.latest()));
        }
        return List.copyOf(result);
    }

    private AttemptGroup attemptGroup(
            String aggregateRunId,
            String packageId,
            List<OfficialVerificationRunView> runs,
            String latestAggregateRunId) {
        List<OfficialVerificationRunView> safeRuns = runs == null ? List.of() : runs.stream().filter(Objects::nonNull).toList();
        int total = safeRuns.size();
        int passed = (int) safeRuns.stream().filter(run -> PASS_STATES.contains(normalize(run.state()))).count();
        int failed = (int) safeRuns.stream().filter(run -> failedState(run.state())).count();
        String state = total == 0
                ? "PENDING"
                : failed == 0 && total >= metricCatalog.promptQualityMetrics().size() ? "SUCCESS" : "FAILED";
        return new AttemptGroup(
                aggregateRunId,
                packageId,
                minTime(safeRuns),
                maxTime(safeRuns),
                total,
                passed,
                failed,
                state,
                stateLabel(state),
                same(aggregateRunId, latestAggregateRunId));
    }

    private String minTime(List<OfficialVerificationRunView> runs) {
        return runs.stream()
                .map(OfficialVerificationRunView::startedAt)
                .filter(StringUtils::hasText)
                .min(String::compareTo)
                .orElse("");
    }

    private String maxTime(List<OfficialVerificationRunView> runs) {
        return runs.stream()
                .map(run -> firstNonBlank(run.completedAt(), run.startedAt()))
                .filter(StringUtils::hasText)
                .max(String::compareTo)
                .orElse("");
    }

    private List<OfficialRunAuditSnapshot> auditSnapshots(
            String packageId,
            String aggregateRunId,
            List<OfficialVerificationMetricTrace> runs,
            RuntimeEvidencePackageDetail sealedEvidence,
            PromptQualityCertificate certificate,
            PromptQualityAssuranceCase assuranceCase,
            List<OfficialRunFailureCause> failureCauses,
            List<String> nextActions,
            List<PromptQualityProcessEventSnapshot> processEvents,
            OperatorSnapshot operatorSnapshot) {
        if (!StringUtils.hasText(packageId)) {
            return List.of();
        }
        if (operatorSnapshot != null && operatorSnapshot.available()
                && operatorSnapshot.auditSnapshots() != null
                && !operatorSnapshot.auditSnapshots().isEmpty()) {
            return operatorSnapshot.auditSnapshots().stream()
                    .map(this::storedAuditSnapshot)
                    .toList();
        }
        boolean persisted = processEvents != null && processEvents.stream()
                .filter(event -> event != null && "OFFICIAL_VERIFICATION_AUDIT_SNAPSHOT".equalsIgnoreCase(clean(event.type())))
                .anyMatch(event -> !StringUtils.hasText(aggregateRunId) || clean(event.payloadJson()).contains(aggregateRunId));
        String state = certificate == null
                ? ((failureCauses == null || failureCauses.isEmpty()) ? "SUCCESS" : "BLOCKED")
                : certificate.state();
        String stateLabel = certificate == null ? stateLabel(state) : certificate.stateLabel();
        String promptHash = sealedEvidence == null || sealedEvidence.summary() == null ? "" : sealedEvidence.summary().promptHash();
        String contextHash = sealedEvidence == null ? "" : fact(sealedEvidence.promptMetadata(), "contextHash");
        boolean snapshotAvailable = operatorSnapshot != null && operatorSnapshot.available();
        int failed = snapshotAvailable ? operatorSnapshot.batch().failedMetricCount() : (failureCauses == null ? 0 : failureCauses.size());
        int total = snapshotAvailable ? operatorSnapshot.batch().actualMetricCount() : (runs == null ? 0 : runs.size());
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("packageId", valueOrEmpty(packageId));
        payload.put("aggregateRunId", valueOrEmpty(aggregateRunId));
        payload.put("certificateId", firstNonBlank(
                certificate == null ? null : certificate.certificateId(),
                snapshotAvailable ? operatorSnapshot.batch().certificateId() : null,
                ""));
        payload.put("caseId", firstNonBlank(
                assuranceCase == null ? null : assuranceCase.caseId(),
                snapshotAvailable ? operatorSnapshot.batch().caseId() : null,
                ""));
        payload.put("state", valueOrEmpty(state));
        payload.put("totalMetricCount", total);
        payload.put("failedMetricCount", failed);
        payload.put("promptHash", valueOrEmpty(promptHash));
        payload.put("contextHash", valueOrEmpty(contextHash));
        payload.put("operatorSnapshotAvailable", snapshotAvailable);
        if (snapshotAvailable) {
            payload.put("expectedMetricCount", operatorSnapshot.batch().expectedMetricCount());
            payload.put("finalDecision", operatorSnapshot.batch().finalDecision());
            payload.put("blockReasonSummary", valueOrEmpty(operatorSnapshot.batch().blockReasonSummary()));
            payload.put("findings", operatorSnapshot.findings().stream()
                    .map(finding -> Map.of(
                            "findingId", valueOrEmpty(finding.findingId()),
                            "metricCode", valueOrEmpty(finding.metricCode()),
                            "checkCode", valueOrEmpty(finding.checkCode()),
                            "issueId", valueOrEmpty(finding.issueId()),
                            "reason", valueOrEmpty(firstNonBlank(finding.operatorReason(), finding.evidenceSummary()))))
                    .toList());
            payload.put("remediationGroups", operatorSnapshot.remediationGroups().stream()
                    .map(group -> Map.of(
                            "groupId", valueOrEmpty(group.groupId()),
                            "owner", valueOrEmpty(group.remediationOwner()),
                            "rootCause", valueOrEmpty(group.rootCauseKey()),
                            "metrics", valueOrEmpty(String.join(",", group.affectedMetricCodes())),
                            "checks", valueOrEmpty(String.join(",", group.affectedCheckCodes()))))
                    .toList());
        }
        return List.of(new OfficialRunAuditSnapshot(
                "pqa-audit-" + packageId + "-" + valueOrEmpty(aggregateRunId),
                packageId,
                aggregateRunId,
                Instant.now().toString(),
                state,
                stateLabel,
                total,
                failed,
                certificate != null && certificate.usableForLlmZeroTrust(),
                firstNonBlank(certificate == null ? null : certificate.certificateId(), snapshotAvailable ? operatorSnapshot.batch().certificateId() : null),
                firstNonBlank(assuranceCase == null ? null : assuranceCase.caseId(), snapshotAvailable ? operatorSnapshot.batch().caseId() : null),
                promptHash,
                contextHash,
                List.of(),
                List.of(),
                persisted,
                jsonPayload(payload)));
    }

    private OfficialRunAuditSnapshot storedAuditSnapshot(OperatorAuditSnapshot snapshot) {
        return new OfficialRunAuditSnapshot(
                valueOrEmpty(snapshot.snapshotId()),
                valueOrEmpty(snapshot.packageId()),
                valueOrEmpty(snapshot.aggregateRunId()),
                snapshot.createdAt() == null ? "" : snapshot.createdAt().toString(),
                valueOrEmpty(snapshot.state()),
                firstNonBlank(snapshot.stateLabel(), stateLabel(snapshot.state())),
                snapshot.totalMetricCount(),
                snapshot.failedMetricCount(),
                snapshot.certificateIssued(),
                valueOrEmpty(snapshot.certificateId()),
                valueOrEmpty(snapshot.caseId()),
                valueOrEmpty(snapshot.promptHash()),
                valueOrEmpty(snapshot.contextHash()),
                snapshot.blockingFindings(),
                snapshot.nextActions(),
                true,
                firstNonBlank(snapshot.payloadJson(), "{}"));
    }

    private String jsonPayload(Map<String, Object> payload) {
        if (payload == null || payload.isEmpty()) {
            return "{}";
        }
        return payload.entrySet().stream()
                .map(entry -> "\"" + jsonEscape(entry.getKey()) + "\":\"" + jsonEscape(String.valueOf(entry.getValue())) + "\"")
                .collect(Collectors.joining(",", "{", "}"));
    }

    private String jsonEscape(String value) {
        return valueOrEmpty(value)
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }

    private String valueOrEmpty(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
    }

    private record CachedOfficialRunPackageDetail(
            OfficialRunPackageDetail detail,
            long expiresAtNanos) {
    }

    private record AttemptGroup(
            String aggregateRunId,
            String packageId,
            String startedAt,
            String completedAt,
            int totalRunCount,
            int passedRunCount,
            int failedRunCount,
            String state,
            String stateLabel,
            boolean latest) {
    }

    private OfficialVerificationMetricDefinition metric(String metricCode) {
        String normalized = normalize(metricCode);
        return metricCatalog.promptQualityMetrics().stream()
                .filter(metric -> normalize(metric.code()).equals(normalized))
                .findFirst()
                .orElse(null);
    }

    private String detailCacheKey(String packageId, String aggregateRunId) {
        if (!StringUtils.hasText(packageId) || !StringUtils.hasText(aggregateRunId)) {
            return null;
        }
        return packageId.trim() + "\n" + aggregateRunId.trim();
    }

    private OfficialRunPackageDetail cachedDetail(String cacheKey) {
        if (!StringUtils.hasText(cacheKey)) {
            return null;
        }
        CachedOfficialRunPackageDetail cached = detailCache.get(cacheKey);
        if (cached == null) {
            return null;
        }
        if (System.nanoTime() > cached.expiresAtNanos()) {
            detailCache.remove(cacheKey, cached);
            return null;
        }
        return cached.detail();
    }

    private void cacheDetail(String cacheKey, OfficialRunPackageDetail detail) {
        if (!StringUtils.hasText(cacheKey) || detail == null) {
            return;
        }
        pruneDetailCache();
        detailCache.put(cacheKey, new CachedOfficialRunPackageDetail(
                detail,
                System.nanoTime() + DETAIL_CACHE_TTL.toNanos()));
    }

    private void pruneDetailCache() {
        if (detailCache.size() < DETAIL_CACHE_MAX_SIZE) {
            return;
        }
        long now = System.nanoTime();
        detailCache.entrySet().removeIf(entry -> entry.getValue() == null || now > entry.getValue().expiresAtNanos());
        if (detailCache.size() >= DETAIL_CACHE_MAX_SIZE) {
            detailCache.clear();
        }
    }

    private long elapsedMillis(long startedNanos) {
        return Math.max(0L, (System.nanoTime() - startedNanos) / 1_000_000L);
    }

    private void logSlowPackageDetail(
            String packageId,
            String aggregateRunId,
            long startedNanos,
            long evidenceMs,
            long ledgerMs,
            long runtimeMs,
            int runCount) {
        long totalMs = elapsedMillis(startedNanos);
        if (totalMs < 1_000L) {
            return;
        }
        log.warn(
                "[PQA-OFFICIAL-DETAIL-SLOW] packageId={} aggregateRunId={} totalMs={} evidenceMs={} ledgerMs={} runtimeFallbackMs={} runCount={}",
                packageId,
                valueOrEmpty(aggregateRunId),
                totalMs,
                evidenceMs,
                ledgerMs,
                runtimeMs,
                runCount);
    }

    private List<OfficialVerificationRunView> safeRuns(OfficialSealedEvidenceVerificationResult officialResult) {
        if (officialResult == null || officialResult.runs() == null) {
            return List.of();
        }
        return officialResult.runs().stream().filter(Objects::nonNull).toList();
    }

    private List<OfficialVerificationRunView> safeRunViews(List<OfficialVerificationRunView> runs) {
        if (runs == null || runs.isEmpty()) {
            return List.of();
        }
        return runs.stream().filter(Objects::nonNull).toList();
    }

    private OfficialRunLedgerConsistency ledgerConsistency(
            OfficialSealedEvidenceVerificationResult officialResult,
            List<OfficialVerificationMetricTrace> runs) {
        List<OfficialVerificationMetricTrace> safeRuns = runs == null ? List.of() : runs;
        int expectedMetricCount = metricCatalog.promptQualityMetrics().size();
        int actualRunCount = safeRuns.size();
        int storedCheckRowCount = safeRuns.stream()
                .mapToInt(this::storedCheckRowCount)
                .sum();
        int declaredCheckCount = safeRuns.stream()
                .mapToInt(run -> Math.max(run.totalChecks(), storedCheckRowCount(run)))
                .sum();
        int totalCheckCount = storedCheckRowCount;
        int missingSourceCheckCount = (int) safeRuns.stream()
                .flatMap(run -> run.checks().stream())
                .filter(check -> "MISSING_SOURCE".equals(normalize(check.source())))
                .count();
        int abstractSourceCheckCount = (int) safeRuns.stream()
                .flatMap(run -> run.checks().stream())
                .filter(check -> sourceNeedsDetail(check.source()))
                .count();
        int rawArtifactRunCount = (int) safeRuns.stream()
                .filter(run -> run.rawEvidence() != null && !run.rawEvidence().isEmpty())
                .count();
        int factBackedRunCount = (int) safeRuns.stream()
                .filter(run -> !run.requestFacts().isEmpty() && !run.promptFacts().isEmpty() && !run.analysisFacts().isEmpty())
                .count();
        boolean aggregateRunIdPresent = officialResult != null && StringUtils.hasText(officialResult.aggregateRunId());
        boolean metricCountMatched = expectedMetricCount == 0 || expectedMetricCount == actualRunCount;
        boolean checkCountMatched = declaredCheckCount == storedCheckRowCount;
        List<String> warnings = new ArrayList<>();
        if (!aggregateRunIdPresent) {
            warnings.add(message("enterprise.pqa.officialRun.ledgerConsistency.warning.aggregateMissing", "Aggregate run ID is missing."));
        }
        if (!metricCountMatched) {
            warnings.add(message(
                    "enterprise.pqa.officialRun.ledgerConsistency.warning.metricCountTpl",
                    "Expected {0} metric runs but found {1}.",
                    expectedMetricCount,
                    actualRunCount));
        }
        if (missingSourceCheckCount > 0 || abstractSourceCheckCount > 0) {
            warnings.add(message(
                    "enterprise.pqa.officialRun.ledgerConsistency.warning.sourceTpl",
                    "{0} checks need a more concrete evidence source.",
                    missingSourceCheckCount + abstractSourceCheckCount));
        }
        if (!checkCountMatched) {
            warnings.add(message(
                    "enterprise.pqa.officialRun.ledgerConsistency.warning.checkCountTpl",
                    "Metric runs declare {0} checks but the core check ledger stores {1} rows.",
                    declaredCheckCount,
                    storedCheckRowCount));
        }
        if (factBackedRunCount < actualRunCount) {
            warnings.add(message("enterprise.pqa.officialRun.ledgerConsistency.warning.factLedger", "Some metric runs do not have request, prompt, and analysis fact rows."));
        }
        if (rawArtifactRunCount < actualRunCount) {
            warnings.add(message("enterprise.pqa.officialRun.ledgerConsistency.warning.rawArtifact", "Some metric runs do not have a raw artifact reference."));
        }
        boolean ready = aggregateRunIdPresent
                && metricCountMatched
                && totalCheckCount > 0
                && checkCountMatched
                && missingSourceCheckCount == 0
                && abstractSourceCheckCount == 0
                && rawArtifactRunCount == actualRunCount
                && factBackedRunCount == actualRunCount;
        return new OfficialRunLedgerConsistency(
                expectedMetricCount,
                actualRunCount,
                metricCountMatched,
                totalCheckCount,
                declaredCheckCount,
                storedCheckRowCount,
                checkCountMatched,
                missingSourceCheckCount,
                abstractSourceCheckCount,
                rawArtifactRunCount,
                factBackedRunCount,
                aggregateRunIdPresent,
                ready,
                List.copyOf(warnings));
    }

    private int storedCheckRowCount(OfficialVerificationMetricTrace run) {
        if (run == null) {
            return 0;
        }
        if (run.checks() != null && !run.checks().isEmpty()) {
            return run.checks().size();
        }
        if (run.totalChecks() <= 0 || run.purposeEvidence() == null || run.purposeEvidence().isEmpty()) {
            return 0;
        }
        return (int) run.purposeEvidence().stream()
                .filter(Objects::nonNull)
                .count();
    }

    private boolean sourceNeedsDetail(String source) {
        String normalized = normalize(source);
        return !StringUtils.hasText(source)
                || "MISSING_SOURCE".equals(normalized)
                || "COREEVIDENCEREPLAY".equals(normalized)
                || "EVIDENCEREPLAY".equals(normalized);
    }

    private boolean passed(OfficialVerificationMetricTrace run) {
        return run != null && PASS_STATES.contains(normalize(run.state()));
    }

    private boolean failed(OfficialVerificationMetricTrace run) {
        return run != null && failedState(run.state());
    }

    private boolean failedState(String state) {
        String normalized = normalize(state);
        return StringUtils.hasText(normalized)
                && !PASS_STATES.contains(normalized)
                && !NOT_APPLICABLE_STATES.contains(normalized);
    }

    private Map<String, String> safeMap(Map<String, String> raw) {
        return raw == null ? Map.of() : Map.copyOf(raw);
    }

    private String groupName(String category) {
        return switch (clean(category)) {
            case "IMPLEMENTATION_ALIGNMENT" -> message("enterprise.pqa.runtimeVerification.metric.group.implementationAlignment", "Implementation alignment");
            case "RAG_AND_BASELINE" -> message("enterprise.pqa.runtimeVerification.metric.group.ragAndBaseline", "Learning and baseline");
            case "BEHAVIORAL_CONTEXT" -> message("enterprise.pqa.runtimeVerification.metric.group.behavioralContext", "Behavior context");
            case "LLM_DECISION" -> message("enterprise.pqa.runtimeVerification.metric.group.llmDecision", "Decision reliability");
            case "RESOURCE_ELIGIBILITY" -> message("enterprise.pqa.runtimeVerification.metric.group.resourceEligibility", "Operational promotion eligibility");
            default -> message("enterprise.pqa.runtimeVerification.metric.group.other", "Other");
        };
    }

    private String stateLabel(String state) {
        String normalized = normalize(state);
        if ("NOT_APPLICABLE".equals(normalized)) {
            return message("enterprise.pqa.runtimeVerification.metric.state.notApplicable", "해당 없음");
        }
        return PASS_STATES.contains(normalized)
                ? message("enterprise.pqa.runtimeVerification.metric.state.passed", "통과")
                : message("enterprise.pqa.runtimeVerification.metric.state.blocked", "차단");
    }

    private String sourceMeaning(String source) {
        String normalized = normalize(source);
        if (!StringUtils.hasText(source) || "MISSING_SOURCE".equals(normalized)) {
            return message("enterprise.pqa.officialRun.source.missing", "The official verifier did not store a concrete evidence source. This must be supplemented before issue resolution.");
        }
        if (normalized.contains("COREEVIDENCEREPLAY")) {
            return message("enterprise.pqa.officialRun.source.coreEvidenceReplay", "The core official verifier replayed the sealed evidence to produce this value.");
        }
        if (normalized.contains("PROMPT")) {
            return message("enterprise.pqa.officialRun.source.prompt", "This value comes from prompt assembly or prompt capture.");
        }
        if (normalized.contains("EVIDENCE")) {
            return message("enterprise.pqa.officialRun.source.evidence", "This value is stored in the sealed evidence package.");
        }
        return message("enterprise.pqa.officialRun.source.ledger", "This value is stored as inspection evidence in the official verification ledger.");
    }

    private String remediationHint(String label, String source) {
        String text = (clean(label) + " " + clean(source)).toLowerCase(Locale.ROOT);
        if (text.contains("mfa")) {
            return message("enterprise.pqa.officialRun.remediation.mfa", "Ensure MFA completion is captured as true in the real request context and sealed evidence.");
        }
        if (text.contains("prompt") && text.contains("hash")) {
            return message("enterprise.pqa.officialRun.remediation.promptHash", "Align final prompt generation, hash calculation, and sealed storage in the same transaction flow.");
        }
        if (text.contains("prompt") || text.contains("context")) {
            return message("enterprise.pqa.officialRun.remediation.promptContext", "Compare prompt assembly trace with sealed final prompt fields and add missing context.");
        }
        if (text.contains("resource") || text.contains("requestpath") || text.contains("request path")) {
            return message("enterprise.pqa.officialRun.remediation.resource", "Align @Protectable resource ID, URL, and HTTP method with the real request evidence scope.");
        }
        if (text.contains("authorization") || text.contains("role") || text.contains("permission")) {
            return message("enterprise.pqa.officialRun.remediation.authorization", "Ensure authorization effect, roles, and permissions remain in both request context and final prompt.");
        }
        return message("enterprise.pqa.officialRun.remediation.default", "Fix the expected/actual difference between real request evidence and core official verification detail, then call the same resource again.");
    }

    private String reverifyCriterion(String label) {
        return StringUtils.hasText(label)
                ? message("enterprise.pqa.officialRun.reverifyCriterionTpl", "{0} must pass in new sealed evidence from the same protected resource.", label.trim())
                : message("enterprise.pqa.officialRun.reverifyCriterion.default", "The same metric must pass in new sealed evidence from the same protected resource.");
    }

    private String rootCause(OfficialRunCheckDetail check) {
        return message(
                "enterprise.pqa.officialRun.rootCauseTpl",
                "{0} expected {1}, actual {2}. Evidence source: {3}.",
                display(check.label()),
                display(check.expectedValue()),
                display(check.actualValue()),
                display(check.source()));
    }

    private String comparisonLabel(String state) {
        return switch (state) {
            case "MATCH" -> message("enterprise.pqa.officialRun.comparison.state.match", "Match");
            case "PROMPT_MISSING" -> message("enterprise.pqa.officialRun.comparison.state.promptMissing", "Missing from prompt");
            case "FACT_MISSING" -> message("enterprise.pqa.officialRun.comparison.state.factMissing", "Missing from core fact");
            case "VALUE_MISMATCH" -> message("enterprise.pqa.officialRun.comparison.state.valueMismatch", "Value mismatch");
            case "NOT_APPLICABLE" -> message("enterprise.pqa.officialRun.comparison.state.notApplicable", "Not applicable");
            default -> message("enterprise.pqa.officialRun.comparison.state.unknown", "Review");
        };
    }

    private String comparisonMeaning(String label, String state) {
        return switch (state) {
            case "MATCH" -> message("enterprise.pqa.officialRun.comparison.meaning.matchTpl", "{0} matches across sealed evidence, prompt, and core official fact.", label);
            case "PROMPT_MISSING" -> message("enterprise.pqa.officialRun.comparison.meaning.promptMissingTpl", "{0} exists in sealed evidence but is not visible in the final prompt.", label);
            case "FACT_MISSING" -> message("enterprise.pqa.officialRun.comparison.meaning.factMissingTpl", "{0} exists in sealed evidence but is missing from the core official fact ledger.", label);
            case "VALUE_MISMATCH" -> message("enterprise.pqa.officialRun.comparison.meaning.valueMismatchTpl", "{0} differs between sealed evidence, prompt, or core official fact.", label);
            case "NOT_APPLICABLE" -> message("enterprise.pqa.officialRun.comparison.meaning.notApplicableTpl", "{0} is not applicable to this package.", label);
            default -> message("enterprise.pqa.officialRun.comparison.meaning.defaultTpl", "Review {0}.", label);
        };
    }

    private String evidenceFact(RuntimeEvidencePackageDetail detail, String key) {
        return fact(detail == null ? null : detail.requestFacts(), key);
    }

    private String promptMetadata(RuntimeEvidencePackageDetail detail, String key) {
        return fact(detail == null ? null : detail.promptMetadata(), key);
    }

    private String decision(RuntimeEvidencePackageDetail detail, String key) {
        return fact(detail == null ? null : detail.decision(), key);
    }

    private String authFact(RuntimeEvidencePackageDetail detail, String key) {
        return fact(detail == null ? null : detail.authState(), key);
    }

    private String summaryValue(RuntimeEvidencePackageDetail detail, String field) {
        if (detail == null || detail.summary() == null) {
            return "";
        }
        return switch (field) {
            case "correlationId" -> detail.summary().correlationId();
            case "tenantId" -> detail.summary().tenantId();
            case "userId" -> detail.summary().userId();
            case "requestPath" -> detail.summary().requestPath();
            case "resourceId" -> detail.summary().resourceId();
            case "httpMethod" -> detail.summary().httpMethod();
            case "promptHash" -> detail.summary().promptHash();
            default -> "";
        };
    }

    private String promptValue(RuntimeEvidencePackageDetail detail, String key, String sealedValue) {
        String promptMetadataValue = promptMetadata(detail, key);
        if (StringUtils.hasText(promptMetadataValue)) {
            return promptMetadataValue;
        }
        String prompt = promptText(detail).toLowerCase(Locale.ROOT);
        String normalizedKey = clean(key).toLowerCase(Locale.ROOT);
        String normalizedValue = clean(sealedValue).toLowerCase(Locale.ROOT);
        if (StringUtils.hasText(normalizedKey)
                && StringUtils.hasText(normalizedValue)
                && prompt.contains(normalizedKey)
                && prompt.contains(normalizedValue)) {
            return sealedValue;
        }
        return "";
    }

    private String promptSectionValue(RuntimeEvidencePackageDetail detail, String... markers) {
        String prompt = promptText(detail).toLowerCase(Locale.ROOT);
        if (markers != null) {
            for (String marker : markers) {
                if (StringUtils.hasText(marker) && prompt.contains(marker.toLowerCase(Locale.ROOT))) {
                    return "true";
                }
            }
        }
        return "";
    }

    private String promptText(RuntimeEvidencePackageDetail detail) {
        if (detail == null) {
            return "";
        }
        return firstNonBlank(detail.systemPromptText(), detail.systemPromptPreview())
                + "\n"
                + firstNonBlank(detail.userPromptText(), detail.userPromptPreview());
    }

    private List<String> metricCodesFor(String key, OfficialVerificationRunView run) {
        return List.of();
    }

    private String promptLocation(String key) {
        String normalized = clean(key).toLowerCase(Locale.ROOT);
        if (normalized.contains("systemprompt")) {
            return "systemPrompt";
        }
        if (normalized.contains("hash") || normalized.contains("version") || normalized.contains("model")) {
            return "promptExecutionMetadata";
        }
        if (normalized.contains("baseline")) {
            return "userPrompt.baseline";
        }
        if (normalized.contains("rag")) {
            return "userPrompt.rag";
        }
        return "userPrompt.requestContext";
    }

    private String evidenceSource(String key) {
        String normalized = clean(key).toLowerCase(Locale.ROOT);
        if (normalized.contains("auth") || normalized.contains("mfa") || normalized.contains("role") || normalized.contains("permission")) {
            return "sealedEvidence.authState";
        }
        if (normalized.contains("prompt") || normalized.contains("model")) {
            return "sealedEvidence.promptExecutionMetadata";
        }
        if (normalized.contains("baseline")) {
            return "sealedEvidence.baselineSnapshot";
        }
        if (normalized.contains("rag")) {
            return "sealedEvidence.ragResults";
        }
        if (normalized.contains("decision")) {
            return "sealedEvidence.decision";
        }
        return "sealedEvidence.requestFacts";
    }

    private String recommendedOwner(String key) {
        String normalized = clean(key).toLowerCase(Locale.ROOT);
        if (normalized.contains("auth") || normalized.contains("mfa") || normalized.contains("role") || normalized.contains("permission")) {
            return "CONTEXT_SOURCE_MAPPING";
        }
        if (normalized.contains("prompt") || normalized.contains("model")) {
            return "PROMPT_GOVERNANCE";
        }
        if (normalized.contains("baseline") || normalized.contains("rag")) {
            return "LEARNING_CONTEXT";
        }
        if (normalized.contains("resource") || normalized.contains("requestpath") || normalized.contains("httpmethod")) {
            return "RESOURCE_SCOPE";
        }
        return "CONTEXT_PROJECTION";
    }

    private boolean same(String left, String right) {
        return clean(left).equalsIgnoreCase(clean(right));
    }

    private String raw(Map<String, Object> raw, String key) {
        Object value = raw == null ? null : raw.get(key);
        return value == null ? "" : String.valueOf(value);
    }

    private String fact(Map<?, ?> raw, String key) {
        Object value = raw == null ? null : raw.get(key);
        return value == null ? "" : String.valueOf(value);
    }

    private String value(Map<String, String> raw, String key) {
        return raw == null ? null : raw.get(key);
    }

    private String bool(boolean value) {
        return String.valueOf(value);
    }

    private String display(String value) {
        return StringUtils.hasText(value)
                ? value.trim()
                : message("enterprise.pqa.verification.value.notAvailable", "Not available");
    }

    private String clean(String value) {
        return value == null ? "" : value.trim();
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return "";
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String normalize(String value) {
        return clean(value).toUpperCase(Locale.ROOT);
    }

    private String requireText(String value, String message) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(message);
        }
        return value.trim();
    }

    private String fieldLabel(String key, String fallback) {
        return message("enterprise.pqa.officialRun.field." + key, fallback);
    }

    private String message(String key, String fallback, Object... args) {
        if (messageResolver == null) {
            return args == null || args.length == 0 ? fallback : MessageFormat.format(fallback, args);
        }
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            return args == null || args.length == 0 ? fallback : MessageFormat.format(fallback, args);
        }
        return resolved;
    }
}
