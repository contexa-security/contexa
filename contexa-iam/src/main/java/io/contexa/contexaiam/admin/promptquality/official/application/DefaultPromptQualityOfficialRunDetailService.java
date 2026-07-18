package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.persistence.VerificationLedgerService;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageListItem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;
public class DefaultPromptQualityOfficialRunDetailService implements PromptQualityOfficialRunDetailService {

    private static final Logger log = LoggerFactory.getLogger(DefaultPromptQualityOfficialRunDetailService.class);
    private final PromptQualityMessageResolver messageResolver;
    private final OfficialRunDetailPresentation presentation;
    private final OfficialRunAuditSnapshotFactory auditSnapshotFactory;
    private final OfficialRunAttemptSummaryFactory attemptSummaryFactory;
    private final OfficialRunOperatorSnapshotMapper operatorSnapshotMapper;
    private final OfficialRunMetricContractView metricContractView;
    private final OfficialRunMetricSummaryCalculator metricSummaryCalculator = new OfficialRunMetricSummaryCalculator();
    private final OfficialRunMetricEvidenceMapper metricEvidenceMapper;
    private final OfficialRunMetricTraceMapper metricTraceMapper;
    private final OfficialRunLedgerConsistencyEvaluator ledgerConsistencyEvaluator;
    private final OfficialVerificationOperatorSnapshotService operatorSnapshotService;
    private final OfficialRunPackageDetailCache detailCache = new OfficialRunPackageDetailCache();
    private final OfficialRunPackageRunLoader packageRunLoader;
    private final OfficialRunPackageDetailAssembler packageDetailAssembler;

    public DefaultPromptQualityOfficialRunDetailService(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService verificationLedgerService,
            OfficialRunLightweightEvidenceReader evidenceReader,
            OfficialRunMetricContractView metricContractView,
            PromptQualityMessageResolver messageResolver,
            PromptQualityAssuranceCaseService assuranceCaseService,
            PromptQualityProcessRunService processRunService,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService) {
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
        this.presentation = new OfficialRunDetailPresentation(this.messageResolver);
        this.auditSnapshotFactory = new OfficialRunAuditSnapshotFactory(this.presentation);
        this.attemptSummaryFactory = new OfficialRunAttemptSummaryFactory(this.presentation);
        this.operatorSnapshotMapper = new OfficialRunOperatorSnapshotMapper(this.presentation, this.messageResolver);
        this.operatorSnapshotService = Objects.requireNonNull(operatorSnapshotService, "operatorSnapshotService");
        this.metricContractView = Objects.requireNonNull(metricContractView, "metricContractView");
        this.metricEvidenceMapper = new OfficialRunMetricEvidenceMapper(this.metricContractView, this.presentation);
        this.metricTraceMapper = new OfficialRunMetricTraceMapper(
                this.metricContractView,
                this.metricEvidenceMapper,
                this.metricSummaryCalculator,
                this.operatorSnapshotMapper,
                this.presentation);
        this.ledgerConsistencyEvaluator = new OfficialRunLedgerConsistencyEvaluator(
                this.metricContractView.expectedMetricCount(),
                this.metricSummaryCalculator,
                this.messageResolver);
        this.packageRunLoader = new OfficialRunPackageRunLoader(
                officialRuntime,
                verificationLedgerService,
                evidenceReader,
                this.operatorSnapshotService,
                this.attemptSummaryFactory,
                this.metricSummaryCalculator,
                this.metricTraceMapper,
                this.messageResolver);
        this.packageDetailAssembler = new OfficialRunPackageDetailAssembler(
                assuranceCaseService,
                processRunService,
                this.operatorSnapshotService,
                this.operatorSnapshotMapper,
                this.attemptSummaryFactory,
                this.metricSummaryCalculator,
                this.ledgerConsistencyEvaluator,
                this.auditSnapshotFactory);
    }
    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<OfficialRunPackageListItem> listRecentRunSummaries(int limit) {
        return operatorSnapshotService.recentSnapshots(limit).stream()
                .filter(OperatorSnapshot::available)
                .map(snapshot -> operatorSnapshotMapper.listItem(snapshot.batch()))
                .toList();
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public OfficialRunPackageSummary findPackageSummary(String packageId, String aggregateRunId) {
        String normalizedPackageId = requireText(packageId, message("enterprise.pqa.runtimeVerification.error.packageId.required"));
        OperatorSnapshot snapshot = operatorSnapshotService.findLatest(normalizedPackageId, aggregateRunId);
        if (snapshot.available()) {
            return operatorSnapshotMapper.summary(snapshot);
        }
        return OfficialRunPackageSummary.fromDetail(
                findPackageDetail(normalizedPackageId, aggregateRunId),
                messageResolver);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<OfficialRunFailureCause> findFailureDetails(String packageId, String aggregateRunId) {
        String normalizedPackageId = requireText(packageId, message("enterprise.pqa.runtimeVerification.error.packageId.required"));
        OperatorSnapshot snapshot = operatorSnapshotService.findLatest(normalizedPackageId, aggregateRunId);
        if (snapshot.available()) {
            List<OfficialRunFailureCause> operatorFailures = operatorSnapshotMapper.failureCauses(snapshot);
            if (!operatorFailures.isEmpty()) {
                return operatorFailures;
            }
        }
        return findPackageDetail(normalizedPackageId, aggregateRunId).failureCauses();
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<OfficialRunAuditSnapshot> findAuditPayloads(String packageId, String aggregateRunId) {
        String normalizedPackageId = requireText(packageId, message("enterprise.pqa.runtimeVerification.error.packageId.required"));
        OperatorSnapshot snapshot = operatorSnapshotService.findLatest(normalizedPackageId, aggregateRunId);
        if (snapshot.available()) {
            return snapshot.auditSnapshots().stream()
                    .map(auditSnapshotFactory::storedSnapshot)
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
    public OfficialRunPackageDetail findPackageDetail(String packageId, String aggregateRunId) {
        String normalizedPackageId = requireText(packageId, message("enterprise.pqa.runtimeVerification.error.packageId.required"));
        String normalizedAggregateRunId = StringUtils.hasText(aggregateRunId) ? aggregateRunId.trim() : null;
        String cacheKey = detailCache.key(normalizedPackageId, normalizedAggregateRunId);
        OfficialRunPackageDetail cachedDetail = detailCache.get(cacheKey);
        if (cachedDetail != null) {
            return cachedDetail;
        }
        long startedNanos = System.nanoTime();
        OfficialRunPackageRunLoader.LoadedRunPackage loaded = packageRunLoader.load(
                normalizedPackageId, normalizedAggregateRunId);
        OfficialRunPackageDetail detail = packageDetailAssembler.assemble(
                normalizedPackageId, loaded, metricContractView.expectedMetricCount());
        detailCache.put(cacheKey, detail);
        logSlowPackageDetail(
                normalizedPackageId, loaded.aggregateRunId(), startedNanos,
                loaded.evidenceMs(), loaded.ledgerMs(), loaded.runtimeMs(), loaded.runs().size());
        return detail;
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public String findPackageIdByRunId(String runId) {
        return packageRunLoader.findPackageIdByRunId(runId);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public OfficialVerificationMetricTrace findRunDetail(String runId) {
        return packageRunLoader.findRunDetail(runId);
    }

    private String valueOrEmpty(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
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
        log.error(
                "[PQA-OFFICIAL-DETAIL-SLOW] packageId={} aggregateRunId={} totalMs={} evidenceMs={} ledgerMs={} runtimeFallbackMs={} runCount={}",
                packageId,
                valueOrEmpty(aggregateRunId),
                totalMs,
                evidenceMs,
                ledgerMs,
                runtimeMs,
                runCount);
    }

    private String requireText(String value, String message) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(message);
        }
        return value.trim();
    }


    private String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }
}

