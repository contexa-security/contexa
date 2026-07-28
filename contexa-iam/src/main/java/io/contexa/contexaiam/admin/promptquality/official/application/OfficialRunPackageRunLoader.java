package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.persistence.VerificationLedgerService;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationResult;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageSummary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;

final class OfficialRunPackageRunLoader {

    private static final Logger log = LoggerFactory.getLogger(OfficialRunPackageRunLoader.class);

    private final OfficialSealedEvidenceVerificationRuntime officialRuntime;
    private final VerificationLedgerService ledgerService;
    private final OfficialRunLightweightEvidenceReader evidenceReader;
    private final OfficialVerificationOperatorSnapshotService operatorSnapshotService;
    private final OfficialRunAttemptSummaryFactory attemptSummaryFactory;
    private final OfficialRunMetricSummaryCalculator summaryCalculator;
    private final OfficialRunMetricTraceMapper metricTraceMapper;
    private final PromptQualityMessageResolver messageResolver;

    OfficialRunPackageRunLoader(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService ledgerService,
            OfficialRunLightweightEvidenceReader evidenceReader,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService,
            OfficialRunAttemptSummaryFactory attemptSummaryFactory,
            OfficialRunMetricSummaryCalculator summaryCalculator,
            OfficialRunMetricTraceMapper metricTraceMapper,
            PromptQualityMessageResolver messageResolver) {
        this.officialRuntime = Objects.requireNonNull(officialRuntime, "officialRuntime");
        this.ledgerService = Objects.requireNonNull(ledgerService, "ledgerService");
        this.evidenceReader = Objects.requireNonNull(evidenceReader, "evidenceReader");
        this.operatorSnapshotService = Objects.requireNonNull(operatorSnapshotService, "operatorSnapshotService");
        this.attemptSummaryFactory = Objects.requireNonNull(attemptSummaryFactory, "attemptSummaryFactory");
        this.summaryCalculator = Objects.requireNonNull(summaryCalculator, "summaryCalculator");
        this.metricTraceMapper = Objects.requireNonNull(metricTraceMapper, "metricTraceMapper");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    LoadedRunPackage load(String packageId, String aggregateRunId) {
        long evidenceStartedNanos = System.nanoTime();
        RuntimeEvidencePackageDetail sealedEvidence = evidenceReader.findDetail(packageId);
        long evidenceMs = elapsedMillis(evidenceStartedNanos);
        long ledgerStartedNanos = System.nanoTime();
        List<OfficialVerificationRunView> allPackageRuns = safeRunViews(ledgerService.findMetricRunsByPackageId(packageId));
        long ledgerMs = elapsedMillis(ledgerStartedNanos);
        String requestedAggregateRunId = normalizeRequestedAggregateRunId(aggregateRunId);
        OperatorSnapshot operatorSnapshot = operatorSnapshotService.findLatest(packageId, requestedAggregateRunId);
        requireExplicitAggregateCandidate(
                packageId, requestedAggregateRunId, allPackageRuns, operatorSnapshot);
        String selectedAggregateRunId = firstNonBlank(
                requestedAggregateRunId,
                operatorSnapshot.available() ? operatorSnapshot.batch().aggregateRunId() : null);
        long runtimeMs = 0L;
        OfficialSealedEvidenceVerificationResult officialResult = storedResult(
                packageId, selectedAggregateRunId, sealedEvidence, allPackageRuns);
        if (officialResult == null) {
            long runtimeStartedNanos = System.nanoTime();
            officialResult = officialRuntime.findByPackageId(packageId);
            runtimeMs = elapsedMillis(runtimeStartedNanos);
        }
        officialResult = selectAggregate(officialResult, selectedAggregateRunId, allPackageRuns);
        String resolvedRequestedAggregateRunId = firstNonBlank(
                requestedAggregateRunId,
                operatorSnapshot.available() ? null : officialResult.aggregateRunId());
        requireRequestedAggregateRun(
                packageId,
                resolvedRequestedAggregateRunId,
                allPackageRuns,
                officialResult,
                operatorSnapshot,
                operatorSnapshotService.executionRecordExists(resolvedRequestedAggregateRunId));
        String resolvedAggregateRunId = firstNonBlank(
                operatorSnapshot.available() ? operatorSnapshot.batch().aggregateRunId() : null,
                officialResult.aggregateRunId(), requestedAggregateRunId);
        List<OfficialVerificationMetricTrace> runs = metricTraces(officialResult, sealedEvidence, operatorSnapshot);
        return new LoadedRunPackage(
                sealedEvidence, allPackageRuns, officialResult, operatorSnapshot,
                resolvedAggregateRunId, runs, evidenceMs, ledgerMs, runtimeMs);
    }

    String findPackageIdByRunId(String runId) {
        if (!StringUtils.hasText(runId)) {
            return null;
        }
        OfficialVerificationRunRecord record = ledgerService.findRunRecord(null, runId.trim());
        return record == null ? null : value(record.evidenceReferences(), "packageId");
    }

    OfficialVerificationMetricTrace findRunDetail(String runId) {
        String normalizedRunId = requireText(runId, message("enterprise.pqa.officialRun.error.runId.required"));
        OfficialVerificationRunRecord record = ledgerService.findRunRecord(null, normalizedRunId);
        if (record == null) {
            throw new NoSuchElementException(message("enterprise.pqa.officialRun.error.run.notFoundTpl", normalizedRunId));
        }
        OfficialVerificationRunView run = ledgerService.findMetricRun(null, record.metricCode(), normalizedRunId);
        if (run == null) {
            throw new NoSuchElementException(message("enterprise.pqa.officialRun.error.run.detailNotFoundTpl", normalizedRunId));
        }
        String packageId = value(record.evidenceReferences(), "packageId");
        RuntimeEvidencePackageDetail sealedEvidence = StringUtils.hasText(packageId) ? evidenceReader.findDetail(packageId) : null;
        String aggregateRunId = attemptSummaryFactory.aggregateRunId(run);
        OperatorSnapshot operatorSnapshot = StringUtils.hasText(packageId)
                ? operatorSnapshotService.findLatest(packageId, aggregateRunId)
                : OperatorSnapshot.empty();
        return metricTraceMapper.toMetricDetail(run, sealedEvidence, operatorSnapshot);
    }

    private OfficialSealedEvidenceVerificationResult selectAggregate(
            OfficialSealedEvidenceVerificationResult officialResult,
            String aggregateRunId,
            List<OfficialVerificationRunView> allPackageRuns) {
        if (!StringUtils.hasText(aggregateRunId)) {
            return officialResult;
        }
        String normalized = aggregateRunId.trim();
        List<OfficialVerificationRunView> selectedRuns = allPackageRuns.stream()
                .filter(run -> same(normalized, attemptSummaryFactory.aggregateRunId(run)))
                .toList();
        if (selectedRuns.isEmpty()) {
            return officialResult;
        }
        return new OfficialSealedEvidenceVerificationResult(
                normalized, officialResult.packageId(), officialResult.operatorId(), officialResult.generatedAt(),
                officialResult.integrityValid(), selectedRuns);
    }

    private String normalizeRequestedAggregateRunId(String aggregateRunId) {
        if (!StringUtils.hasText(aggregateRunId)) {
            return null;
        }
        return aggregateRunId.trim();
    }

    private void requireExplicitAggregateCandidate(
            String packageId,
            String requested,
            List<OfficialVerificationRunView> allPackageRuns,
            OperatorSnapshot operatorSnapshot) {
        if (!StringUtils.hasText(requested) || operatorSnapshot.available()) {
            return;
        }
        boolean ledgerMatch = allPackageRuns.stream()
                .anyMatch(run -> same(requested, attemptSummaryFactory.aggregateRunId(run)));
        boolean trackedExecution = operatorSnapshotService.executionRecordExists(requested);
        if (trackedExecution || (!ledgerMatch && !allPackageRuns.isEmpty())) {
            throw aggregateNotFound(
                    packageId,
                    requested,
                    trackedExecution
                            ? "TRACKED_EXECUTION_WITHOUT_PUBLISHABLE_SNAPSHOT"
                            : "NO_PACKAGE_AGGREGATE_MATCH");
        }
    }

    private void requireRequestedAggregateRun(
            String packageId,
            String requested,
            List<OfficialVerificationRunView> allPackageRuns,
            OfficialSealedEvidenceVerificationResult officialResult,
            OperatorSnapshot operatorSnapshot,
            boolean executionTracked) {
        if (!StringUtils.hasText(requested)) {
            return;
        }
        boolean ledgerMatch = allPackageRuns.stream()
                .anyMatch(run -> same(requested, attemptSummaryFactory.aggregateRunId(run)));
        boolean runtimeMatch = officialResult != null && same(requested, officialResult.aggregateRunId());
        boolean snapshotMatch = operatorSnapshot.available()
                && same(requested, operatorSnapshot.batch().aggregateRunId());
        if (executionTracked && !snapshotMatch) {
            throw aggregateNotFound(
                    packageId,
                    requested,
                    "TRACKED_EXECUTION_WITHOUT_PUBLISHABLE_SNAPSHOT");
        }
        if (!ledgerMatch && !runtimeMatch && !snapshotMatch) {
            throw aggregateNotFound(packageId, requested, "NO_PACKAGE_AGGREGATE_MATCH");
        }
    }

    private NoSuchElementException aggregateNotFound(String packageId, String aggregateRunId, String reason) {
        log.warn(
                "PQA official aggregate lookup rejected. packageId={}, aggregateRunId={}, reason={}",
                packageId,
                aggregateRunId,
                reason);
        return new NoSuchElementException(message(
                "enterprise.pqa.officialRun.error.aggregate.notFoundTpl",
                aggregateRunId,
                packageId));
    }

    private List<OfficialVerificationMetricTrace> metricTraces(
            OfficialSealedEvidenceVerificationResult officialResult,
            RuntimeEvidencePackageDetail sealedEvidence,
            OperatorSnapshot operatorSnapshot) {
        List<? extends OfficialVerificationRunView> coreRuns = safeRuns(officialResult);
        List<OperatorMetricSnapshot> operatorMetrics = summaryCalculator.safeOperatorMetrics(operatorSnapshot).stream()
                .filter(Objects::nonNull)
                .toList();
        List<OfficialVerificationMetricTrace> coreMetricRuns = coreRuns.stream()
                .sorted(Comparator.comparing(run -> normalize(run.endpointKey())))
                .map(run -> metricTraceMapper.toMetricDetail(run, sealedEvidence, operatorSnapshot))
                .toList();
        return operatorMetrics.size() > coreMetricRuns.size()
                ? operatorMetrics.stream()
                        .sorted(Comparator.comparing(metric -> normalize(metric.metricCode())))
                        .map(metric -> metricTraceMapper.toMetricDetail(metric, sealedEvidence, operatorSnapshot))
                        .toList()
                : coreMetricRuns;
    }

    private OfficialSealedEvidenceVerificationResult storedResult(
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
            String requested = resolvedAggregateRunId;
            selectedRuns = allPackageRuns.stream()
                    .filter(run -> same(requested, attemptSummaryFactory.aggregateRunId(run)))
                    .toList();
        }
        if (!StringUtils.hasText(aggregateRunId) && selectedRuns.isEmpty()) {
            resolvedAggregateRunId = latestAggregateRunId(allPackageRuns);
            if (StringUtils.hasText(resolvedAggregateRunId)) {
                String latest = resolvedAggregateRunId;
                selectedRuns = allPackageRuns.stream()
                        .filter(run -> same(latest, attemptSummaryFactory.aggregateRunId(run)))
                        .toList();
            } else {
                selectedRuns = List.copyOf(allPackageRuns);
            }
        }
        if (selectedRuns.isEmpty()) {
            return null;
        }
        RuntimeEvidencePackageSummary summary = sealedEvidence == null ? null : sealedEvidence.summary();
        String generatedAt = selectedRuns.stream()
                .map(run -> firstNonBlank(run.completedAt(), run.startedAt()))
                .filter(StringUtils::hasText)
                .max(String::compareTo)
                .orElseGet(() -> Instant.now().toString());
        return new OfficialSealedEvidenceVerificationResult(
                resolvedAggregateRunId, packageId,
                firstNonBlank(summary == null ? null : summary.userId(), "stored-official-ledger"),
                generatedAt, summary != null && summary.integrityValid(), selectedRuns);
    }

    private String latestAggregateRunId(List<OfficialVerificationRunView> runs) {
        String latestAggregateRunId = null;
        String latestCompletedAt = "";
        for (OfficialVerificationRunView run : runs) {
            if (run == null) {
                continue;
            }
            String aggregateRunId = attemptSummaryFactory.aggregateRunId(run);
            String completedAt = firstNonBlank(run.completedAt(), run.startedAt());
            if (!StringUtils.hasText(latestAggregateRunId) || completedAt.compareTo(latestCompletedAt) >= 0) {
                latestAggregateRunId = aggregateRunId;
                latestCompletedAt = completedAt;
            }
        }
        return latestAggregateRunId;
    }

    private List<OfficialVerificationRunView> safeRuns(OfficialSealedEvidenceVerificationResult result) {
        return result == null || result.runs() == null
                ? List.of()
                : result.runs().stream().filter(Objects::nonNull).toList();
    }

    private List<OfficialVerificationRunView> safeRunViews(List<OfficialVerificationRunView> runs) {
        return runs == null || runs.isEmpty() ? List.of() : runs.stream().filter(Objects::nonNull).toList();
    }

    private long elapsedMillis(long startedNanos) {
        return Math.max(0L, (System.nanoTime() - startedNanos) / 1_000_000L);
    }

    private boolean same(String left, String right) {
        return StringUtils.hasText(left) && StringUtils.hasText(right) && left.trim().equalsIgnoreCase(right.trim());
    }

    private String value(Map<String, String> raw, String key) {
        return raw == null || raw.get(key) == null ? null : raw.get(key).trim();
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

    private String requireText(String value, String errorMessage) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(errorMessage);
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

    record LoadedRunPackage(
            RuntimeEvidencePackageDetail sealedEvidence,
            List<OfficialVerificationRunView> allPackageRuns,
            OfficialSealedEvidenceVerificationResult officialResult,
            OperatorSnapshot operatorSnapshot,
            String aggregateRunId,
            List<OfficialVerificationMetricTrace> runs,
            long evidenceMs,
            long ledgerMs,
            long runtimeMs) {
    }
}
