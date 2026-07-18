package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorFinding;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityCustomerSentencePolicy;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyFindingResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import org.springframework.dao.DataAccessException;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

final class OfficialVerificationReverificationResultRecorder {

    private static final Set<String> PASS_STATES =
            Set.of("SUCCESS", "PASS", "PASSED", "VERIFIED", "COMPLETED");

    private final OfficialVerificationSnapshotQueryService snapshotQueryService;
    private final OfficialVerificationReverificationWriter writer;
    private final FinalPromptMetricContractCatalog metricContractCatalog;
    private final OfficialVerificationMessageResolver messageResolver;

    OfficialVerificationReverificationResultRecorder(
            ObjectMapper objectMapper,
            OfficialVerificationSnapshotQueryService snapshotQueryService,
            OfficialVerificationReverificationWriter writer) {
        this(
                objectMapper,
                snapshotQueryService,
                writer,
                OfficialVerificationMessageResolver.classpath(Locale.KOREAN));
    }

    OfficialVerificationReverificationResultRecorder(
            ObjectMapper objectMapper,
            OfficialVerificationSnapshotQueryService snapshotQueryService,
            OfficialVerificationReverificationWriter writer,
            OfficialVerificationMessageResolver messageResolver) {
        this.snapshotQueryService = snapshotQueryService;
        this.writer = writer;
        this.metricContractCatalog = FinalPromptMetricContractCatalog.load(objectMapper);
        this.messageResolver = messageResolver;
    }

    List<RuntimeEvidenceReverifyFindingResult> record(
            String sourcePackageId,
            String sourceAggregateRunId,
            List<String> findingIds,
            List<String> issueIds,
            RuntimeEvidenceVerificationRun fixedRun,
            String operatorId) {
        if (!StringUtils.hasText(sourcePackageId) || fixedRun == null || !StringUtils.hasText(fixedRun.packageId())) {
            return List.of();
        }
        requireTenant(fixedRun.tenantId());
        requirePersistedPackage(sourcePackageId, fixedRun.tenantId());
        requirePersistedPackage(fixedRun.packageId(), fixedRun.tenantId());
        List<OperatorFinding> findings = sourceFindings(
                snapshotQueryService.findLatest(sourcePackageId, sourceAggregateRunId), findingIds, issueIds);
        if (findings.isEmpty()) {
            return List.of();
        }
        String fixedAggregateRunId = safe(fixedRun.runId());
        writer.replace(sourcePackageId.trim(), fixedRun.packageId().trim(), fixedAggregateRunId, fixedRun.tenantId().trim());
        Map<String, RuntimeEvidenceMetricResult> fixedMetrics = fixedMetricsByCode(fixedRun);
        return findings.stream()
                .map(finding -> recordFinding(finding, fixedRun, fixedAggregateRunId, fixedMetrics, operatorId))
                .toList();
    }

    private void requireTenant(String tenantId) {
        if (!StringUtils.hasText(tenantId)) {
            throw new IllegalArgumentException("tenantId is required for official verification reverify mutation.");
        }
    }

    private void requirePersistedPackage(String packageId, String tenantId) {
        if (!StringUtils.hasText(packageId) || !snapshotQueryService.sealedEvidencePackageExists(packageId.trim(), tenantId.trim())) {
            throw new IllegalStateException(
                    "ENGINE_CONTRACT_ERROR: official verification package is not linked to tenant-scoped sealed evidence."
                            + " packageId=" + safe(packageId) + ", tenantId=" + safe(tenantId));
        }
    }

    private List<OperatorFinding> sourceFindings(
            OperatorSnapshot sourceSnapshot,
            List<String> findingIds,
            List<String> issueIds) {
        if (!sourceSnapshot.available() || sourceSnapshot.findings().isEmpty()) {
            return List.of();
        }
        Set<String> findingFilter = normalizedSet(findingIds);
        Set<String> issueFilter = normalizedSet(issueIds);
        return sourceSnapshot.findings().stream()
                .filter(finding -> finding != null)
                .filter(finding -> findingFilter.isEmpty() || findingFilter.contains(normalize(finding.findingId())))
                .filter(finding -> issueFilter.isEmpty() || issueFilter.contains(normalize(finding.issueId())))
                .toList();
    }

    private Map<String, RuntimeEvidenceMetricResult> fixedMetricsByCode(RuntimeEvidenceVerificationRun fixedRun) {
        return safeList(fixedRun.metrics()).stream()
                .filter(metric -> metric != null && StringUtils.hasText(metric.metricCode()))
                .collect(Collectors.toMap(
                        metric -> normalize(metric.metricCode()), metric -> metric,
                        (left, right) -> left, LinkedHashMap::new));
    }

    private RuntimeEvidenceReverifyFindingResult recordFinding(
            OperatorFinding finding,
            RuntimeEvidenceVerificationRun fixedRun,
            String fixedAggregateRunId,
            Map<String, RuntimeEvidenceMetricResult> fixedMetrics,
            String operatorId) {
        RuntimeEvidenceMetricResult fixedMetric = fixedMetrics.get(normalize(finding.metricCode()));
        RuntimeEvidenceCheckResult fixedCheck = matchingCheck(fixedMetric, finding.checkCode());
        boolean criterionPassed = fixedCheck != null ? fixedCheck.pass() : fixedMetric != null && passed(fixedMetric);
        boolean sourceIssueGone = sourceIssueGone(finding.issueId(), fixedRun);
        boolean resolved = criterionPassed && sourceIssueGone;
        String state = fixedMetric == null ? "NOT_VERIFIED" : resolved ? "RESOLVED" : "UNRESOLVED";
        String problemTitle = safe(
                finding.operatorTitle(),
                message("enterprise.pqa.runtimeVerification.reverify.problemTitle"));
        String summary = resolved
                ? message(
                        "enterprise.pqa.runtimeVerification.reverify.resolvedSummary",
                        problemTitle)
                : message(
                        "enterprise.pqa.runtimeVerification.reverify.unresolvedSummary",
                        problemTitle);
        RuntimeEvidenceReverifyFindingResult result = new RuntimeEvidenceReverifyFindingResult(
                safe(finding.packageId()), safe(finding.aggregateRunId()), safe(fixedRun.packageId()),
                fixedAggregateRunId, safe(finding.findingId()), safe(finding.issueId()), safe(finding.metricCode()),
                safe(finding.checkCode()), resolved, state, safe(finding.reverifyCriterion()),
                customerText("reverify.sourceOperatorReason", firstNonBlank(
                        finding.problemStatement(), finding.operatorReason(), finding.operatorSummary())),
                safe(finding.actualValue()), reverifiedActualValue(fixedMetric, fixedCheck, criterionPassed, sourceIssueGone),
                customerText("reverify.operatorSummary", summary));
        write(result, finding.expectedValue(), operatorId);
        return result;
    }

    private String reverifiedActualValue(
            RuntimeEvidenceMetricResult metric,
            RuntimeEvidenceCheckResult check,
            boolean criterionPassed,
            boolean sourceIssueGone) {
        if (criterionPassed && !sourceIssueGone) {
            return message("enterprise.pqa.runtimeVerification.reverify.sourceLinkUnresolved");
        }
        if (check != null) {
            return safe(check.actualValue());
        }
        return metric == null
                ? message("enterprise.pqa.runtimeVerification.reverify.metricMissing")
                : message(
                        "enterprise.pqa.runtimeVerification.reverify.latestMetricState",
                        safe(metric.state()));
    }

    private void write(
            RuntimeEvidenceReverifyFindingResult result,
            String sourceExpectedValue,
            String operatorId) {
        writer.insert(new OfficialVerificationReverificationWriter.Command(
                fit(result.sourcePackageId(), 256), fit(result.sourceAggregateRunId(), 256),
                fit(result.fixedPackageId(), 256), fit(result.fixedAggregateRunId(), 256),
                fit(result.findingId(), 256), fit(result.issueId(), 256), fit(result.metricCode(), 32),
                fit(result.checkCode(), 128), result.reverifyCriterion(), result.sourceOperatorReason(),
                sourceExpectedValue, result.sourceActualValue(), result.fixedActualValue(), result.resolved(),
                fit(result.resolutionState(), 64), result.operatorSummary(),
                fit(safe(operatorId, "runtime-pqa"), 128), OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION));
    }

    private boolean sourceIssueGone(String issueId, RuntimeEvidenceVerificationRun fixedRun) {
        if (!StringUtils.hasText(issueId)
                || !StringUtils.hasText(fixedRun.packageId())
                || !StringUtils.hasText(fixedRun.runId())) {
            return false;
        }
        try {
            return !snapshotQueryService.actualPromptProblemExists(
                    fixedRun.packageId().trim(), fixedRun.runId().trim(), issueId.trim());
        }
        catch (DataAccessException ignored) {
            return false;
        }
    }

    private RuntimeEvidenceCheckResult matchingCheck(RuntimeEvidenceMetricResult metric, String checkCode) {
        if (metric == null || metric.checks() == null || !StringUtils.hasText(checkCode)) {
            return null;
        }
        String metricCode = normalize(metric.metricCode());
        String normalizedCheckCode = normalize(canonicalCheckCode(metricCode, checkCode));
        return metric.checks().stream()
                .filter(check -> check != null
                        && normalizedCheckCode.equals(normalize(canonicalCheckCode(metricCode, check.checkCode()))))
                .findFirst()
                .orElse(null);
    }

    private String canonicalCheckCode(String metricCode, String checkCode) {
        String normalizedMetric = normalize(metricCode);
        String normalizedCheck = normalize(checkCode);
        if (!StringUtils.hasText(normalizedCheck)) {
            return "";
        }
        if (StringUtils.hasText(normalizedMetric)) {
            try {
                return metricContractCatalog.check(normalizedMetric, normalizedCheck).checkName();
            }
            catch (IllegalStateException ignored) {
                String prefix = normalizedMetric + "_";
                if (normalizedCheck.startsWith(prefix) && normalizedCheck.length() > prefix.length()) {
                    return normalizedCheck.substring(prefix.length());
                }
            }
        }
        return normalizedCheck;
    }

    private Set<String> normalizedSet(List<String> values) {
        Set<String> result = new LinkedHashSet<>();
        for (String value : safeList(values)) {
            String normalized = normalize(value);
            if (StringUtils.hasText(normalized)) {
                result.add(normalized);
            }
        }
        return Set.copyOf(result);
    }

    private boolean passed(RuntimeEvidenceMetricResult metric) {
        return PASS_STATES.contains(normalize(metric == null ? null : metric.state()));
    }

    private String message(String key, Object... args) {
        return messageResolver.resolve(key, args);
    }

    private String customerText(String fieldName, String value) {
        String text = concise(value, fieldName.toUpperCase(Locale.ROOT).contains("TITLE") ? 120 : 1200);
        return PromptQualityCustomerSentencePolicy.requireCustomerSentence(fieldName, text);
    }

    private String concise(String value, int maxLength) {
        if (!StringUtils.hasText(value)) {
            return value;
        }
        String cleaned = value.trim().replaceAll("\\s+", " ");
        return cleaned.length() <= maxLength ? cleaned : cleaned.substring(0, maxLength).trim();
    }

    private String fit(String value, int maxLength) {
        return !StringUtils.hasText(value) || value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

    private String firstNonBlank(String... values) {
        for (String value : values == null ? new String[0] : values) {
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

    private String safe(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : safe(fallback);
    }

    private <T> List<T> safeList(List<T> values) {
        return values == null ? List.of() : values;
    }
}
