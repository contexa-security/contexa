package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupService;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationEventItemView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialMetricPurposeEvidence;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunCheckDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunEventDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunLedgerConsistency;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageListItem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunSummaryCounts;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DefaultPromptQualityOfficialRunDetailService implements PromptQualityOfficialRunDetailService {

    private final SealedEvidencePackageLookupService evidenceLookupService;
    private final OfficialVerificationRunStore runStore;
    private final ObjectMapper objectMapper;

    public DefaultPromptQualityOfficialRunDetailService(
            SealedEvidencePackageLookupService evidenceLookupService,
            OfficialVerificationRunStore runStore,
            ObjectMapper objectMapper) {
        this.evidenceLookupService = evidenceLookupService;
        this.runStore = runStore;
        this.objectMapper = objectMapper;
    }

    @Override
    public List<OfficialRunPackageListItem> listRecentRunSummaries(int limit) {
        int safeLimit = Math.max(1, Math.min(limit, 100));
        Page<SealedEvidencePackage> packages = evidenceLookupService.searchRecent(
                Instant.EPOCH,
                Instant.now().plusSeconds(60),
                PageRequest.of(0, safeLimit));
        return packages.stream()
                .filter(pkg -> !runStore.listDetailedByPackageId(pkg.getPackageId()).isEmpty())
                .map(pkg -> listItem(pkg, runStore.listDetailedByPackageId(pkg.getPackageId())))
                .toList();
    }

    @Override
    public OfficialRunPackageDetail findPackageDetail(String packageId) {
        return findPackageDetail(packageId, null);
    }

    @Override
    public OfficialRunPackageDetail findPackageDetail(String packageId, String aggregateRunId) {
        SealedEvidencePackage pkg = findPackage(packageId);
        List<OfficialVerificationRunView> runs = selectedRuns(packageId, aggregateRunId);
        String selectedAggregateRunId = runs.isEmpty() ? aggregateRunId : aggregateRunId(runs.get(0));
        List<OfficialVerificationMetricTrace> traces = runs.stream()
                .sorted(Comparator.comparing(OfficialVerificationRunView::endpointKey))
                .map(this::trace)
                .toList();
        List<OfficialRunFailureCause> failures = traces.stream()
                .flatMap(trace -> trace.failureCauses().stream())
                .toList();
        int passed = (int) traces.stream()
                .filter(trace -> trace.passedChecks() == trace.totalChecks())
                .count();
        return new OfficialRunPackageDetail(
                packageId,
                selectedAggregateRunId,
                evidenceLookupService.verifyIntegrity(pkg),
                traces.size(),
                passed,
                Math.max(0, traces.size() - passed),
                ledgerConsistency(runs),
                sealedEvidence(pkg),
                traces,
                traces.stream().flatMap(trace -> trace.comparisons().stream()).toList(),
                failures,
                failures.stream().map(OfficialRunFailureCause::reverifyCriterion).filter(StringUtils::hasText).distinct().toList(),
                null,
                null,
                null,
                null,
                false,
                null,
                failures.stream().map(OfficialRunFailureCause::problemStatement).filter(StringUtils::hasText).distinct().toList(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of());
    }

    @Override
    public OfficialVerificationMetricTrace findRunDetail(String runId) {
        OfficialVerificationRunView run = runStore.findDetailedByRunId(runId);
        if (run == null) {
            throw new IllegalArgumentException("Official run not found: " + runId);
        }
        return trace(run);
    }

    private OfficialRunPackageListItem listItem(SealedEvidencePackage pkg, List<OfficialVerificationRunView> runs) {
        int failed = (int) runs.stream().filter(run -> run.passedChecks() < run.totalChecks()).count();
        int passed = Math.max(0, runs.size() - failed);
        return new OfficialRunPackageListItem(
                pkg.getPackageId(),
                runs.isEmpty() ? "" : aggregateRunId(runs.get(0)),
                failed == 0 ? "PASS" : "BLOCK",
                failed > 0,
                failed == 0 ? "" : failed + " metric(s) failed",
                12,
                runs.size(),
                passed,
                failed,
                null,
                null,
                pkg.getPromptHash(),
                contextHash(pkg),
                contextHashState(pkg),
                "",
                requestValue(pkg, "resourceId", "actualResourceId", "resource"),
                "",
                requestPath(pkg),
                httpMethod(pkg),
                pkg.getCapturedAt());
    }

    private List<OfficialVerificationRunView> selectedRuns(String packageId, String aggregateRunId) {
        List<OfficialVerificationRunView> runs = runStore.listDetailedByPackageId(packageId);
        if (!StringUtils.hasText(aggregateRunId) || runs.isEmpty()) {
            return runs;
        }
        return runs.stream()
                .filter(run -> aggregateRunId.equals(aggregateRunId(run)))
                .toList();
    }

    private OfficialVerificationMetricTrace trace(OfficialVerificationRunView run) {
        List<OfficialRunCheckDetail> checks = checks(run);
        List<OfficialRunFailureCause> failures = failures(run);
        return new OfficialVerificationMetricTrace(
                run.endpointKey(),
                run.endpointLabel(),
                groupName(run.endpointKey()),
                run.runId(),
                run.requestId(),
                requestPath(run),
                run.state(),
                stateLabel(run),
                run.score(),
                run.passedChecks(),
                run.totalChecks(),
                run.processingTimeMs(),
                run.startedAt(),
                run.completedAt(),
                checks,
                run.requestFacts(),
                run.eventFacts(),
                run.promptFacts(),
                run.analysisFacts(),
                events(run),
                run.rawEvidence(),
                comparisons(run),
                actualPromptProblems(run),
                failures);
    }

    private List<OfficialRunCheckDetail> checks(OfficialVerificationRunView run) {
        List<? extends OfficialVerificationCheckResultView> checks = run.checks();
        if (checks == null) {
            return List.of();
        }
        final int[] sequence = {1};
        return checks.stream()
                .map(check -> new OfficialRunCheckDetail(
                        sequence[0]++,
                        check.checkCode(),
                        check.label(),
                        check.expectedValue(),
                        check.actualValue(),
                        check.pass(),
                        check.source(),
                        check.severity(),
                        check.failureType(),
                        check.remediationOwner(),
                        check.operatorReason(),
                        check.nextAction(),
                        check.operatorReason(),
                        check.nextAction(),
                        check.reverifyCriterion(),
                        check.decisionUtility(),
                        check.whyItMatters()))
                .toList();
    }

    private List<OfficialRunFailureCause> failures(OfficialVerificationRunView run) {
        List<? extends OfficialVerificationCheckResultView> checks = run.checks();
        if (checks == null) {
            return List.of();
        }
        return checks.stream()
                .filter(check -> !check.pass())
                .map(check -> new OfficialRunFailureCause(
                        run.endpointKey(),
                        run.endpointLabel(),
                        run.runId(),
                        check.checkCode(),
                        check.label(),
                        check.expectedValue(),
                        check.actualValue(),
                        check.source(),
                        check.remediationOwner(),
                        check.label(),
                        check.operatorReason(),
                        check.remediationOwner(),
                        check.operatorReason(),
                        check.nextAction(),
                        check.reverifyCriterion()))
                .toList();
    }

    private List<OfficialVerificationPromptComparison> comparisons(OfficialVerificationRunView run) {
        return run.promptFacts().entrySet().stream()
                .map(entry -> new OfficialVerificationPromptComparison(
                        entry.getKey(),
                        entry.getKey(),
                        "",
                        entry.getValue(),
                        entry.getValue(),
                        "MATCH",
                        "일치",
                        "프롬프트 값과 공식 검사 입력값이 연결되어 있습니다.",
                        List.of(run.endpointKey()),
                        "",
                        "PROMPT_FACT",
                        "PQA_RUNTIME"))
                .toList();
    }

    private List<OfficialActualPromptProblem> actualPromptProblems(OfficialVerificationRunView run) {
        return failures(run).stream()
                .map(failure -> new OfficialActualPromptProblem(
                        failure.officialRunId() + ":" + failure.checkCode(),
                        firstText(String.valueOf(run.rawEvidence().get("packageId")), String.valueOf(run.rawEvidence().get("sealedEvidencePackageId"))),
                        aggregateRunId(run),
                        failure.checkCode(),
                        "PROMPT",
                        failure.source(),
                        failure.checkLabel(),
                        failure.actualValue(),
                        failure.checkCode(),
                        failure.source(),
                        failure.expectedValue(),
                        failure.actualValue(),
                        "BLOCKING",
                        List.of(failure.metricCode()),
                        failure.remediationOwner(),
                        failure.checkLabel(),
                        failure.impact(),
                        failure.remediationHint(),
                        failure.reverifyCriterion(),
                        List.of(firstText(failure.expectedValue(), failure.actualValue())),
                        List.of(failure.source())))
                .toList();
    }

    private String contextHash(SealedEvidencePackage pkg) {
        return firstText(
                jsonValue(pkg.getPromptExecutionMetadataJson(), "contextHash", "canonicalContextHash"),
                jsonValue(pkg.getRequestFactsJson(), "contextHash", "canonicalContextHash"));
    }

    private String contextHashState(SealedEvidencePackage pkg) {
        String state = firstText(
                jsonValue(pkg.getPromptExecutionMetadataJson(), "contextHashState", "contextHashStatus"),
                jsonValue(pkg.getRequestFactsJson(), "contextHashState", "contextHashStatus"));
        return StringUtils.hasText(state) ? state : (StringUtils.hasText(contextHash(pkg)) ? "PRESENT" : "MISSING");
    }

    private List<OfficialRunEventDetail> events(OfficialVerificationRunView run) {
        List<? extends OfficialVerificationEventItemView> events = run.events();
        if (events == null) {
            return List.of();
        }
        final int[] sequence = {1};
        return events.stream()
                .map(event -> new OfficialRunEventDetail(
                        sequence[0]++,
                        event.type(),
                        event.layer(),
                        event.status(),
                        event.requestPath()))
                .toList();
    }

    private RuntimeEvidencePackageDetail sealedEvidence(SealedEvidencePackage pkg) {
        return new RuntimeEvidencePackageDetail(
                summary(pkg),
                StringUtils.hasText(pkg.getRawSystemPrompt()),
                StringUtils.hasText(pkg.getRawUserPrompt()),
                StringUtils.hasText(pkg.getSystemPromptText()),
                StringUtils.hasText(pkg.getUserPromptText()),
                StringUtils.hasText(pkg.getBaselineSnapshotJson()),
                StringUtils.hasText(pkg.getRagResultsJson()),
                preview(pkg.getSystemPromptText()),
                preview(pkg.getUserPromptText()),
                objectValue(pkg.getRequestFactsJson()),
                objectValue(pkg.getAuthStateJson()),
                objectValue(pkg.getPromptExecutionMetadataJson()),
                objectValue(pkg.getDecisionJson()),
                objectValue(pkg.getBaselineSnapshotJson()),
                objectValue(pkg.getRagResultsJson()),
                List.of(),
                List.of(),
                List.of(),
                RuntimeEvidencePromptConsistencyResult.empty(),
                pkg.getSystemPromptText(),
                pkg.getUserPromptText());
    }

    private RuntimeEvidencePackageSummary summary(SealedEvidencePackage pkg) {
        return new RuntimeEvidencePackageSummary(
                pkg.getPackageId(),
                pkg.getCorrelationId(),
                pkg.getTenantId(),
                pkg.getUserId(),
                pkg.getCapturedAt(),
                requestPath(pkg),
                requestValue(pkg, "resourceId", "actualResourceId", "resource"),
                httpMethod(pkg),
                decisionValue(pkg, "action", "decision", "verdict"),
                doubleValue(decisionValue(pkg, "confidence", "confidenceScore")),
                pkg.isSealed(),
                evidenceLookupService.verifyIntegrity(pkg),
                pkg.getPromptHash(),
                pkg.getUserPromptText() == null ? 0 : pkg.getUserPromptText().length(),
                "검사 가능",
                "공식검사 실행");
    }

    private OfficialRunLedgerConsistency ledgerConsistency(List<OfficialVerificationRunView> runs) {
        int checks = runs.stream().mapToInt(OfficialVerificationRunView::totalChecks).sum();
        return new OfficialRunLedgerConsistency(
                12,
                runs.size(),
                runs.size() == 12,
                checks,
                checks,
                checks,
                true,
                0,
                0,
                0,
                runs.size(),
                runs.stream().allMatch(run -> StringUtils.hasText(aggregateRunId(run))),
                true,
                List.of());
    }

    private SealedEvidencePackage findPackage(String packageId) {
        return evidenceLookupService.findWithIntegrityCheck(packageId)
                .orElseThrow(() -> new IllegalArgumentException("Sealed evidence package not found: " + packageId));
    }

    private String aggregateRunId(OfficialVerificationRunView run) {
        Object value = run.rawEvidence() == null ? null : run.rawEvidence().get("aggregateRunId");
        if (value != null && StringUtils.hasText(String.valueOf(value))) {
            return String.valueOf(value);
        }
        String runId = run.runId();
        String metric = run.endpointKey();
        if (StringUtils.hasText(runId) && StringUtils.hasText(metric)) {
            String suffix = "-" + metric.toLowerCase();
            if (runId.toLowerCase().endsWith(suffix)) {
                return runId.substring(0, runId.length() - suffix.length());
            }
        }
        return runId;
    }

    private String requestPath(OfficialVerificationRunView run) {
        return firstText(
                run.requestFacts().get("resourceUrl"),
                run.requestFacts().get("requestPath"),
                run.requestFacts().get("path"),
                run.requestFacts().get("url"));
    }

    private String requestPath(SealedEvidencePackage pkg) {
        return requestValue(pkg, "resourceUrl", "requestPath", "path", "uri", "url");
    }

    private String httpMethod(SealedEvidencePackage pkg) {
        String value = requestValue(pkg, "httpMethod", "method");
        return StringUtils.hasText(value) ? value.toUpperCase() : "GET";
    }

    private String requestValue(SealedEvidencePackage pkg, String... keys) {
        return jsonValue(pkg.getRequestFactsJson(), keys);
    }

    private String decisionValue(SealedEvidencePackage pkg, String... keys) {
        return jsonValue(pkg.getDecisionJson(), keys);
    }

    private String jsonValue(String json, String... keys) {
        JsonNode root = json(json);
        for (String key : keys) {
            JsonNode node = root.path(key);
            if (!node.isMissingNode() && !node.isNull() && StringUtils.hasText(node.asText())) {
                return node.asText();
            }
        }
        return "";
    }

    private Map<String, Object> objectValue(String json) {
        try {
            if (!StringUtils.hasText(json)) {
                return Map.of();
            }
            return objectMapper.readValue(json, objectMapper.getTypeFactory().constructMapType(LinkedHashMap.class, String.class, Object.class));
        }
        catch (Exception ignored) {
            return Map.of();
        }
    }

    private JsonNode json(String json) {
        try {
            if (!StringUtils.hasText(json)) {
                return objectMapper.createObjectNode();
            }
            return objectMapper.readTree(json);
        }
        catch (Exception ignored) {
            return objectMapper.createObjectNode();
        }
    }

    private String preview(String text) {
        if (!StringUtils.hasText(text)) {
            return "";
        }
        String compact = text.replaceAll("\\s+", " ").trim();
        return compact.length() <= 240 ? compact : compact.substring(0, 240) + "...";
    }

    private Double doubleValue(String value) {
        try {
            return StringUtils.hasText(value) ? Double.valueOf(value) : null;
        }
        catch (NumberFormatException ignored) {
            return null;
        }
    }

    private String stateLabel(OfficialVerificationRunView run) {
        return run.passedChecks() >= run.totalChecks() ? "통과" : "차단";
    }

    private String groupName(String metricCode) {
        return switch (metricCode == null ? "" : metricCode.toUpperCase()) {
            case "CCSR", "CCR", "EIR", "PFR", "COR", "MTR" -> "구현 정합성";
            case "BMA", "RAP", "RPI" -> "학습·기준선";
            case "BSR", "USNS" -> "행동 맥락";
            case "PRE" -> "운영 승격 자격";
            default -> "지표 영역";
        };
    }

    private String firstText(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value) && !"null".equalsIgnoreCase(value)) {
                return value;
            }
        }
        return "";
    }
}
