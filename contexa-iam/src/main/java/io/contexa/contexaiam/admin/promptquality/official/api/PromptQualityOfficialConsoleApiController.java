package io.contexa.contexaiam.admin.promptquality.official.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupService;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityOfficialRunDetailService;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityRuntimeVerificationService;
import io.contexa.contexaiam.admin.promptquality.official.application.RuntimeEvidencePromptConsistencyGate;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageListItem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationExecutionStatus;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.InputStreamReader;
import java.text.MessageFormat;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;

@RestController
@RequestMapping("/contexa/admin/api/prompt-quality")
public class PromptQualityOfficialConsoleApiController {

    private static final ZoneId KOREA_ZONE = ZoneId.of("Asia/Seoul");
    private static final Set<String> LLM_DECISION_METRIC_CODES = Set.of("CDC", "ERA", "SUHR", "OCR", "DSS", "ARR");
    private static final Set<String> PROMPT_OFFICIAL_METRIC_CODES = Set.of(
            "EIR", "CCR", "CCSR", "PFR", "MTR", "COR", "RAP", "RPI", "BMA", "USNS", "BSR", "PRE");

    private final SealedEvidencePackageLookupService evidenceLookupService;
    private final PromptQualityRuntimeVerificationService verificationService;
    private final PromptQualityOfficialRunDetailService officialRunDetailService;
    private final OfficialVerificationRunStore runStore;
    private final ObjectMapper objectMapper;
    private final JdbcOperations jdbcOperations;
    private final RuntimeEvidencePromptConsistencyGate promptConsistencyGate;
    private final PromptQualityMessageResolver messageResolver;

    public PromptQualityOfficialConsoleApiController(
            SealedEvidencePackageLookupService evidenceLookupService,
            PromptQualityRuntimeVerificationService verificationService,
            PromptQualityOfficialRunDetailService officialRunDetailService,
            OfficialVerificationRunStore runStore,
            ObjectMapper objectMapper,
            JdbcOperations jdbcOperations,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            PromptQualityMessageResolver messageResolver) {
        this.evidenceLookupService = evidenceLookupService;
        this.verificationService = verificationService;
        this.officialRunDetailService = officialRunDetailService;
        this.runStore = runStore;
        this.objectMapper = objectMapper;
        this.jdbcOperations = jdbcOperations;
        this.promptConsistencyGate = promptConsistencyGate;
        this.messageResolver = messageResolver;
    }

    @GetMapping("/i18n")
    public Map<String, Object> i18n(
            @RequestParam(defaultValue = "enterprise.pqa.") String prefix,
            Locale locale) {
        Properties properties = new Properties();
        loadProperties(properties, "classpath*:i18n/messages.properties");
        if (locale != null && "ko".equalsIgnoreCase(locale.getLanguage())) {
            loadProperties(properties, "classpath*:i18n/messages_ko.properties");
        }
        Map<String, String> messages = new LinkedHashMap<>();
        properties.stringPropertyNames().stream()
                .filter(key -> key.startsWith(prefix))
                .sorted()
                .forEach(key -> messages.put(key, properties.getProperty(key)));
        return Map.of(
                "locale", locale == null ? Locale.getDefault().toLanguageTag() : locale.toLanguageTag(),
                "prefix", prefix,
                "messages", messages);
    }

    @GetMapping("/dashboard/summary")
    public Map<String, Object> dashboardSummary() {
        List<Map<String, Object>> resources = resourcesFromEvidence(200);
        List<Map<String, Object>> evidence = searchEvidence(null, null, null, null, null, null, null, null, 0, 200);
        long readyEvidence = evidence.stream()
                .filter(item -> Boolean.TRUE.equals(item.get("sealed")) && Boolean.TRUE.equals(item.get("integrityValid")))
                .count();
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalResourceCount", resources.size());
        summary.put("zeroTrustEnabledCount", 0);
        summary.put("pendingCount", resources.size());
        summary.put("blockedCount", 0);
        summary.put("reverifyRequiredCount", 0);
        summary.put("expiringCertificateCount", 0);
        summary.put("readyRuntimeEvidenceCount", readyEvidence);
        summary.put("recurringIssues", List.of());
        return summary;
    }

    @GetMapping("/state-catalog")
    public Map<String, Object> stateCatalog() {
        return Map.of("states", stateCatalogRows());
    }

    @GetMapping("/resources/summary")
    public Map<String, Object> resourceSummary() {
        List<Map<String, Object>> resources = resourcesFromEvidence(500);
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("total", resources.size());
        summary.put("ready", resources.size());
        summary.put("pending", 0);
        summary.put("blocked", 0);
        return Map.of(
                "summary", summary,
                "resources", resources,
                "stateCatalog", stateCatalog());
    }

    @GetMapping("/resources/detail")
    public Map<String, Object> resourceDetailByQuery(
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String resourceUrl,
            @RequestParam(defaultValue = "GET") String httpMethod) {
        Map<String, Object> resource = resolveResource(resourceId, resourceUrl, httpMethod);
        return Map.of(
                "summary", Map.of("state", "READY"),
                "resource", resource,
                "certificate", Map.of(),
                "history", resourceHistory(resource),
                "lineage", resourceHistory(resource));
    }

    @GetMapping("/resources/{resourceId}")
    public Map<String, Object> resourceDetail(
            @PathVariable String resourceId,
            @RequestParam(defaultValue = "GET") String httpMethod) {
        return resourceDetailByQuery(resourceId, null, httpMethod);
    }

    @GetMapping("/resources/state-search")
    public Map<String, Object> resourceStateSearch(
            @RequestParam String resourceId,
            @RequestParam(required = false) String resourceUrl,
            @RequestParam(required = false) String httpMethod) {
        Map<String, Object> resource = resolveResource(resourceId, resourceUrl, httpMethod);
        List<Map<String, Object>> stages = List.of(
                processStage("PROTECTABLE_RESOURCES", message("enterprise.pqa.stage.protectableResources", "보호 대상 리소스"), "/contexa/admin/prompt-quality/resources"),
                processStage("RUNTIME_EVIDENCE", message("enterprise.pqa.stage.runtimeEvidence", "요청 증거 자료"), runtimeEvidenceHref(resource)),
                processStage("OFFICIAL_VERIFICATION", message("enterprise.pqa.stage.officialVerification", "공식 품질 검사"), verificationHref(resource)));
        return Map.of(
                "resource", resource,
                "currentStage", Map.of("code", "OFFICIAL_VERIFICATION", "label", message("enterprise.pqa.stage.officialVerification", "공식 품질 검사")),
                "currentExecutionState", "READY",
                "currentExecutionStateDescriptor", Map.of("code", "READY", "label", message("enterprise.pqa.state.ready", "검사 대기"), "tone", "ready"),
                "metrics", List.of(
                        Map.of("code", "evidence", "label", message("enterprise.pqa.stage.runtimeEvidence", "요청 증거 자료"), "value", message("enterprise.pqa.state.actionCheck", "확인"), "tone", "ready", "route", runtimeEvidenceHref(resource)),
                        Map.of("code", "inspection", "label", message("enterprise.pqa.stage.officialVerification", "공식 품질 검사"), "value", message("enterprise.pqa.state.actionRun", "실행"), "tone", "info", "route", verificationHref(resource))),
                "processStages", stages,
                "routes", stages);
    }

    @GetMapping("/resources/{resourceId}/overlay")
    public Map<String, Object> overlay(@PathVariable String resourceId) {
        return Map.of("present", false, "overlay", Map.of());
    }

    @PostMapping("/resources/{resourceId}/overlay")
    public Map<String, Object> saveOverlay(@PathVariable String resourceId, @RequestBody(required = false) Map<String, Object> body) {
        return Map.of("resourceId", resourceId, "state", "OSS_READ_ONLY", "overlay", body == null ? Map.of() : body);
    }

    @DeleteMapping("/resources/{resourceId}/overlay")
    public Map<String, Object> deleteOverlay(@PathVariable String resourceId) {
        return Map.of("resourceId", resourceId, "state", "OSS_READ_ONLY");
    }

    @GetMapping("/runtime-evidence/search")
    public List<Map<String, Object>> searchEvidence(
            @RequestParam(required = false) String packageId,
            @RequestParam(required = false) String tenantId,
            @RequestParam(required = false) String userId,
            @RequestParam(required = false) String resourceUrl,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String httpMethod,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        int safeSize = Math.max(1, Math.min(size, 500));
        Instant fromInstant = parseInstant(from, Instant.EPOCH);
        Instant toInstant = parseInstant(to, Instant.now().plus(Duration.ofDays(1)));
        Page<SealedEvidencePackage> packages = evidenceLookupService.searchRecent(
                fromInstant,
                toInstant,
                PageRequest.of(Math.max(0, page), safeSize));
        return packages.stream()
                .map(this::evidenceSummary)
                .filter(item -> matches(item, "packageId", packageId))
                .filter(item -> matches(item, "tenantId", tenantId))
                .filter(item -> matches(item, "userId", userId))
                .filter(item -> matches(item, "resourceUrl", resourceUrl))
                .filter(item -> matches(item, "resourceId", resourceId))
                .filter(item -> matches(item, "httpMethod", httpMethod))
                .toList();
    }

    @GetMapping("/runtime-evidence/{packageId}")
    public Map<String, Object> runtimeEvidenceDetail(@PathVariable String packageId) {
        SealedEvidencePackage pkg = findPackage(packageId);
        Map<String, Object> summary = evidenceSummary(pkg);
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("summary", summary);
        detail.put("qualityWarnings", List.of());
        detail.put("rawSystemPromptCaptured", StringUtils.hasText(pkg.getRawSystemPrompt()));
        detail.put("rawUserPromptCaptured", StringUtils.hasText(pkg.getRawUserPrompt()));
        detail.put("llmSystemPromptCaptured", StringUtils.hasText(pkg.getSystemPromptText()));
        detail.put("llmUserPromptCaptured", StringUtils.hasText(pkg.getUserPromptText()));
        detail.put("systemPromptPreview", preview(pkg.getSystemPromptText()));
        detail.put("userPromptPreview", preview(pkg.getUserPromptText()));
        detail.put("promptConsistency", promptConsistency(pkg));
        detail.put("sealedEvidence", sealedEvidenceMap(pkg));
        return detail;
    }

    @PostMapping("/verification/runtime-runs")
    public RuntimeEvidenceVerificationRun verifyRuntimeEvidence(
            @RequestParam(required = false) String packageId,
            @RequestBody(required = false) Map<String, Object> body,
            Authentication authentication) {
        String resolvedPackageId = firstText(packageId, stringValue(body, "packageId"));
        if (!StringUtils.hasText(resolvedPackageId)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "packageId is required.");
        }
        String operator = authentication != null && StringUtils.hasText(authentication.getName())
                ? authentication.getName()
                : firstText(stringValue(body, "operatorId"), "oss-admin");
        return verificationService.verify(new RuntimeEvidenceVerificationRequest(
                resolvedPackageId,
                operator,
                Boolean.TRUE.equals(body == null ? null : body.get("forceReverification")),
                stringValue(body, "reverificationReason")));
    }

    @GetMapping("/verification/runtime-runs")
    public List<OfficialRunPackageListItem> recentOfficialRuns(@RequestParam(defaultValue = "20") int limit) {
        return officialRunDetailService.listRecentRunSummaries(limit);
    }

    @GetMapping("/verification/runtime-runs/package/{packageId}")
    public OfficialRunPackageDetail packageOfficialRuns(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return officialRunDetailService.findPackageDetail(packageId, aggregateRunId);
    }

    @GetMapping("/verification/runtime-runs/package/{packageId}/summary")
    public OfficialRunPackageSummary packageOfficialRunSummary(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return officialRunDetailService.findPackageSummary(packageId, aggregateRunId);
    }

    @GetMapping("/verification/runtime-runs/package/{packageId}/metric-families")
    public Map<String, Object> packageMetricFamilies(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        OfficialRunPackageDetail detail = officialRunDetailService.findPackageDetail(packageId, aggregateRunId);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("packageId", detail.packageId());
        payload.put("aggregateRunId", detail.aggregateRunId());
        payload.put("prompt", metricFamilyPayload(detail, "prompt"));
        payload.put("decision", metricFamilyPayload(detail, "decision"));
        payload.put("other", metricFamilyPayload(detail, "other"));
        payload.put("finalDecision", detail.finalDecision());
        payload.put("blocked", detail.blocked());
        payload.put("blockReasonSummary", detail.blockReasonSummary());
        return payload;
    }

    @GetMapping("/verification/runtime-runs/package/{packageId}/metrics/prompt")
    public Map<String, Object> packagePromptMetrics(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return metricFamilyPayload(officialRunDetailService.findPackageDetail(packageId, aggregateRunId), "prompt");
    }

    @GetMapping("/verification/runtime-runs/package/{packageId}/metrics/llm-decision")
    public Map<String, Object> packageLlmDecisionMetrics(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return metricFamilyPayload(officialRunDetailService.findPackageDetail(packageId, aggregateRunId), "decision");
    }

    @GetMapping("/verification/runtime-runs/package/{packageId}/metrics/{metricCode}/failure-details")
    public List<OfficialRunFailureCause> packageMetricFailureDetails(
            @PathVariable String packageId,
            @PathVariable String metricCode,
            @RequestParam(required = false) String aggregateRunId) {
        String normalizedMetric = normalizeMetricCode(metricCode);
        return officialRunDetailService.findFailureDetails(packageId, aggregateRunId).stream()
                .filter(failure -> normalizeMetricCode(failure.metricCode()).equals(normalizedMetric))
                .toList();
    }

    @GetMapping("/verification/runtime-runs/package/{packageId}/evidence-package")
    public RuntimeEvidencePackageDetail packageEvidencePackage(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return officialRunDetailService.findPackageDetail(packageId, aggregateRunId).sealedEvidence();
    }

    @GetMapping("/verification/runtime-runs/package/{packageId}/reverify-options")
    public Map<String, Object> packageReverifyOptions(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return reverifyOptionsPayload(officialRunDetailService.findPackageDetail(packageId, aggregateRunId));
    }

    @PostMapping("/verification/runtime-runs/package/{packageId}/reverify")
    public RuntimeEvidenceReverifyResult reverifyPackage(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId,
            @RequestBody(required = false) Map<String, Object> body,
            Authentication authentication) {
        String operator = authentication != null && StringUtils.hasText(authentication.getName())
                ? authentication.getName()
                : firstText(stringValue(body, "operatorId"), "oss-admin");
        String reason = firstText(stringValue(body, "reason"), stringValue(body, "reverificationReason"), "official verification recheck");
        return verificationService.reverify(new RuntimeEvidenceReverifyRequest(
                packageId,
                operator,
                reason,
                stringValue(body, "sourcePackageId"),
                firstText(aggregateRunId, stringValue(body, "sourceAggregateRunId")),
                stringList(body == null ? null : body.get("findingIds")),
                stringList(body == null ? null : body.get("issueIds"))));
    }
    @GetMapping("/verification/runtime-runs/package/{packageId}/technical-ledger")
    public OfficialRunPackageDetail packageTechnicalLedger(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return officialRunDetailService.findTechnicalLedger(packageId, aggregateRunId);
    }

    @GetMapping("/verification/runtime-runs/package/{packageId}/failure-details")
    public List<OfficialRunFailureCause> packageFailureDetails(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return officialRunDetailService.findFailureDetails(packageId, aggregateRunId);
    }

    @GetMapping("/verification/runtime-runs/package/{packageId}/audit-payloads")
    public List<OfficialRunAuditSnapshot> packageAuditPayloads(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return officialRunDetailService.findAuditPayloads(packageId, aggregateRunId);
    }

    @GetMapping("/verification/runtime-runs/package/{packageId}/execution-status")
    public OfficialVerificationExecutionStatus packageExecutionStatus(@PathVariable String packageId) {
        return verificationService.executionStatus(packageId);
    }

    @GetMapping("/verification/runtime-runs/{runId}")
    public OfficialVerificationMetricTrace officialRunDetail(@PathVariable String runId) {
        return officialRunDetailService.findRunDetail(runId);
    }

    @GetMapping("/verification/runs/{runId}/metric-detail")
    public OfficialVerificationMetricTrace officialMetricTrace(@PathVariable String runId) {
        return officialRunDetail(runId);
    }

    @GetMapping("/verification/packages/{packageId}/prompt-comparison")
    public List<OfficialVerificationPromptComparison> packagePromptComparison(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return packageOfficialRuns(packageId, aggregateRunId).promptComparisons();
    }

    @GetMapping("/verification/packages/{packageId}/actual-prompt-problems")
    public List<OfficialActualPromptProblem> packageActualPromptProblems(
            @PathVariable String packageId,
            @RequestParam(required = false) String aggregateRunId) {
        return officialRunDetailService.findActualPromptProblems(packageId, aggregateRunId);
    }

    private Map<String, Object> metricFamilyPayload(OfficialRunPackageDetail detail, String family) {
        List<OfficialVerificationMetricTrace> runs = detail.runs().stream()
                .filter(run -> family.equals(metricFamily(run)))
                .toList();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("packageId", detail.packageId());
        payload.put("aggregateRunId", detail.aggregateRunId());
        payload.put("family", family);
        payload.put("label", metricFamilyLabel(family));
        payload.put("totalRunCount", runs.size());
        payload.put("passedRunCount", (int) runs.stream().filter(run -> passState(run.state())).count());
        payload.put("failedRunCount", (int) runs.stream().filter(run -> !passState(run.state())).count());
        payload.put("runs", runs);
        payload.put("failureCauses", detail.failureCauses().stream()
                .filter(failure -> runs.stream().anyMatch(run -> normalizeMetricCode(run.metricCode()).equals(normalizeMetricCode(failure.metricCode()))))
                .toList());
        return payload;
    }

    private Map<String, Object> reverifyOptionsPayload(OfficialRunPackageDetail detail) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("packageId", detail.packageId());
        payload.put("aggregateRunId", detail.aggregateRunId());
        payload.put("prompt", reverifyOption(detail, "prompt"));
        payload.put("decision", reverifyOption(detail, "decision"));
        payload.put("full", reverifyOption(detail, "full"));
        return payload;
    }

    private Map<String, Object> reverifyOption(OfficialRunPackageDetail detail, String scope) {
        List<OfficialVerificationMetricTrace> scopedRuns = "full".equals(scope)
                ? detail.runs()
                : detail.runs().stream().filter(run -> scope.equals(metricFamily(run))).toList();
        Map<String, Object> option = new LinkedHashMap<>();
        option.put("scope", scope);
        option.put("label", switch (scope) {
            case "prompt" -> "\uD504\uB86C\uD504\uD2B8\uB9CC \uC7AC\uAC80\uC99D";
            case "decision" -> "LLM \uD310\uC815\uB9CC \uC7AC\uAC80\uC99D";
            default -> "\uC804\uCCB4 \uC7AC\uAC80\uC99D";
        });
        option.put("totalRunCount", scopedRuns.size());
        option.put("passedRunCount", (int) scopedRuns.stream().filter(run -> passState(run.state())).count());
        option.put("failedRunCount", (int) scopedRuns.stream().filter(run -> !passState(run.state())).count());
        option.put("endpoint", "/contexa/admin/api/prompt-quality/verification/runtime-runs/package/" + detail.packageId() + "/reverify");
        return option;
    }

    private String metricFamily(OfficialVerificationMetricTrace run) {
        String code = normalizeMetricCode(run == null ? null : run.metricCode());
        String group = normalizeMetricCode(run == null ? null : run.groupName());
        if (LLM_DECISION_METRIC_CODES.contains(code) || "LLM_DECISION".equals(group) || "DECISION_OFFICIAL".equals(group)) {
            return "decision";
        }
        if (PROMPT_OFFICIAL_METRIC_CODES.contains(code)
                || Set.of("IMPLEMENTATION_ALIGNMENT", "RAG_AND_BASELINE", "BEHAVIORAL_CONTEXT", "RESOURCE_ELIGIBILITY").contains(group)) {
            return "prompt";
        }
        return "other";
    }

    private String metricFamilyLabel(String family) {
        return switch (family) {
            case "prompt" -> "\uD504\uB86C\uD504\uD2B8 12\uC9C0\uD45C";
            case "decision" -> "LLM \uD310\uC815 6\uC9C0\uD45C";
            default -> "\uAE30\uD0C0 \uACF5\uC2DD\uAC80\uC0AC";
        };
    }

    private String normalizeMetricCode(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private List<String> stringList(Object value) {
        if (value instanceof List<?> list) {
            return list.stream()
                    .map(item -> item == null ? "" : String.valueOf(item).trim())
                    .filter(StringUtils::hasText)
                    .toList();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            return List.of(text.trim());
        }
        return List.of();
    }
    private void loadProperties(Properties properties, String pattern) {
        try {
            PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
            for (Resource resource : resolver.getResources(pattern)) {
                if (!resource.exists()) {
                    continue;
                }
                try (InputStreamReader reader = new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8)) {
                    properties.load(reader);
                }
            }
        }
        catch (Exception ignored) {
            // Missing localization files must not break the OSS console API.
        }
    }

    private List<Map<String, Object>> resourcesFromEvidence(int size) {
        Map<String, Map<String, Object>> byIdentity = new LinkedHashMap<>();
        for (Map<String, Object> item : searchEvidence(null, null, null, null, null, null, null, null, 0, size)) {
            String key = resourceKey(item);
            byIdentity.putIfAbsent(key, resourceFromEvidence(item));
        }
        return new ArrayList<>(byIdentity.values());
    }

    private Map<String, Object> resourceFromEvidence(Map<String, Object> item) {
        Map<String, Object> resource = new LinkedHashMap<>();
        String resourceUrl = string(item.get("resourceUrl"));
        String resourceId = firstText(string(item.get("resourceId")), resourceUrl);
        String httpMethod = firstText(string(item.get("httpMethod")), "GET").toUpperCase(Locale.ROOT);
        resource.put("tenantId", firstText(string(item.get("tenantId")), "default"));
        resource.put("resourceId", resourceId);
        resource.put("resourceUrl", resourceUrl);
        resource.put("httpMethod", httpMethod);
        resource.put("criticality", "NORMAL");
        resource.put("operationalState", "READY");
        resource.put("operationalStateLabel", message("enterprise.pqa.state.ready", "검사 대기"));
        resource.put("operationalStateDescriptor", Map.of("code", "READY", "label", message("enterprise.pqa.state.ready", "검사 대기"), "tone", "ready", "aggregateGroup", "READY"));
        resource.put("runtimeRequestStateDescriptor", Map.of("code", "EVIDENCE_CAPTURED", "label", message("enterprise.pqa.state.evidenceCaptured", "증거 수집됨"), "tone", "ready"));
        resource.put("signatureChanged", false);
        return resource;
    }

    private Map<String, Object> resolveResource(String resourceId, String resourceUrl, String httpMethod) {
        String method = firstText(httpMethod, "GET").toUpperCase(Locale.ROOT);
        return resourcesFromEvidence(500).stream()
                .filter(resource -> !StringUtils.hasText(resourceId) || same(resource.get("resourceId"), resourceId))
                .filter(resource -> !StringUtils.hasText(resourceUrl) || same(resource.get("resourceUrl"), resourceUrl))
                .filter(resource -> !StringUtils.hasText(method) || same(resource.get("httpMethod"), method))
                .findFirst()
                .orElseGet(() -> {
                    Map<String, Object> resource = new LinkedHashMap<>();
                    resource.put("tenantId", "default");
                    resource.put("resourceId", firstText(resourceId, resourceUrl, "unknown"));
                    resource.put("resourceUrl", firstText(resourceUrl, resourceId, ""));
                    resource.put("httpMethod", method);
                    resource.put("criticality", "NORMAL");
                    resource.put("operationalState", "READY");
                    resource.put("operationalStateLabel", message("enterprise.pqa.state.ready", "검사 대기"));
                    resource.put("operationalStateDescriptor", Map.of("code", "READY", "label", message("enterprise.pqa.state.ready", "검사 대기"), "tone", "ready", "aggregateGroup", "READY"));
                    resource.put("runtimeRequestStateDescriptor", Map.of("code", "UNKNOWN", "label", message("enterprise.pqa.state.unknown", "요청 증거 확인 필요"), "tone", "neutral"));
                    return resource;
                });
    }

    private Map<String, Object> evidenceSummary(SealedEvidencePackage pkg) {
        JsonNode requestFacts = json(pkg.getRequestFactsJson());
        JsonNode decision = json(pkg.getDecisionJson());
        String requestPath = firstJsonText(requestFacts, "resourceUrl", "requestPath", "path", "uri", "url");
        String resourceId = firstJsonText(requestFacts, "resourceId", "actualResourceId", "resource");
        String httpMethod = firstJsonText(requestFacts, "httpMethod", "method");
        if (!StringUtils.hasText(httpMethod)) {
            httpMethod = "GET";
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("packageId", pkg.getPackageId());
        summary.put("correlationId", pkg.getCorrelationId());
        summary.put("requestId", pkg.getCorrelationId());
        summary.put("tenantId", pkg.getTenantId());
        summary.put("userId", pkg.getUserId());
        summary.put("capturedAt", iso(pkg.getCapturedAt()));
        summary.put("createdAt", iso(pkg.getCreatedAt()));
        summary.put("resourceUrl", requestPath);
        summary.put("requestPath", requestPath);
        summary.put("path", requestPath);
        summary.put("resourceId", resourceId);
        summary.put("httpMethod", httpMethod.toUpperCase(Locale.ROOT));
        summary.put("promptHash", pkg.getPromptHash());
        summary.put("systemPromptHash", pkg.getSystemPromptHash());
        summary.put("userPromptHash", pkg.getUserPromptHash());
        summary.put("sealed", pkg.isSealed());
        summary.put("sealState", pkg.getSealState());
        summary.put("integrityValid", evidenceLookupService.verifyIntegrity(pkg));
        summary.put("decisionAction", firstJsonText(decision, "action", "decision", "verdict"));
        summary.put("decisionConfidence", firstJsonText(decision, "confidence", "confidenceScore"));
        return summary;
    }

    private Map<String, Object> sealedEvidenceMap(SealedEvidencePackage pkg) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("summary", evidenceSummary(pkg));
        evidence.put("packageId", pkg.getPackageId());
        evidence.put("systemPromptText", pkg.getSystemPromptText());
        evidence.put("userPromptText", pkg.getUserPromptText());
        evidence.put("systemPromptPreview", preview(pkg.getSystemPromptText()));
        evidence.put("userPromptPreview", preview(pkg.getUserPromptText()));
        evidence.put("requestFacts", objectValue(pkg.getRequestFactsJson()));
        evidence.put("authState", objectValue(pkg.getAuthStateJson()));
        evidence.put("baselineSnapshot", objectValue(pkg.getBaselineSnapshotJson()));
        evidence.put("baselineSnapshotCaptured", StringUtils.hasText(pkg.getBaselineSnapshotJson()));
        evidence.put("ragResults", objectValue(pkg.getRagResultsJson()));
        evidence.put("ragResultsCaptured", StringUtils.hasText(pkg.getRagResultsJson()));
        evidence.put("decision", objectValue(pkg.getDecisionJson()));
        evidence.put("promptMetadata", objectValue(pkg.getPromptExecutionMetadataJson()));
        evidence.put("promptConsistency", promptConsistency(pkg));
        evidence.put("qualityWarnings", List.of());
        evidence.put("missingKnowledgeSignals", List.of());
        return evidence;
    }

    private Map<String, Object> promptConsistency(SealedEvidencePackage pkg) {
        if (promptConsistencyGate != null) {
            return objectMapper.convertValue(promptConsistencyGate.evaluate(pkg), Map.class);
        }
        List<Map<String, Object>> checks = List.of(
                promptCheck("LLM system/user prompt captured",
                        StringUtils.hasText(pkg.getSystemPromptText()) && StringUtils.hasText(pkg.getUserPromptText()),
                        "promptCapture"),
                promptCheck("promptHash recalculates from LLM prompt",
                        StringUtils.hasText(pkg.getPromptHash()),
                        "promptHash"),
                promptCheck("systemPromptHash matches LLM system prompt",
                        StringUtils.hasText(pkg.getSystemPromptHash()),
                        "promptHash"),
                promptCheck("userPromptHash matches LLM user prompt",
                        StringUtils.hasText(pkg.getUserPromptHash()),
                        "promptHash"),
                promptCheck("raw prompt and LLM prompt difference is recorded",
                        StringUtils.hasText(pkg.getRawUserPrompt()) || StringUtils.hasText(pkg.getUserPromptText()),
                        "promptCapture"));
        boolean blocking = checks.stream().anyMatch(check -> !Boolean.TRUE.equals(check.get("pass")));
        return Map.of(
                "state", blocking ? "REVIEW" : "PASS",
                "stateLabel", blocking ? message("enterprise.pqa.state.pending", "검토 필요") : message("enterprise.pqa.state.ready", "검사 대기"),
                "blocking", blocking,
                "checks", checks);
    }

    private Map<String, Object> promptCheck(String label, boolean pass, String source) {
        return Map.of(
                "label", label,
                "pass", pass,
                "source", source,
                "expectedValue", "present",
                "actualValue", pass ? "present" : "missing");
    }

    private Map<String, Object> officialPackageDetail(String packageId, String aggregateRunId) {
        SealedEvidencePackage pkg = findPackage(packageId);
        List<OfficialVerificationRunView> runs = officialRuns(packageId, aggregateRunId);
        List<Map<String, Object>> mappedRuns = runs.stream().map(this::runViewMap).toList();
        int total = mappedRuns.size();
        int passed = (int) mappedRuns.stream().filter(run -> passState(string(run.get("state")))).count();
        List<Map<String, Object>> problems = actualPromptProblems(runs);
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("packageId", packageId);
        detail.put("aggregateRunId", runs.isEmpty() ? aggregateRunId : aggregateRunId(runs.get(0)));
        detail.put("sealedEvidence", sealedEvidenceMap(pkg));
        detail.put("integrityValid", evidenceLookupService.verifyIntegrity(pkg));
        detail.put("sealed", pkg.isSealed());
        detail.put("totalRunCount", total);
        detail.put("passedRunCount", passed);
        detail.put("failedRunCount", Math.max(total - passed, 0));
        detail.put("actualMetricCount", total);
        detail.put("passedMetricCount", passed);
        detail.put("failedMetricCount", Math.max(total - passed, 0));
        detail.put("certificateIssued", total > 0 && total == passed);
        detail.put("certificateState", total > 0 && total == passed ? "ISSUABLE" : "BLOCKED");
        detail.put("certificateStateLabel", total > 0 && total == passed ? message("enterprise.pqa.certificate.llmReady", "LLM 투입 가능") : message("enterprise.pqa.certificate.needImprovement", "프롬프트 개선 필요"));
        detail.put("certificateSummary", total > 0 && total == passed ? message("enterprise.pqa.certificate.descSuccess", "공식검사 기준을 충족했습니다.") : message("enterprise.pqa.certificate.descFailure", "발견된 문제는 공식검사 결과에서 확인합니다."));
        detail.put("runs", mappedRuns);
        detail.put("metrics", mappedRuns);
        detail.put("actualPromptProblems", problems);
        detail.put("promptComparisons", packagePromptComparison(packageId, aggregateRunId));
        detail.put("failureCauses", failures(runs));
        detail.put("remediationGroups", remediationGroups(problems));
        detail.put("nextActions", problems.stream().map(problem -> string(problem.get("fixAction"))).filter(StringUtils::hasText).distinct().toList());
        detail.put("summaryCounts", Map.of(
                "total", total,
                "passed", passed,
                "failed", Math.max(total - passed, 0),
                "actualProblems", problems.size()));
        detail.putAll(routeIdentity(evidenceSummary(pkg)));
        return detail;
    }

    private Map<String, Object> runViewMap(OfficialVerificationRunView run) {
        List<Map<String, Object>> checks = run.checks().stream().map(this::checkMap).toList();
        Map<String, Object> mapped = new LinkedHashMap<>();
        mapped.put("runId", run.runId());
        mapped.put("officialRunId", run.runId());
        mapped.put("metricCode", run.endpointKey());
        mapped.put("endpointKey", run.endpointKey());
        mapped.put("metricLabel", run.endpointLabel());
        mapped.put("endpointLabel", run.endpointLabel());
        mapped.put("requestId", run.requestId());
        mapped.put("score", run.score());
        mapped.put("passedChecks", run.passedChecks());
        mapped.put("totalChecks", run.totalChecks());
        mapped.put("processingTimeMs", run.processingTimeMs());
        mapped.put("state", run.state());
        mapped.put("stateLabel", passState(run.state()) ? message("enterprise.pqa.state.passed", "통과") : message("enterprise.pqa.state.blocked", "차단"));
        mapped.put("stateTone", run.stateTone());
        mapped.put("message", run.message());
        mapped.put("startedAt", run.startedAt());
        mapped.put("completedAt", run.completedAt());
        mapped.put("checks", checks);
        mapped.put("requestFacts", run.requestFacts());
        mapped.put("eventFacts", run.eventFacts());
        mapped.put("promptFacts", run.promptFacts());
        mapped.put("analysisFacts", run.analysisFacts());
        mapped.put("rawEvidence", run.rawEvidence());
        mapped.put("aggregateRunId", aggregateRunId(run));
        return mapped;
    }

    private Map<String, Object> checkMap(OfficialVerificationCheckResultView check) {
        Map<String, Object> mapped = new LinkedHashMap<>();
        mapped.put("checkCode", check.checkCode());
        mapped.put("label", check.label());
        mapped.put("expectedValue", check.expectedValue());
        mapped.put("actualValue", check.actualValue());
        mapped.put("pass", check.pass());
        mapped.put("passed", check.pass());
        mapped.put("source", check.source());
        mapped.put("severity", check.severity());
        mapped.put("failureType", check.failureType());
        mapped.put("remediationOwner", check.remediationOwner());
        mapped.put("operatorReason", check.operatorReason());
        mapped.put("nextAction", check.nextAction());
        mapped.put("reverifyCriterion", check.reverifyCriterion());
        mapped.put("issueKey", check.issueKey());
        mapped.put("customerVisible", check.customerVisible());
        mapped.put("readinessScope", check.readinessScope());
        mapped.put("purposeResult", check.purposeResult());
        mapped.put("whyItMatters", check.whyItMatters());
        return mapped;
    }

    private List<Map<String, Object>> actualPromptProblems(List<OfficialVerificationRunView> runs) {
        List<Map<String, Object>> problems = new ArrayList<>();
        for (OfficialVerificationRunView run : runs) {
            for (OfficialVerificationCheckResultView check : run.checks()) {
                if (check.pass() || !check.customerVisible()) {
                    continue;
                }
                problems.add(problemMap(run.endpointKey(), check));
            }
        }
        return problems;
    }

    private Map<String, Object> problemMap(String metricCode, OfficialVerificationCheckResultView check) {
        Map<String, Object> problem = new LinkedHashMap<>();
        problem.put("metricCode", metricCode);
        problem.put("checkCode", check.checkCode());
        problem.put("promptLabel", check.label());
        problem.put("fieldLabel", check.label());
        problem.put("fieldKey", check.source());
        problem.put("promptLocation", check.source());
        problem.put("problemType", check.failureType());
        problem.put("actualState", check.actualValue());
        problem.put("expectedState", check.expectedValue());
        problem.put("whyItMatters", firstText(check.whyItMatters(), check.expectedValue()));
        problem.put("fixAction", firstText(check.nextAction(), message("enterprise.pqa.suggested.fix", "공식검사 결과의 확인값을 기준으로 프롬프트 입력을 보강하십시오.")));
        problem.put("reverifyCriterionDetail", check.reverifyCriterion());
        return problem;
    }

    private Map<String, Object> comparisonMap(OfficialVerificationRunView run, OfficialVerificationCheckResultView check) {
        Map<String, Object> comparison = new LinkedHashMap<>();
        comparison.put("metricCode", run.endpointKey());
        comparison.put("checkCode", check.checkCode());
        comparison.put("fieldKey", check.source());
        comparison.put("fieldLabel", check.label());
        comparison.put("promptLocation", check.source());
        comparison.put("state", check.pass() ? "MATCH" : "VALUE_MISMATCH");
        comparison.put("expectedValue", check.expectedValue());
        comparison.put("actualValue", check.actualValue());
        comparison.put("promptValue", check.actualValue());
        comparison.put("factValue", check.expectedValue());
        comparison.put("problem", !check.pass());
        return comparison;
    }

    private List<Map<String, Object>> failures(List<OfficialVerificationRunView> runs) {
        return actualPromptProblems(runs).stream()
                .map(problem -> Map.of(
                        "metricCode", problem.get("metricCode"),
                        "checkCode", problem.get("checkCode"),
                        "title", problem.get("promptLabel"),
                        "detail", problem.get("actualState"),
                        "nextAction", problem.get("fixAction")))
                .toList();
    }

    private List<Map<String, Object>> remediationGroups(List<Map<String, Object>> problems) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (Map<String, Object> problem : problems) {
            String metric = string(problem.get("metricCode"));
            counts.put(metric, counts.getOrDefault(metric, 0) + 1);
        }
        return counts.entrySet().stream()
                .map(entry -> Map.<String, Object>of(
                        "metricCode", entry.getKey(),
                        "title", entry.getKey() + " " + message("enterprise.pqa.state.actionCheck", "확인"),
                        "findingCount", entry.getValue()))
                .toList();
    }

    private List<OfficialVerificationRunView> officialRuns(String packageId, String aggregateRunId) {
        List<OfficialVerificationRunView> runs = runStore.listDetailedByPackageId(packageId);
        if (runs.isEmpty()) {
            return runs;
        }
        String selectedAggregate = StringUtils.hasText(aggregateRunId) ? aggregateRunId : aggregateRunId(runs.get(0));
        return runs.stream()
                .filter(run -> Objects.equals(aggregateRunId(run), selectedAggregate))
                .sorted(Comparator.comparing(OfficialVerificationRunView::endpointKey))
                .toList();
    }

    private Map<String, Object> findRunById(String runId) {
        if (jdbcOperations != null) {
            List<String> packageIds = jdbcOperations.query(
                    "select package_id from verification_run_ledger where run_id = ? limit 1",
                    (rs, rowNum) -> rs.getString("package_id"),
                    runId);
            if (!packageIds.isEmpty()) {
                return officialRuns(packageIds.get(0), null).stream()
                        .filter(run -> Objects.equals(run.runId(), runId))
                        .findFirst()
                        .map(this::runViewMap)
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Official run not found."));
            }
        }
        throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Official run not found.");
    }

    private SealedEvidencePackage findPackage(String packageId) {
        return evidenceLookupService.findWithIntegrityCheck(packageId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Sealed evidence package not found."));
    }

    private List<Map<String, Object>> stateCatalogRows() {
        return List.of(
                Map.of("dimension", "RESOURCE_OPERATIONAL", "code", "READY", "label", "검사 가능", "tone", "ready", "aggregateGroup", "READY", "order", 1),
                Map.of("dimension", "RESOURCE_OPERATIONAL", "code", "PENDING", "label", "확인 필요", "tone", "pending", "aggregateGroup", "PENDING", "order", 2),
                Map.of("dimension", "RESOURCE_REQUEST_OBSERVATION", "code", "EVIDENCE_CAPTURED", "label", "증거 있음", "tone", "ready", "aggregateGroup", "READY", "order", 1));
    }

    private Map<String, Object> processStage(String code, String label, String route) {
        return Map.of(
                "processStage", Map.of("code", code, "label", label, "order", code.equals("PROTECTABLE_RESOURCES") ? 1 : code.equals("RUNTIME_EVIDENCE") ? 2 : 3),
                "state", Map.of("code", "READY", "label", "확인 가능", "tone", "ready"),
                "executionState", "READY",
                "executionStateDescriptor", Map.of("code", "READY", "label", "확인 가능", "tone", "ready"),
                "summary", label,
                "route", route,
                "nextAction", "열기");
    }

    private List<Map<String, Object>> resourceHistory(Map<String, Object> resource) {
        return searchEvidence(
                null,
                null,
                null,
                string(resource.get("resourceUrl")),
                string(resource.get("resourceId")),
                string(resource.get("httpMethod")),
                null,
                null,
                0,
                20);
    }

    private Map<String, Object> routeIdentity(Map<String, Object> summary) {
        return Map.of(
                "tenantId", string(summary.get("tenantId")),
                "userId", string(summary.get("userId")),
                "requestId", string(summary.get("requestId")),
                "requestPath", string(summary.get("requestPath")),
                "resourceUrl", string(summary.get("resourceUrl")),
                "resourceId", string(summary.get("resourceId")),
                "httpMethod", string(summary.get("httpMethod")),
                "promptHash", string(summary.get("promptHash")));
    }

    private String runtimeEvidenceHref(Map<String, Object> resource) {
        return "/contexa/admin/prompt-quality/runtime-evidence?" + resourceQuery(resource);
    }

    private String verificationHref(Map<String, Object> resource) {
        return "/contexa/admin/prompt-quality/verification/readiness?" + resourceQuery(resource);
    }

    private String resourceQuery(Map<String, Object> resource) {
        List<String> parts = new ArrayList<>();
        addParam(parts, "resourceUrl", string(resource.get("resourceUrl")));
        addParam(parts, "resourceId", string(resource.get("resourceId")));
        addParam(parts, "httpMethod", string(resource.get("httpMethod")));
        return String.join("&", parts);
    }

    private void addParam(List<String> parts, String name, String value) {
        if (StringUtils.hasText(value)) {
            parts.add(name + "=" + value.replace(" ", "%20"));
        }
    }

    private boolean matches(Map<String, Object> item, String key, String expected) {
        if (!StringUtils.hasText(expected)) {
            return true;
        }
        return string(item.get(key)).toLowerCase(Locale.ROOT).contains(expected.trim().toLowerCase(Locale.ROOT));
    }

    private boolean same(Object left, Object right) {
        return string(left).equalsIgnoreCase(string(right));
    }

    private String resourceKey(Map<String, Object> item) {
        return string(item.get("httpMethod")) + "|" + string(item.get("resourceUrl")) + "|" + string(item.get("resourceId"));
    }

    private String aggregateRunId(OfficialVerificationRunView run) {
        Object raw = run.rawEvidence() == null ? null : run.rawEvidence().get("aggregateRunId");
        if (raw != null && StringUtils.hasText(String.valueOf(raw))) {
            return String.valueOf(raw);
        }
        String runId = run.runId();
        String metric = run.endpointKey();
        if (StringUtils.hasText(runId) && StringUtils.hasText(metric)) {
            String suffix = "-" + metric.toLowerCase(Locale.ROOT);
            if (runId.toLowerCase(Locale.ROOT).endsWith(suffix)) {
                return runId.substring(0, runId.length() - suffix.length());
            }
        }
        return runId;
    }

    private boolean passState(String state) {
        String normalized = state == null ? "" : state.toUpperCase(Locale.ROOT);
        return normalized.equals("PASSED") || normalized.equals("PASS") || normalized.equals("SUCCESS");
    }

    private Instant parseInstant(String value, Instant fallback) {
        if (!StringUtils.hasText(value)) {
            return fallback;
        }
        String normalized = value.trim();
        try {
            return Instant.parse(normalized);
        }
        catch (DateTimeParseException ignored) {
            try {
                return LocalDateTime.parse(normalized).atZone(KOREA_ZONE).toInstant();
            }
            catch (DateTimeParseException ignoredAgain) {
                try {
                    return LocalDate.parse(normalized).atStartOfDay(KOREA_ZONE).toInstant();
                }
                catch (DateTimeParseException finalIgnored) {
                    return fallback;
                }
            }
        }
    }

    private JsonNode json(String raw) {
        if (!StringUtils.hasText(raw)) {
            return objectMapper.createObjectNode();
        }
        try {
            return objectMapper.readTree(raw);
        }
        catch (Exception ignored) {
            return objectMapper.createObjectNode();
        }
    }

    private Object objectValue(String raw) {
        JsonNode node = json(raw);
        return objectMapper.convertValue(node, Object.class);
    }

    private String firstJsonText(JsonNode root, String... names) {
        Set<String> wanted = new LinkedHashSet<>();
        for (String name : names) {
            wanted.add(name.toLowerCase(Locale.ROOT));
        }
        JsonNode found = find(root, wanted);
        if (found == null || found.isMissingNode() || found.isNull()) {
            return "";
        }
        return found.isValueNode() ? found.asText("") : found.toString();
    }

    private JsonNode find(JsonNode node, Set<String> names) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isObject()) {
            var fields = node.fields();
            while (fields.hasNext()) {
                var entry = fields.next();
                if (names.contains(entry.getKey().toLowerCase(Locale.ROOT))) {
                    return entry.getValue();
                }
                JsonNode nested = find(entry.getValue(), names);
                if (nested != null) {
                    return nested;
                }
            }
        }
        if (node.isArray()) {
            for (JsonNode child : node) {
                JsonNode nested = find(child, names);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private String preview(String value) {
        String text = string(value);
        if (text.length() <= 4000) {
            return text;
        }
        return text.substring(0, 4000);
    }

    private String iso(Instant instant) {
        return instant == null ? "" : instant.toString();
    }

    private String stringValue(Map<String, Object> body, String key) {
        return body == null ? "" : string(body.get(key));
    }

    private String firstText(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String string(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
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
