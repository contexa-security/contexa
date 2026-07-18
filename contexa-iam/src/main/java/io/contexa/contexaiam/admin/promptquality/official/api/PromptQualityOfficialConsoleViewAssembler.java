package io.contexa.contexaiam.admin.promptquality.official.api;

import static io.contexa.contexaiam.admin.promptquality.official.api.PromptQualityOfficialViewValueReader.firstJsonText;
import static io.contexa.contexaiam.admin.promptquality.official.api.PromptQualityOfficialViewValueReader.iso;
import static io.contexa.contexaiam.admin.promptquality.official.api.PromptQualityOfficialViewValueReader.objectValue;
import static io.contexa.contexaiam.admin.promptquality.official.api.PromptQualityOfficialViewValueReader.string;



import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupPort;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptQualityOfficialRunDetailService;
import io.contexa.contexaiam.admin.promptquality.official.application.RuntimeEvidencePromptConsistencyGate;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Map;
import java.util.Properties;
import org.springframework.stereotype.Component;

@Component
public final class PromptQualityOfficialConsoleViewAssembler {

    private final SealedEvidencePackageLookupPort evidenceLookupService;
    private final PromptQualityOfficialRunDetailService officialRunDetailService;
    private final OfficialVerificationRunStore runStore;
    private final ObjectMapper objectMapper;
    private final RuntimeEvidencePromptConsistencyGate promptConsistencyGate;
    private final PromptQualityMessageResolver messageResolver;
    private final PromptQualityOfficialMetricViewAssembler metricViewAssembler;

    public PromptQualityOfficialConsoleViewAssembler(
            SealedEvidencePackageLookupPort evidenceLookupService,
            PromptQualityOfficialRunDetailService officialRunDetailService,
            OfficialVerificationRunStore runStore,
            ObjectMapper objectMapper,
            RuntimeEvidencePromptConsistencyGate promptConsistencyGate,
            PromptQualityMessageResolver messageResolver) {
        this.evidenceLookupService = evidenceLookupService;
        this.officialRunDetailService = officialRunDetailService;
        this.runStore = runStore;
        this.objectMapper = objectMapper;
        this.promptConsistencyGate = promptConsistencyGate;
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
        this.metricViewAssembler = new PromptQualityOfficialMetricViewAssembler(this::message);
    }

    List<Map<String, Object>> searchEvidence(
            String packageId,
            String tenantId,
            String userId,
            String resourceUrl,
            String resourceId,
            String httpMethod,
            String from,
            String to,
            int page,
            int size) {
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

    public Map<String, Object> metricFamilyPayload(OfficialRunPackageDetail detail, String family) {
        return metricViewAssembler.metricFamilyPayload(detail, family);
    }

    List<String> expectedMetricCodes(String family) {
        return metricViewAssembler.expectedMetricCodes(family);
    }

    Map<String, Object> expectedMetricPayload(String metricCode, boolean executed) {
        return metricViewAssembler.expectedMetricPayload(metricCode, executed);
    }

    String expectedMetricLabel(String metricCode) {
        return metricViewAssembler.expectedMetricLabel(metricCode);
    }

    public Map<String, Object> reverifyOptionsPayload(OfficialRunPackageDetail detail) {
        String endpoint = "/contexa/admin/api/prompt-quality/verification/runtime-runs/package/"
                + detail.packageId() + "/reverify";
        return reverifyOptionsPayload(detail, endpoint);
    }

    public Map<String, Object> reverifyOptionsPayload(OfficialRunPackageDetail detail, String endpoint) {
        return metricViewAssembler.reverifyOptionsPayload(detail, endpoint);
    }

    public String metricFamily(OfficialVerificationMetricTrace run) {
        return metricViewAssembler.metricFamily(run);
    }

    String metricFamilyLabel(String family) {
        return metricViewAssembler.metricFamilyLabel(family);
    }

    public String normalizeMetricCode(String value) {
        return metricViewAssembler.normalizeMetricCode(value);
    }
    List<String> stringList(Object value) {
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
    void loadProperties(Properties properties, String pattern) {
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

    List<Map<String, Object>> resourcesFromEvidence(int size) {
        Map<String, Map<String, Object>> byIdentity = new LinkedHashMap<>();
        for (Map<String, Object> item : searchEvidence(null, null, null, null, null, null, null, null, 0, size)) {
            String key = resourceKey(item);
            byIdentity.putIfAbsent(key, resourceFromEvidence(item));
        }
        return new ArrayList<>(byIdentity.values());
    }

    Map<String, Object> resourceFromEvidence(Map<String, Object> item) {
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
        resource.put("operationalStateLabel", message("enterprise.pqa.state.ready"));
        resource.put("operationalStateDescriptor", Map.of("code", "READY", "label", message("enterprise.pqa.state.ready"), "tone", "ready", "aggregateGroup", "READY"));
        resource.put("runtimeRequestStateDescriptor", Map.of("code", "EVIDENCE_CAPTURED", "label", message("enterprise.pqa.state.evidenceCaptured"), "tone", "ready"));
        resource.put("signatureChanged", false);
        return resource;
    }

    Map<String, Object> resolveResource(String resourceId, String resourceUrl, String httpMethod) {
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
                    resource.put("operationalStateLabel", message("enterprise.pqa.state.ready"));
                    resource.put("operationalStateDescriptor", Map.of("code", "READY", "label", message("enterprise.pqa.state.ready"), "tone", "ready", "aggregateGroup", "READY"));
                    resource.put("runtimeRequestStateDescriptor", Map.of("code", "UNKNOWN", "label", message("enterprise.pqa.state.unknown"), "tone", "neutral"));
                    return resource;
                });
    }

    Map<String, Object> evidenceSummary(SealedEvidencePackage pkg) {
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
        summary.put("integrityValid", pkg.isSealed() && StringUtils.hasText(pkg.getPackageHash()));
        summary.put("decisionAction", firstJsonText(decision, "action", "decision", "verdict"));
        summary.put("decisionConfidence", firstJsonText(decision, "confidence", "confidenceScore"));
        return summary;
    }

    Map<String, Object> sealedEvidenceMap(SealedEvidencePackage pkg) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("summary", evidenceSummary(pkg));
        evidence.put("packageId", pkg.getPackageId());
        evidence.put("systemPromptText", pkg.getSystemPromptText());
        evidence.put("userPromptText", pkg.getUserPromptText());
        evidence.put("systemPromptPreview", preview(pkg.getSystemPromptText()));
        evidence.put("userPromptPreview", preview(pkg.getUserPromptText()));
        evidence.put("requestFacts", objectValue(objectMapper, pkg.getRequestFactsJson()));
        evidence.put("authState", objectValue(objectMapper, pkg.getAuthStateJson()));
        evidence.put("baselineSnapshot", objectValue(objectMapper, pkg.getBaselineSnapshotJson()));
        evidence.put("baselineSnapshotCaptured", StringUtils.hasText(pkg.getBaselineSnapshotJson()));
        evidence.put("ragResults", objectValue(objectMapper, pkg.getRagResultsJson()));
        evidence.put("ragResultsCaptured", StringUtils.hasText(pkg.getRagResultsJson()));
        evidence.put("decision", objectValue(objectMapper, pkg.getDecisionJson()));
        evidence.put("promptConsistency", promptConsistency(pkg));
        evidence.put("qualityWarnings", List.of());
        evidence.put("missingKnowledgeSignals", List.of());
        return evidence;
    }

    Map<String, Object> promptConsistency(SealedEvidencePackage pkg) {
        List<Map<String, Object>> checks = List.of(
                promptCheck("LLM system/user prompt captured",
                        StringUtils.hasText(pkg.getSystemPromptText()) && StringUtils.hasText(pkg.getUserPromptText()),
                        "promptCapture"),
                promptCheck("promptHash is present",
                        StringUtils.hasText(pkg.getPromptHash()),
                        "promptHash"),
                promptCheck("systemPromptHash is present",
                        StringUtils.hasText(pkg.getSystemPromptHash()),
                        "promptHash"),
                promptCheck("userPromptHash is present",
                        StringUtils.hasText(pkg.getUserPromptHash()),
                        "promptHash"));
        boolean blocking = checks.stream().anyMatch(check -> !Boolean.TRUE.equals(check.get("pass")));
        return Map.of(
                "state", blocking ? "REVIEW" : "PASS",
                "stateLabel", blocking ? message("enterprise.pqa.state.pending") : message("enterprise.pqa.state.ready"),
                "blocking", blocking,
                "checks", checks);
    }

    Map<String, Object> promptCheck(String label, boolean pass, String source) {
        return Map.of(
                "label", label,
                "pass", pass,
                "source", source,
                "expectedValue", "present",
                "actualValue", pass ? "present" : "missing");
    }

    SealedEvidencePackage findPackage(String packageId) {
        if (!StringUtils.hasText(packageId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, message("promptQuality.official.evidence.notFound"));
        }
        return evidenceLookupService.findByPackageId(packageId.trim())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, message("promptQuality.official.evidence.notFound")));
    }

    List<Map<String, Object>> stateCatalogRows() {
        return List.of(
                Map.of("dimension", "RESOURCE_OPERATIONAL", "code", "READY", "label", message("enterprise.pqa.state.available"), "tone", "ready", "aggregateGroup", "READY", "order", 1),
                Map.of("dimension", "RESOURCE_OPERATIONAL", "code", "PENDING", "label", message("enterprise.pqa.state.pending"), "tone", "pending", "aggregateGroup", "PENDING", "order", 2),
                Map.of("dimension", "RESOURCE_REQUEST_OBSERVATION", "code", "EVIDENCE_CAPTURED", "label", message("enterprise.pqa.state.evidenceAvailable"), "tone", "ready", "aggregateGroup", "READY", "order", 1));
    }

    Map<String, Object> processStage(String code, String label, String route) {
        return Map.of(
                "processStage", Map.of("code", code, "label", label, "order", code.equals("PROTECTABLE_RESOURCES") ? 1 : code.equals("RUNTIME_EVIDENCE") ? 2 : 3),
                "state", Map.of("code", "READY", "label", message("enterprise.pqa.state.confirmable"), "tone", "ready"),
                "executionState", "READY",
                "executionStateDescriptor", Map.of("code", "READY", "label", message("enterprise.pqa.state.confirmable"), "tone", "ready"),
                "summary", label,
                "route", route,
                "nextAction", message("enterprise.pqa.action.open"));
    }

    List<Map<String, Object>> resourceHistory(Map<String, Object> resource) {
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

    Map<String, Object> routeIdentity(Map<String, Object> summary) {
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

    String runtimeEvidenceHref(Map<String, Object> resource) {
        return "/contexa/admin/prompt-quality/runtime-evidence?" + resourceQuery(resource);
    }

    String verificationHref(Map<String, Object> resource) {
        return "/contexa/admin/prompt-quality/verification/readiness?" + resourceQuery(resource);
    }

    String resourceQuery(Map<String, Object> resource) {
        List<String> parts = new ArrayList<>();
        addParam(parts, "resourceUrl", string(resource.get("resourceUrl")));
        addParam(parts, "resourceId", string(resource.get("resourceId")));
        addParam(parts, "httpMethod", string(resource.get("httpMethod")));
        return String.join("&", parts);
    }

    void addParam(List<String> parts, String name, String value) {
        if (StringUtils.hasText(value)) {
            parts.add(name + "=" + value.replace(" ", "%20"));
        }
    }

    boolean matches(Map<String, Object> item, String key, String expected) {
        if (!StringUtils.hasText(expected)) {
            return true;
        }
        return string(item.get(key)).toLowerCase(Locale.ROOT).contains(expected.trim().toLowerCase(Locale.ROOT));
    }

    boolean same(Object left, Object right) {
        return string(left).equalsIgnoreCase(string(right));
    }

    String resourceKey(Map<String, Object> item) {
        return string(item.get("httpMethod")) + "|" + string(item.get("resourceUrl")) + "|" + string(item.get("resourceId"));
    }

    String aggregateRunId(OfficialVerificationRunView run) {
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

    JsonNode json(String raw) {
        return PromptQualityOfficialViewValueReader.json(objectMapper, raw);
    }

    String preview(String value) {
        return PromptQualityOfficialViewValueReader.preview(value);
    }
    Instant parseInstant(String value, Instant fallback) {
        return PromptQualityOfficialViewValueReader.parseInstant(value, fallback);
    }

    String stringValue(Map<String, Object> body, String key) {
        return PromptQualityOfficialViewValueReader.stringValue(body, key);
    }

    String firstText(String... values) {
        return PromptQualityOfficialViewValueReader.firstText(values);
    }

    String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }
}
