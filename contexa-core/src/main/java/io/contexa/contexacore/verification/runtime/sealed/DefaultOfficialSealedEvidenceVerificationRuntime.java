package io.contexa.contexacore.verification.runtime.sealed;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupService;
import io.contexa.contexacore.verification.evidence.SealedEvidencePromptEvidenceBackfill;
import io.contexa.contexacore.verification.metric.OfficialContextHashStateResolver;
import io.contexa.contexacore.verification.metric.OfficialMetricEvaluationResult;
import io.contexa.contexacore.verification.metric.OfficialPromptQualityMetricContractGate;
import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricCatalog;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCasePublisher;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricEvaluationSuite;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

public class DefaultOfficialSealedEvidenceVerificationRuntime implements OfficialSealedEvidenceVerificationRuntime {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final DateTimeFormatter KOREA_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final String EXECUTION_PATH = "CORE_OFFICIAL_SEALED_EVIDENCE_REPLAY";

    private final SealedEvidencePackageLookupService evidenceLookupService;
    private final OfficialVerificationMetricCatalog metricCatalog;
    private final OfficialVerificationRunStore runStore;
    private final OfficialVerificationCasePublisher casePublisher;
    private final ObjectMapper objectMapper;
    private final OfficialPromptQualityMetricContractGate metricContractGate;
    private final FinalPromptMetricEvaluationSuite finalPromptMetricEvaluationSuite;
    private final OfficialPromptQualityNarrativeCatalog narrativeCatalog = new OfficialPromptQualityNarrativeCatalog();
    private final SealedEvidenceOfficialRunViewFactory runViewFactory = new SealedEvidenceOfficialRunViewFactory();

    public DefaultOfficialSealedEvidenceVerificationRuntime(
            SealedEvidencePackageLookupService evidenceLookupService,
            OfficialVerificationMetricCatalog metricCatalog,
            OfficialVerificationRunStore runStore,
            OfficialVerificationCasePublisher casePublisher,
            ObjectMapper objectMapper) {
        this.evidenceLookupService = evidenceLookupService;
        this.metricCatalog = metricCatalog;
        this.runStore = runStore;
        this.casePublisher = casePublisher;
        this.objectMapper = objectMapper;
        this.metricContractGate = new OfficialPromptQualityMetricContractGate(metricCatalog);
        this.finalPromptMetricEvaluationSuite = new FinalPromptMetricEvaluationSuite(objectMapper);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public OfficialSealedEvidenceVerificationResult executeAll(OfficialSealedEvidenceVerificationRequest request) {
        if (request == null || !StringUtils.hasText(request.packageId())) {
            throw new IllegalArgumentException("sealed evidence packageId is required.");
        }
        SealedEvidencePackage loadedPackage = evidenceLookupService.findByPackageId(request.packageId().trim())
                .orElseThrow(() -> new IllegalArgumentException("sealed evidence package not found: " + request.packageId()));
        SealedEvidencePackage evidencePackage = prepareSealedPromptEvidencePackage(loadedPackage);
        String operatorId = firstNonBlank(request.operatorId(), evidencePackage.getUserId(), "official-sealed-evidence-runtime");
        boolean integrityValid = evidenceLookupService.verifyIntegrity(evidencePackage);
        Instant started = Instant.now();
        String startedAt = format(started);
        Map<String, Object> requestFacts = parseJson(evidencePackage.getRequestFactsJson());
        Map<String, Object> authState = parseJson(evidencePackage.getAuthStateJson());
        Map<String, Object> promptMetadata = parseJson(evidencePackage.getPromptExecutionMetadataJson());
        Map<String, Object> decision = parseJson(evidencePackage.getDecisionJson());
        Map<String, String> requestFactStrings = requestAndAuthFacts(requestFacts, authState, decision);
        Map<String, String> promptFactStrings = promptFacts(evidencePackage, promptMetadata);
        String requestPath = firstNonBlank(
                text(requestFacts, "requestPath"),
                text(requestFacts, "path"),
                text(promptMetadata, "requestPath"),
                evidencePackage.getCorrelationId());
        Map<String, OfficialMetricEvaluationResult> resultsByMetric =
                metricContractGate.validateEvaluationResults(narrativeCatalog.enrichResults(
                        finalPromptMetricEvaluationSuite.evaluatePromptQuality(evidencePackage),
                        evidencePackage,
                        requestPath));
        String aggregateRunId = "osev-" + evidencePackage.getPackageId() + "-" + UUID.randomUUID();
        Instant completed = Instant.now();
        String completedAt = format(completed);
        Duration processingTime = Duration.between(started, completed);
        List<OfficialVerificationRunView> runs = metricCatalog.promptQualityMetrics().stream()
                .map(metric -> createRunView(
                        aggregateRunId,
                        metric,
                        evidencePackage,
                        resultsByMetric.get(normalizeMetric(metric.code())),
                        requestFactStrings,
                        promptFactStrings,
                        requestPath,
                        integrityValid,
                        started,
                        completed,
                        startedAt,
                        completedAt,
                        processingTime))
                .toList();
        metricContractGate.validateRunViews(runs);
        runs.forEach(run -> storeRun(operatorId, evidencePackage, run, requestFactStrings, promptFactStrings, started, completed));
        return new OfficialSealedEvidenceVerificationResult(
                aggregateRunId,
                evidencePackage.getPackageId(),
                operatorId,
                completedAt,
                integrityValid,
                runs);
    }

    @Override
    public OfficialSealedEvidenceVerificationResult findByPackageId(String packageId) {
        if (!StringUtils.hasText(packageId)) {
            throw new IllegalArgumentException("sealed evidence packageId is required.");
        }
        SealedEvidencePackage loadedPackage = evidenceLookupService.findByPackageId(packageId.trim())
                .orElseThrow(() -> new IllegalArgumentException("sealed evidence package not found: " + packageId));
        SealedEvidencePackage evidencePackage = prepareSealedPromptEvidencePackage(loadedPackage);
        List<OfficialVerificationRunView> runs = runStore.listDetailedByPackageId(packageId.trim());
        String aggregateRunId = latestAggregateRunId(runs);
        List<OfficialVerificationRunView> latestRuns = StringUtils.hasText(aggregateRunId)
                ? runs.stream()
                .filter(run -> aggregateRunId.equals(aggregateRunId(run)))
                .toList()
                : List.copyOf(runs);
        return new OfficialSealedEvidenceVerificationResult(
                aggregateRunId,
                evidencePackage.getPackageId(),
                evidencePackage.getUserId(),
                format(Instant.now()),
                evidenceLookupService.verifyIntegrity(evidencePackage),
                List.copyOf(latestRuns));
    }

    private OfficialVerificationRunView createRunView(
            String aggregateRunId,
            OfficialVerificationMetricDefinition metric,
            SealedEvidencePackage evidencePackage,
            OfficialMetricEvaluationResult result,
            Map<String, String> requestFacts,
            Map<String, String> promptFacts,
            String requestPath,
            boolean integrityValid,
            Instant started,
            Instant completed,
            String startedAt,
            String completedAt,
            Duration processingTime) {
        return runViewFactory.create(
                aggregateRunId,
                metric,
                evidencePackage,
                result,
                requestFacts,
                promptFacts,
                requestPath,
                integrityValid,
                startedAt,
                completedAt,
                processingTime);
    }

    private SealedEvidencePackage prepareSealedPromptEvidencePackage(SealedEvidencePackage loadedPackage) {
        SealedEvidencePromptEvidenceBackfill.Result result =
                SealedEvidencePromptEvidenceBackfill.prepare(objectMapper, loadedPackage);
        if (!result.ready()) {
            throw new IllegalStateException("sealed evidence package is not ready for official verification: "
                    + String.join(" ", result.violations()));
        }
        return result.packageForVerification();
    }

    private void storeRun(
            String operatorId,
            SealedEvidencePackage evidencePackage,
            OfficialVerificationRunView runView,
            Map<String, String> requestFacts,
            Map<String, String> promptFacts,
            Instant started,
            Instant completed) {
        OfficialVerificationRunRecord record = new OfficialVerificationRunRecord(
                runView.runId(),
                runView.endpointKey(),
                EXECUTION_PATH,
                runView.state(),
                operatorId,
                started,
                started,
                completed,
                runView.message(),
                evidenceReferences(evidencePackage, requestFacts, promptFacts));
        runStore.saveDetailed(operatorId, record, runView);
        casePublisher.register(operatorId, record);
    }

    private Map<String, String> evidenceReferences(
            SealedEvidencePackage evidencePackage,
            Map<String, String> requestFacts,
            Map<String, String> promptFacts) {
        Map<String, String> references = new LinkedHashMap<>();
        putIfPresent(references, "packageId", evidencePackage.getPackageId());
        putIfPresent(references, "requestId", firstNonBlank(requestFacts.get("requestId"), evidencePackage.getCorrelationId()));
        putIfPresent(references, "correlationId", evidencePackage.getCorrelationId());
        putIfPresent(references, "promptHash", evidencePackage.getPromptHash());
        putIfPresent(references, "promptTraceHash", firstNonBlank(evidencePackage.getPromptHash(), promptFacts.get("promptHash")));
        putIfPresent(references, "contextHash", promptFacts.get("contextHash"));
        putIfPresent(references, "contextHashState", promptFacts.get("contextHashState"));
        putIfPresent(references, "canonicalContextHash", promptFacts.get("canonicalContextHash"));
        putIfPresent(references, "resourceId", firstNonBlank(requestFacts.get("resourceId"), requestFacts.get("endpointKey")));
        putIfPresent(references, "requestPath", firstNonBlank(requestFacts.get("requestPath"), requestFacts.get("path")));
        return Map.copyOf(references);
    }

    private Map<String, OfficialMetricEvaluationResult> normalize(
            Map<String, OfficialMetricEvaluationResult> raw) {
        if (raw == null || raw.isEmpty()) {
            return Map.of();
        }
        return raw.entrySet().stream()
                .collect(Collectors.toMap(
                        entry -> normalizeMetric(entry.getKey()),
                        Map.Entry::getValue,
                        (left, right) -> left,
                        LinkedHashMap::new));
    }

    private String normalizeMetric(String metricCode) {
        return metricCode == null ? "" : metricCode.trim().toUpperCase(Locale.ROOT);
    }

    private Map<String, String> promptFacts(SealedEvidencePackage evidencePackage, Map<String, Object> promptMetadata) {
        Map<String, String> facts = new LinkedHashMap<>(stringMap(promptMetadata));
        Map<String, Object> requestFacts = parseJson(evidencePackage.getRequestFactsJson());
        OfficialContextHashStateResolver.Resolution contextHashResolution =
                OfficialContextHashStateResolver.resolve(requestFacts, promptMetadata, evidencePackage.getCanonicalContextJson());
        putIfPresent(facts, "promptHash", firstNonBlank(evidencePackage.getPromptHash(), facts.get("promptHash")));
        putIfPresent(facts, "contextHash", contextHashResolution.contextHash());
        putIfPresent(facts, "contextHashState", contextHashResolution.state());
        putIfPresent(facts, "contextHashStateReason", contextHashResolution.reason());
        facts.put("rawSystemPromptCaptured", String.valueOf(StringUtils.hasText(evidencePackage.getRawSystemPrompt())));
        facts.put("rawUserPromptCaptured", String.valueOf(StringUtils.hasText(evidencePackage.getRawUserPrompt())));
        facts.put("llmSystemPromptCaptured", String.valueOf(StringUtils.hasText(evidencePackage.getSystemPromptText())));
        facts.put("llmUserPromptCaptured", String.valueOf(StringUtils.hasText(evidencePackage.getUserPromptText())));
        facts.put("baselineSnapshotCaptured", String.valueOf(StringUtils.hasText(evidencePackage.getBaselineSnapshotJson())));
        facts.put("ragResultsCaptured", String.valueOf(StringUtils.hasText(evidencePackage.getRagResultsJson())));
        putIfPresent(facts, "rawSystemPromptHash", prefixedSha256(evidencePackage.getRawSystemPrompt()));
        putIfPresent(facts, "rawUserPromptHash", prefixedSha256(evidencePackage.getRawUserPrompt()));
        putIfPresent(facts, "systemPromptHash", prefixedSha256(evidencePackage.getSystemPromptText()));
        putIfPresent(facts, "userPromptHash", prefixedSha256(evidencePackage.getUserPromptText()));
        putIfPresent(facts, "rawSystemPromptRef", promptRef(evidencePackage, "raw_system_prompt"));
        putIfPresent(facts, "rawUserPromptRef", promptRef(evidencePackage, "raw_user_prompt"));
        putIfPresent(facts, "systemPromptTextRef", promptRef(evidencePackage, "system_prompt_text"));
        putIfPresent(facts, "userPromptTextRef", promptRef(evidencePackage, "user_prompt_text"));
        return facts;
    }

    private Map<String, String> requestAndAuthFacts(
            Map<String, Object> requestFacts,
            Map<String, Object> authState,
            Map<String, Object> decision) {
        Map<String, String> facts = new LinkedHashMap<>(stringMap(requestFacts));
        putIfPresent(facts, "requestPath", firstNonBlank(
                facts.get("requestPath"),
                facts.get("resourceUrl"),
                facts.get("path"),
                facts.get("uri")));
        putIfPresent(facts, "httpMethod", firstNonBlank(facts.get("httpMethod"), facts.get("method")));
        putIfPresent(facts, "resourceId", firstNonBlank(facts.get("resourceId"), facts.get("endpointKey")));
        putIfPresent(facts, "clientIp", firstNonBlank(facts.get("clientIp"), facts.get("ipAddress"), facts.get("remoteAddr")));
        Map<String, String> authFacts = stringMap(authState);
        putIfPresent(facts, "mfaVerified", authFacts.get("mfaVerified"));
        putIfPresent(facts, "authMethod", firstNonBlank(authFacts.get("authMethod"), authFacts.get("authenticationMethod")));
        putIfPresent(facts, "authorizationEffect", authFacts.get("authorizationEffect"));
        putIfPresent(facts, "effectiveRoles", firstNonBlank(authFacts.get("effectiveRoles"), authFacts.get("roles")));
        putIfPresent(facts, "effectivePermissions", firstNonBlank(authFacts.get("effectivePermissions"), authFacts.get("permissions")));
        Map<String, String> decisionFacts = stringMap(decision);
        putIfPresent(facts, "decisionAction", firstNonBlank(
                decisionFacts.get("action"),
                decisionFacts.get("decisionAction"),
                decisionFacts.get("effect")));
        return Map.copyOf(facts);
    }

    private Map<String, Object> parseJson(String json) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, MAP_TYPE);
        }
        catch (Exception ignored) {
            return Map.of();
        }
    }

    private Map<String, String> stringMap(Map<String, Object> raw) {
        if (raw == null || raw.isEmpty()) {
            return Map.of();
        }
        Map<String, String> result = new LinkedHashMap<>();
        raw.forEach((key, value) -> putIfPresent(result, key, value == null ? null : String.valueOf(value)));
        return result;
    }

    private String text(Map<String, Object> raw, String key) {
        Object value = raw == null ? null : raw.get(key);
        return value == null ? null : String.valueOf(value);
    }

    private void putIfPresent(Map<String, String> target, String key, String value) {
        if (StringUtils.hasText(value)) {
            target.put(key, value.trim());
        }
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private String format(Instant instant) {
        return LocalDateTime.ofInstant(instant, ZoneId.of("Asia/Seoul")).format(KOREA_TIME);
    }

    private String latestAggregateRunId(List<OfficialVerificationRunView> runs) {
        if (runs == null || runs.isEmpty()) {
            return null;
        }
        return aggregateRunId(runs.get(0));
    }

    private String aggregateRunId(OfficialVerificationRunView run) {
        if (run == null) {
            return null;
        }
        Object rawAggregateRunId = run.rawEvidence() == null ? null : run.rawEvidence().get("aggregateRunId");
        if (rawAggregateRunId != null && StringUtils.hasText(String.valueOf(rawAggregateRunId))) {
            return String.valueOf(rawAggregateRunId).trim();
        }
        String runId = run.runId();
        String endpointKey = run.endpointKey();
        if (!StringUtils.hasText(runId)) {
            return null;
        }
        if (StringUtils.hasText(endpointKey)) {
            String suffix = "-" + endpointKey.trim().toLowerCase(Locale.ROOT);
            if (runId.toLowerCase(Locale.ROOT).endsWith(suffix)) {
                return runId.substring(0, runId.length() - suffix.length());
            }
        }
        return runId;
    }

    private String sha256(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 digest is not available.", exception);
        }
    }

    private String prefixedSha256(String value) {
        String digest = sha256(value);
        return digest == null ? null : "sha256:" + digest;
    }

    private String promptRef(SealedEvidencePackage evidencePackage, String columnName) {
        if (evidencePackage == null || !StringUtils.hasText(evidencePackage.getPackageId())) {
            return null;
        }
        return "sealed_evidence_package." + columnName + "#" + evidencePackage.getPackageId();
    }
}
