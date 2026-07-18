package io.contexa.contexacore.verification.runtime.sealed;

import static io.contexa.contexacore.verification.runtime.sealed.SealedEvidenceVerificationFacts.firstNonBlank;
import static io.contexa.contexacore.verification.runtime.sealed.SealedEvidenceVerificationFacts.parseJson;
import static io.contexa.contexacore.verification.runtime.sealed.SealedEvidenceVerificationFacts.promptFacts;
import static io.contexa.contexacore.verification.runtime.sealed.SealedEvidenceVerificationFacts.putIfPresent;
import static io.contexa.contexacore.verification.runtime.sealed.SealedEvidenceVerificationFacts.requestAndAuthFacts;
import static io.contexa.contexacore.verification.runtime.sealed.SealedEvidenceVerificationFacts.sha256;
import static io.contexa.contexacore.verification.runtime.sealed.SealedEvidenceVerificationFacts.text;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageLookupPort;
import io.contexa.contexacore.verification.evidence.SealedEvidencePromptEvidenceBackfill;
import io.contexa.contexacore.verification.metric.OfficialMetricEvaluationResult;
import io.contexa.contexacore.verification.metric.OfficialPromptQualityMetricContractGate;
import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricCatalog;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCasePublisher;
import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunStore;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricEvaluationSuite;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

public class DefaultOfficialSealedEvidenceVerificationRuntime implements OfficialSealedEvidenceVerificationRuntime {

    private static final DateTimeFormatter KOREA_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final String EXECUTION_PATH = "CORE_OFFICIAL_SEALED_EVIDENCE_REPLAY";
    private final SealedEvidencePackageLookupPort evidenceLookupService;
    private final OfficialVerificationMetricCatalog metricCatalog;
    private final OfficialVerificationRunStore runStore;
    private final OfficialVerificationCasePublisher casePublisher;
    private final ObjectMapper objectMapper;
    private final OfficialVerificationMessageResolver messageResolver;
    private final OfficialPromptQualityMetricContractGate metricContractGate;
    private final FinalPromptMetricEvaluationSuite finalPromptMetricEvaluationSuite;
    private final OfficialPromptQualityNarrativeCatalog narrativeCatalog;
    private final SealedEvidenceOfficialRunViewFactory runViewFactory;

    public DefaultOfficialSealedEvidenceVerificationRuntime(
            SealedEvidencePackageLookupPort evidenceLookupService,
            OfficialVerificationMetricCatalog metricCatalog,
            OfficialVerificationRunStore runStore,
            OfficialVerificationCasePublisher casePublisher,
            ObjectMapper objectMapper) {
        this(
                evidenceLookupService,
                metricCatalog,
                runStore,
                casePublisher,
                objectMapper,
                OfficialVerificationMessageResolver.classpath(Locale.KOREAN));
    }

    public DefaultOfficialSealedEvidenceVerificationRuntime(
            SealedEvidencePackageLookupPort evidenceLookupService,
            OfficialVerificationMetricCatalog metricCatalog,
            OfficialVerificationRunStore runStore,
            OfficialVerificationCasePublisher casePublisher,
            ObjectMapper objectMapper,
            OfficialVerificationMessageResolver messageResolver) {
        this.evidenceLookupService = evidenceLookupService;
        this.metricCatalog = metricCatalog;
        this.runStore = runStore;
        this.casePublisher = casePublisher;
        this.objectMapper = objectMapper;
        this.messageResolver = messageResolver;
        this.metricContractGate = new OfficialPromptQualityMetricContractGate(metricCatalog);
        this.finalPromptMetricEvaluationSuite = new FinalPromptMetricEvaluationSuite(objectMapper, this.messageResolver);
        this.narrativeCatalog = new OfficialPromptQualityNarrativeCatalog(this.messageResolver);
        this.runViewFactory = new SealedEvidenceOfficialRunViewFactory(this.messageResolver);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public OfficialSealedEvidenceVerificationResult executeAll(OfficialSealedEvidenceVerificationRequest request) {
        if (request == null || !StringUtils.hasText(request.packageId())) {
            throw new IllegalArgumentException(messageResolver.resolve(
                    "enterprise.pqa.runtimeVerification.error.packageId.required"));
        }
        SealedEvidencePackage loadedPackage = evidenceLookupService.findByPackageId(request.packageId().trim())
                .orElseThrow(() -> new IllegalArgumentException(messageResolver.resolve(
                        "enterprise.pqa.runtimeVerification.error.packageId.notFound",
                        request.packageId())));
        SealedEvidencePackage evidencePackage = prepareSealedPromptEvidencePackage(loadedPackage);
        String operatorId = firstNonBlank(request.operatorId(), evidencePackage.getUserId(), "official-sealed-evidence-runtime");
        boolean integrityValid = evidenceLookupService.verifyIntegrity(evidencePackage);
        Instant started = Instant.now();
        String startedAt = format(started);
        Map<String, Object> requestFacts = parseJson(objectMapper, evidencePackage.getRequestFactsJson());
        Map<String, Object> authState = parseJson(objectMapper, evidencePackage.getAuthStateJson());
        Map<String, Object> promptMetadata = parseJson(objectMapper, evidencePackage.getPromptExecutionMetadataJson());
        Map<String, Object> decision = parseJson(objectMapper, evidencePackage.getDecisionJson());
        Map<String, String> requestFactStrings = requestAndAuthFacts(requestFacts, authState, decision);
        Map<String, String> promptFactStrings = promptFacts(
                objectMapper, evidencePackage, promptMetadata, messageResolver);
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
            throw new IllegalArgumentException(messageResolver.resolve(
                    "enterprise.pqa.runtimeVerification.error.packageId.required"));
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
                SealedEvidencePromptEvidenceBackfill.prepare(objectMapper, loadedPackage, messageResolver);
        if (!result.ready()) {
            throw new IllegalStateException(messageResolver.resolve(
                    "enterprise.pqa.runtimeVerification.preflight.inputContractInvalid",
                    String.join(" ", result.violations())));
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
                evidenceReferences(evidencePackage, runView, requestFacts, promptFacts));
        runStore.saveDetailed(operatorId, record, runView);
        casePublisher.register(operatorId, record);
    }

    private Map<String, String> evidenceReferences(
            SealedEvidencePackage evidencePackage,
            OfficialVerificationRunView runView,
            Map<String, String> requestFacts,
            Map<String, String> promptFacts) {
        Map<String, String> references = new LinkedHashMap<>();
        putIfPresent(references, "packageId", evidencePackage.getPackageId());
        putIfPresent(references, "aggregateRunId", aggregateRunId(runView));
        putIfPresent(references, "runId", runView == null ? null : runView.runId());
        putIfPresent(references, "metricCode", runView == null ? null : runView.endpointKey());
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

}
