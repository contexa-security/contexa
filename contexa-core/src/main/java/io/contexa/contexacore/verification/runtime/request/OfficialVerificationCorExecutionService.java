package io.contexa.contexacore.verification.runtime.request;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import io.contexa.contexacore.verification.runtime.OfficialVerificationExecutionRequest;
import org.springframework.util.StringUtils;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Transactional(transactionManager = "contexaTransactionManager")
public class OfficialVerificationCorExecutionService extends AbstractOfficialVerificationRequestMetricExecutionService<OfficialVerificationCorExecutionService.CorRunRecord, OfficialVerificationCorExecutionService.EndpointDefinition> implements OfficialVerificationCorExecutor {

    private final OfficialVerificationCorEvidenceFactory evidenceFactory = new OfficialVerificationCorEvidenceFactory();

    static final OfficialVerificationContractMetadataSupport.ContractStatus CONTRACT_STATUS =
            OfficialVerificationContractMetadataSupport.aligned(
                    "COR",
                    OfficialVerificationCorExecutionService.class.getName(),
                    "executeRun / buildRequestFacts / buildRawEvidence",
                    "metricCode"
            );

    private static final DateTimeFormatter KOREA_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withLocale(Locale.KOREA)
            .withZone(ZoneId.of("Asia/Seoul"));
    private static final String RESOURCE_ID_HEADER = "X-Contexa-Official-Verification-Resource-Id";
    private static final String RUN_COUNT_HEADER = "X-Contexa-Official-Verification-Requested-Run-Count";
    private static final String CONTAMINATION_SEED_HEADER = "X-Contexa-Official-Verification-Contamination-Seed";
    private static final String BASELINE_SEED_HEADER = "X-Contexa-Official-Verification-Baseline-Seed";
    private static final String USER_ID_HEADER = "X-Contexa-Official-Verification-User-Id";

    public OfficialVerificationCorExecutionService(
        SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
        PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
        OfficialVerificationAnalysisEventStore analysisEventStore,
        OfficialVerificationProbeClient probeClient,
        ObjectMapper objectMapper
) {
    super("COR", decisionOutboxRepository, promptAuditOutboxRepository, analysisEventStore, probeClient, objectMapper, CorRunRecord::runId, CorRunRecord::startedAt);
}

@Override
public synchronized CorRunRecord executeRun(
        String userId,
        String endpointKey,
        String resourceId,
        String requestPath,
        int requestedRunCount,
        boolean rerun,
        boolean contaminationSeed,
        boolean baselineSeedRequested,
        OfficialVerificationExecutionRequest request
) {
    return executeRunTemplate(userId, endpointKey, resourceId, requestPath, requestedRunCount, rerun, contaminationSeed, baselineSeedRequested, request);
}

@Override
protected String requestIdPrefix() {
    return "enterprise-cor-";
}

@Override
protected CorRunRecord buildRunRecord(RequestMetricExecutionState<EndpointDefinition> state) {
    Map<String, Object> decisionMetadata = evidenceFactory.firstMetadata(state.artifacts().events(), "DECISION_APPLIED");
    Map<String, Object> decisionAttributes = evidenceFactory.map(state.artifacts().decisionPayload().get("attributes"));
    Map<String, Object> promptTelemetry = OfficialVerificationRuntimeEvidenceSupport.resolvePromptTelemetry(
            decisionMetadata,
            decisionAttributes,
            state.artifacts().decisionPayload(),
            state.artifacts().promptPayload()
    );
    ContaminationSummary contamination = evidenceFactory.summarizeContamination(state.userId(), state.artifacts().promptPayload());
    List<CorCheckResult> checks = evidenceFactory.buildChecks(
            state.requestId(),
            state.invocation(),
            decisionMetadata,
            state.artifacts().promptPayload(),
            state.artifacts().promptOutbox(),
            contamination
    );
    int totalChecks = checks.size();
    int passedChecks = (int) checks.stream().filter(CorCheckResult::pass).count();
    double contaminationRate = contamination.contaminationRate();
    double contaminationScore = Math.max(0.0d, 100.0d - contaminationRate);
    double structuralScore = totalChecks <= 0 ? 0.0d : (passedChecks * 100.0d) / totalChecks;
    double score = Math.min(contaminationScore, structuralScore);
    boolean success = contaminationRate <= 0.0d && passedChecks == totalChecks;
    CorRunAssembly assembly = new CorRunAssembly(
            decisionMetadata, decisionAttributes, promptTelemetry, contamination,
            checks, totalChecks, passedChecks, score, success);
    return assembleRunRecord(state, assembly);}

private CorRunRecord assembleRunRecord(RequestMetricExecutionState<EndpointDefinition> state, CorRunAssembly assembly) {
    return new CorRunRecord(
            UUID.randomUUID().toString(),
            state.runOrdinal(),
            state.endpoint().key(),
            state.endpoint().label(),
            state.requestId(),
            assembly.score(),
            assembly.passedChecks(),
            assembly.totalChecks(),
            state.processingTimeMs(),
            assembly.success() ? "Threshold passed" : "Threshold failed",
            assembly.success() ? "assembly.success()" : "error",
            evidenceFactory.buildMessage(assembly.contamination(), state.artifacts().promptOutbox()),
            KOREA_TIME.format(state.startedAt()),
            KOREA_TIME.format(state.completedAt()),
            assembly.checks(),
            OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRequestFacts(
                    evidenceFactory.buildRequestFacts(
                            state.endpoint(),
                            state.userId(),
                            state.requestId(),
                            state.invocation(),
                            state.requestedRunCount(),
                            state.rerun(),
                            state.contaminationSeed(),
                            state.baselineSeedRequested()
                    ),
                    state.request()
            ),
            evidenceFactory.buildCorEventFacts(state.artifacts().events(), assembly.decisionMetadata()),
            evidenceFactory.buildCorPromptFacts(assembly.promptTelemetry(), state.artifacts().promptPayload(), assembly.contamination()),
            evidenceFactory.buildCorAnalysisFacts(state.artifacts().decisionPayload(), state.artifacts().decisionOutbox(), state.artifacts().promptOutbox(), state.artifacts().promptPayload(), assembly.contamination()),
            state.artifacts().events().stream().map(evidenceFactory::toCorEventItem).toList(),
            OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                    evidenceFactory.buildCorRawEvidence(
                            state.endpoint(),
                            state.userId(),
                            state.requestedRunCount(),
                            state.rerun(),
                            state.contaminationSeed(),
                            state.baselineSeedRequested(),
                            state.invocation(),
                            state.artifacts().events(),
                            state.artifacts().decisionOutbox(),
                            state.artifacts().promptOutbox(),
                            state.artifacts().decisionPayload(),
                            state.artifacts().promptPayload(),
                            assembly.decisionMetadata(),
                            assembly.decisionAttributes(),
                            assembly.promptTelemetry(),
                            assembly.contamination()
                    ),
                    state.request()
            )
    );
}

    @Override
protected EndpointDefinition resolveEndpoint(String endpointKey, String resourceId, String requestPath) {
    OfficialVerificationReplayPathSupport.ReplayTarget replayTarget = resolveStandardReplayTarget(
            endpointKey,
            resourceId,
            requestPath,
            List.of("normal", "sensitive", "critical")
    );
    return new EndpointDefinition(replayTarget.endpointKey(), switch (replayTarget.endpointKey()) {
        case "sensitive" -> "Sensitive Resource";
        case "critical" -> "Critical Resource";
        default -> "Normal Resource";
    }, replayTarget.requestPath(), replayTarget.resourceId());
}

@Override
protected Map<String, Object> invokeProbe(
        EndpointDefinition endpoint,
        String requestId,
        String verificationUserId,
        int requestedRunCount,
        boolean contaminationSeed,
        boolean baselineSeedRequested,
        OfficialVerificationExecutionRequest request
) {
    return invokeProbeRequest(
            request,
            endpoint.path(),
            headers -> forwardHeaders(
                    headers,
                    request,
                    requestId,
                    verificationUserId,
                    endpoint.resourceId(),
                    requestedRunCount,
                    contaminationSeed,
                    baselineSeedRequested
            )
    );
}

private void forwardHeaders(
            OfficialVerificationProbeHeaders headers,
            OfficialVerificationExecutionRequest request,
            String requestId,
            String userId,
            String resourceId,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested
    ) {
        headers.set("X-Request-ID", requestId);
        headers.set(RESOURCE_ID_HEADER, StringUtils.hasText(resourceId) ? resourceId.trim() : "resource-001");
        headers.set(RUN_COUNT_HEADER, String.valueOf(requestedRunCount));
        headers.set(CONTAMINATION_SEED_HEADER, String.valueOf(contaminationSeed));
        headers.set(BASELINE_SEED_HEADER, String.valueOf(baselineSeedRequested));
        headers.set(USER_ID_HEADER, OfficialVerificationRuntimeIsolationSupport.verificationSubjectId(userId, requestId));
        if (request == null) {
            return;
        }
        copyHeader(request, headers, OfficialVerificationProbeHeaders.COOKIE);
        copyHeader(request, headers, OfficialVerificationProbeHeaders.AUTHORIZATION);
        copyHeader(request, headers, "X-XSRF-TOKEN");
        copyVerificationBridgeHeaders(request, headers);
    }

    private record CorRunAssembly(
            Map<String, Object> decisionMetadata,
            Map<String, Object> decisionAttributes,
            Map<String, Object> promptTelemetry,
            ContaminationSummary contamination,
            List<CorCheckResult> checks,
            int totalChecks,
            int passedChecks,
            double score,
            boolean success) {
    }
    record EndpointDefinition(String key, String label, String path, String resourceId) {
    }

    record ContaminationSummary(
            List<Map<String, Object>> contexts,
            int requestedDocumentCount,
            int allowedDocumentCount,
            int deniedDocumentCount,
            String retrievalPurpose,
            List<String> deniedReasons,
            int contaminatedCount,
            int foreignUserCount,
            int purposeMismatchCount,
            int scopeViolationCount,
            int contaminatedIncludedCount
    ) {

        int totalContextCount() {
            return contexts != null ? contexts.size() : 0;
        }

        double contaminationRate() {
            return totalContextCount() <= 0 ? 0.0d : (contaminatedCount * 100.0d) / totalContextCount();
        }

        Map<String, Object> toMap() {
            Map<String, Object> summary = new LinkedHashMap<>();
            summary.put("retrievalPurpose", StringUtils.hasText(retrievalPurpose) ? retrievalPurpose : "n/a");
            summary.put("requestedDocumentCount", requestedDocumentCount);
            summary.put("allowedDocumentCount", allowedDocumentCount);
            summary.put("deniedDocumentCount", deniedDocumentCount);
            summary.put("contextLedgerCount", totalContextCount());
            summary.put("contaminatedCount", contaminatedCount);
            summary.put("foreignUserCount", foreignUserCount);
            summary.put("purposeMismatchCount", purposeMismatchCount);
            summary.put("scopeViolationCount", scopeViolationCount);
            summary.put("contaminatedIncludedCount", contaminatedIncludedCount);
            summary.put("contaminationRate", contaminationRate());
            summary.put("deniedReasons", deniedReasons == null ? List.of() : deniedReasons);
            return Map.copyOf(summary);
        }
    }

    public record CorRunSummary(
            String runId,
            int round,
            String endpointKey,
            String endpointLabel,
            String requestId,
            double score,
            int passedChecks,
            int totalChecks,
            Long processingTimeMs,
            String state,
            String stateTone,
            String startedAt,
            String completedAt) {
    }

    public record CorRunRecord(
            String runId,
            int round,
            String endpointKey,
            String endpointLabel,
            String requestId,
            double score,
            int passedChecks,
            int totalChecks,
            Long processingTimeMs,
            String state,
            String stateTone,
            String message,
            String startedAt,
            String completedAt,
            List<CorCheckResult> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<CorEventItem> events,
            Map<String, Object> rawEvidence) implements OfficialVerificationDetailedRunRecordView<CorCheckResult, CorEventItem> {

        public CorRunSummary toSummary() {
            return new CorRunSummary(
                    runId,
                    round,
                    endpointKey,
                    endpointLabel,
                    requestId,
                    score,
                    passedChecks,
                    totalChecks,
                    processingTimeMs,
                    state,
                    stateTone,
                    startedAt,
                    completedAt
            );
        }
    }

    public record CorCheckResult(
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) implements OfficialVerificationCheckResultView {
    }

    public record CorEventItem(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}





