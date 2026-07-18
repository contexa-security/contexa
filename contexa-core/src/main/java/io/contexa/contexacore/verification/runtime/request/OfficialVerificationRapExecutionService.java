package io.contexa.contexacore.verification.runtime.request;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import io.contexa.contexacore.verification.runtime.OfficialVerificationExecutionRequest;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

@Transactional(transactionManager = "contexaTransactionManager")
public class OfficialVerificationRapExecutionService extends AbstractOfficialVerificationRequestMetricExecutionService<OfficialVerificationRapExecutionService.RapRunRecord, OfficialVerificationRapExecutionService.EndpointDefinition> implements OfficialVerificationRapExecutor {

    private final OfficialVerificationRapEvidenceFactory evidenceFactory = new OfficialVerificationRapEvidenceFactory();

    static final OfficialVerificationContractMetadataSupport.ContractStatus CONTRACT_STATUS =
            OfficialVerificationContractMetadataSupport.aligned(
                    "RAP",
                    OfficialVerificationRapExecutionService.class.getName(),
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

    public OfficialVerificationRapExecutionService(
        SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
        PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
        OfficialVerificationAnalysisEventStore analysisEventStore,
        OfficialVerificationProbeClient probeClient,
        ObjectMapper objectMapper
) {
    super("RAP", decisionOutboxRepository, promptAuditOutboxRepository, analysisEventStore, probeClient, objectMapper, RapRunRecord::runId, RapRunRecord::startedAt);
}

@Override
public synchronized RapRunRecord executeRun(
        String userId,
        String endpointKey,
        String resourceId,
        String requestPath,
        int requestedRunCount,
        boolean rerun,
        boolean authorizationSeed,
        boolean baselineSeedRequested,
        OfficialVerificationExecutionRequest request
) {
    return executeRunTemplate(userId, endpointKey, resourceId, requestPath, requestedRunCount, rerun, authorizationSeed, baselineSeedRequested, request);
}

@Override
protected String requestIdPrefix() {
    return "enterprise-rap-";
}

@Override
protected RapRunRecord buildRunRecord(RequestMetricExecutionState<EndpointDefinition> state) {
    Map<String, Object> decisionMetadata = evidenceFactory.firstMetadata(state.artifacts().events(), "DECISION_APPLIED");
    Map<String, Object> decisionAttributes = evidenceFactory.map(state.artifacts().decisionPayload().get("attributes"));
    Map<String, Object> promptTelemetry = evidenceFactory.firstPresent(decisionMetadata, decisionAttributes, state.artifacts().decisionPayload());
    AuthorizationSummary authorization = evidenceFactory.summarizeAuthorization(state.artifacts().promptPayload());
    List<RapCheckResult> checks = evidenceFactory.buildChecks(
            state.requestId(),
            state.invocation(),
            decisionMetadata,
            state.artifacts().promptPayload(),
            state.artifacts().promptOutbox(),
            authorization
    );
    int totalChecks = checks.size();
    int passedChecks = (int) checks.stream().filter(RapCheckResult::pass).count();
    double authorizationPrecision = authorization.authorizationPrecision();
    double structuralScore = totalChecks <= 0 ? 0.0d : (passedChecks * 100.0d) / totalChecks;
    double score = Math.min(authorizationPrecision, structuralScore);
    boolean success = authorizationPrecision >= 95.0d && passedChecks == totalChecks;
    RapRunAssembly assembly = new RapRunAssembly(
            decisionMetadata, decisionAttributes, promptTelemetry, authorization,
            checks, totalChecks, passedChecks, score, success);
    return assembleRunRecord(state, assembly);}

private RapRunRecord assembleRunRecord(RequestMetricExecutionState<EndpointDefinition> state, RapRunAssembly assembly) {
    return new RapRunRecord(
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
            evidenceFactory.buildMessage(assembly.authorization(), state.artifacts().promptOutbox()),
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
            evidenceFactory.buildRapEventFacts(state.artifacts().events(), assembly.decisionMetadata()),
            evidenceFactory.buildRapPromptFacts(assembly.promptTelemetry(), state.artifacts().promptPayload(), assembly.authorization()),
            evidenceFactory.buildRapAnalysisFacts(state.artifacts().decisionPayload(), state.artifacts().decisionOutbox(), state.artifacts().promptOutbox(), state.artifacts().promptPayload(), assembly.authorization()),
            state.artifacts().events().stream().map(evidenceFactory::toRapEventItem).toList(),
            OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                    evidenceFactory.buildRapRawEvidence(
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
                            assembly.authorization()
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
            boolean authorizationSeed,
            boolean baselineSeedRequested
    ) {
        headers.set("X-Request-ID", requestId);
        headers.set(RESOURCE_ID_HEADER, StringUtils.hasText(resourceId) ? resourceId.trim() : "resource-001");
        headers.set(RUN_COUNT_HEADER, String.valueOf(requestedRunCount));
        headers.set(CONTAMINATION_SEED_HEADER, String.valueOf(authorizationSeed));
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

    private record RapRunAssembly(
            Map<String, Object> decisionMetadata,
            Map<String, Object> decisionAttributes,
            Map<String, Object> promptTelemetry,
            AuthorizationSummary authorization,
            List<RapCheckResult> checks,
            int totalChecks,
            int passedChecks,
            double score,
            boolean success) {
    }
    record EndpointDefinition(String key, String label, String path, String resourceId) {
    }

    record AuthorizationSummary(
            List<Map<String, Object>> contexts,
            int requestedDocumentCount,
            int allowedDocumentCount,
            int deniedDocumentCount,
            String retrievalPurpose,
            List<String> deniedReasons,
            int includedCount,
            int allowedDecisionCount,
            int deniedDecisionCount,
            int deniedIncludedCount
    ) {

        int totalContextCount() {
            return contexts != null ? contexts.size() : 0;
        }

        double authorizationPrecision() {
            return requestedDocumentCount <= 0 ? 100.0d : (allowedDocumentCount * 100.0d) / requestedDocumentCount;
        }

        Map<String, Object> toMap() {
            Map<String, Object> summary = new LinkedHashMap<>();
            summary.put("retrievalPurpose", StringUtils.hasText(retrievalPurpose) ? retrievalPurpose : "n/a");
            summary.put("requestedDocumentCount", requestedDocumentCount);
            summary.put("allowedDocumentCount", allowedDocumentCount);
            summary.put("deniedDocumentCount", deniedDocumentCount);
            summary.put("contextLedgerCount", totalContextCount());
            summary.put("includedCount", includedCount);
            summary.put("allowedDecisionCount", allowedDecisionCount);
            summary.put("deniedDecisionCount", deniedDecisionCount);
            summary.put("deniedIncludedCount", deniedIncludedCount);
            summary.put("authorizationPrecision", authorizationPrecision());
            summary.put("deniedReasons", deniedReasons == null ? List.of() : deniedReasons);
            return Map.copyOf(summary);
        }
    }

    public record RapRunSummary(
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

    public record RapRunRecord(
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
            List<RapCheckResult> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<RapEventItem> events,
            Map<String, Object> rawEvidence) implements OfficialVerificationDetailedRunRecordView<RapCheckResult, RapEventItem> {

        public RapRunSummary toSummary() {
            return new RapRunSummary(
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

    public record RapCheckResult(
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) implements OfficialVerificationCheckResultView {
    }

    public record RapEventItem(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}






