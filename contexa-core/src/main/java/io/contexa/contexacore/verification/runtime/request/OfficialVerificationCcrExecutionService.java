package io.contexa.contexacore.verification.runtime.request;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import io.contexa.contexacore.verification.runtime.OfficialVerificationExecutionRequest;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

@Transactional(transactionManager = "contexaTransactionManager")
public class OfficialVerificationCcrExecutionService extends AbstractOfficialVerificationRequestMetricExecutionService<OfficialVerificationCcrExecutionService.CcrRunRecord, OfficialVerificationCcrExecutionService.EndpointDefinition> implements OfficialVerificationCcrExecutor {

    static final OfficialVerificationContractMetadataSupport.ContractStatus CONTRACT_STATUS =
            OfficialVerificationContractMetadataSupport.aligned(
                    "CCR",
                    OfficialVerificationCcrExecutionService.class.getName(),
                    "executeRun / buildRequestFacts / buildRawEvidence",
                    "metricCode"
            );

    private static final String RESOURCE_ID_HEADER = "X-Contexa-Official-Verification-Resource-Id";
    private static final String RUN_COUNT_HEADER = "X-Contexa-Official-Verification-Requested-Run-Count";
    private static final String CONTAMINATION_SEED_HEADER = "X-Contexa-Official-Verification-Contamination-Seed";
    private static final String BASELINE_SEED_HEADER = "X-Contexa-Official-Verification-Baseline-Seed";
    private static final String USER_ID_HEADER = "X-Contexa-Official-Verification-User-Id";
    private static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";
    private static final String DEVICE_ID_HEADER = "X-Device-Id";
    private static final String SIMULATED_USER_AGENT_HEADER = "X-Simulated-User-Agent";
    private static final String SIMULATED_USER_AGENT_LABEL_HEADER = "X-Simulated-User-Agent-Label";
    private static final String CCR_CLIENT_IP = "192.168.1.100";
    private static final String CCR_BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    private static final String CCR_USER_AGENT_LABEL = "Chrome 120 / Windows 11";
    private static final String CCR_DEVICE_ID = "official-verification-ccr-admin-browser";

    private final OfficialVerificationCcrEvidenceFactory evidenceFactory;

    public OfficialVerificationCcrExecutionService(
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            OfficialVerificationProbeClient probeClient,
            ObjectMapper objectMapper
    ) {
        super("CCR", decisionOutboxRepository, promptAuditOutboxRepository, analysisEventStore, probeClient, objectMapper, CcrRunRecord::runId, CcrRunRecord::startedAt);
        this.evidenceFactory = new OfficialVerificationCcrEvidenceFactory();
    }

    @Override
    public synchronized CcrRunRecord executeRun(
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
    protected String resolveVerificationUserId(String userId, String requestId) {
        return OfficialVerificationRuntimeIsolationSupport.verificationSubjectId(userId, requestId);
    }

    @Override
    protected String requestIdPrefix() {
        return "enterprise-ccr-";
    }

    @Override
    protected void beforeInvocation(
            EndpointDefinition endpoint,
            String userId,
            String verificationUserId,
            String requestId,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request
    ) {
        primeSessionContext(endpoint, requestId, verificationUserId, contaminationSeed, baselineSeedRequested, request);
    }

    @Override
    protected EndpointDefinition resolveEndpoint(String endpointKey, String resourceId, String requestPath) {
        OfficialVerificationReplayPathSupport.ReplayTarget replayTarget = OfficialVerificationReplayPathSupport.retargetProbeTarget(endpointKey, resourceId, requestPath, List.of("normal", "sensitive", "critical"));
        return new EndpointDefinition(replayTarget.endpointKey(), switch (replayTarget.endpointKey()) {
            case "sensitive" -> "Sensitive Resource";
            case "critical" -> "Critical Resource";
            default -> "Normal Resource";
        }, replayTarget.requestPath(), replayTarget.resourceId());
    }
    @Override
    protected CcrRunRecord buildRunRecord(RequestMetricExecutionState<EndpointDefinition> state) {
        return evidenceFactory.buildRunRecord(new OfficialVerificationCcrEvidenceFactory.CcrRunInput(
                state.endpoint(), state.userId(), state.requestId(), state.runOrdinal(), state.requestedRunCount(),
                state.rerun(), state.contaminationSeed(), state.baselineSeedRequested(), state.request(),
                state.startedAt(), state.completedAt(), state.processingTimeMs(), state.invocation(),
                state.artifacts().events(), state.artifacts().decisionOutbox(), state.artifacts().promptOutbox(),
                state.artifacts().decisionPayload(), state.artifacts().promptPayload()
        ));
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
        return invokeProbeRequest(request, endpoint.path(), headers -> forwardHeaders(
                        headers,
                        request,
                        requestId,
                        verificationUserId,
                        endpoint.resourceId(),
                        endpoint.path(),
                        requestedRunCount,
                        contaminationSeed,
                        baselineSeedRequested
        ));
    }

    private void primeSessionContext(
            EndpointDefinition endpoint,
            String requestId,
            String verificationUserId,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request
    ) {
        if (endpoint == null || !StringUtils.hasText(requestId)) {
            return;
        }
        EndpointDefinition warmupEndpoint = resolveEndpoint(endpoint.key(), endpoint.resourceId() + "-warmup", endpoint.path());
        invokeProbe(
                warmupEndpoint,
                requestId + "-warmup",
                verificationUserId,
                1,
                contaminationSeed,
                baselineSeedRequested,
                request
        );
        sleep(250L);
    }

    private void forwardHeaders(
            OfficialVerificationProbeHeaders headers,
            OfficialVerificationExecutionRequest request,
            String requestId,
            String verificationUserId,
            String resourceId,
            String requestPath,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested
    ) {
        headers.set("X-Request-ID", requestId);
        headers.set(OfficialVerificationProbeHeaders.USER_AGENT, CCR_BROWSER_USER_AGENT);
        headers.set(FORWARDED_FOR_HEADER, CCR_CLIENT_IP);
        headers.set(DEVICE_ID_HEADER, CCR_DEVICE_ID);
        headers.set(SIMULATED_USER_AGENT_HEADER, CCR_BROWSER_USER_AGENT);
        headers.set(SIMULATED_USER_AGENT_LABEL_HEADER, CCR_USER_AGENT_LABEL);
        headers.set(RESOURCE_ID_HEADER, StringUtils.hasText(resourceId) ? resourceId.trim() : "resource-001");
        headers.set(RUN_COUNT_HEADER, String.valueOf(requestedRunCount));
        headers.set(CONTAMINATION_SEED_HEADER, String.valueOf(contaminationSeed));
        headers.set(BASELINE_SEED_HEADER, String.valueOf(baselineSeedRequested));
        headers.set(USER_ID_HEADER, verificationUserId);
        if (request == null) {
            return;
        }
        copyHeader(request, headers, OfficialVerificationProbeHeaders.COOKIE);
        copyHeader(request, headers, OfficialVerificationProbeHeaders.AUTHORIZATION);
        copyHeader(request, headers, "X-XSRF-TOKEN");
        copyVerificationBridgeHeaders(request, headers);
    }
    private void sleep(long millis) {
        try {
            Thread.sleep(millis);
        }
        catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
        }
    }



    record EndpointDefinition(String key, String label, String path, String resourceId) {
    }

    public record CcrRunSummary(
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

    public record CcrRunRecord(
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
            List<CcrCheckResult> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<CcrEventItem> events,
            Map<String, Object> rawEvidence) implements OfficialVerificationDetailedRunRecordView<CcrCheckResult, CcrEventItem> {

        public CcrRunSummary toSummary() {
            return new CcrRunSummary(
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

    public record CcrCheckResult(
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) implements OfficialVerificationCheckResultView {
    }

    public record CcrEventItem(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}











