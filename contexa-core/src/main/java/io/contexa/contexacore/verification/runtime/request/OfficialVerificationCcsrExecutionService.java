package io.contexa.contexacore.verification.runtime.request;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

@Transactional(transactionManager = "contexaTransactionManager")
public class OfficialVerificationCcsrExecutionService extends AbstractOfficialVerificationRequestMetricExecutionService<OfficialVerificationCcsrExecutionService.CcsrRunRecord, OfficialVerificationCcsrExecutionService.EndpointDefinition> implements OfficialVerificationCcsrExecutor {

    static final OfficialVerificationContractMetadataSupport.ContractStatus CONTRACT_STATUS =
            OfficialVerificationContractMetadataSupport.aligned(
                    "CCSR",
                    OfficialVerificationCcsrExecutionService.class.getName(),
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
    private static final String CCSR_CLIENT_IP = "192.168.1.100";
    private static final String CCSR_BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    private static final String CCSR_USER_AGENT_LABEL = "Chrome 120 / Windows 11";
    private static final String CCSR_DEVICE_ID = "official-verification-ccsr-admin-browser";


    private final OfficialVerificationCcsrEvidenceFactory evidenceFactory;
    private final OfficialVerificationFreshOutboxReader freshOutboxReader;
    private final ZeroTrustActionRepository zeroTrustActionRepository;

    public OfficialVerificationCcsrExecutionService(
        SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
        PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
        OfficialVerificationAnalysisEventStore analysisEventStore,
        OfficialVerificationProbeClient probeClient,
        ObjectMapper objectMapper,
        OfficialVerificationFreshOutboxReader freshOutboxReader,
        ZeroTrustActionRepository zeroTrustActionRepository
) {
    super("CCSR", decisionOutboxRepository, promptAuditOutboxRepository, analysisEventStore, probeClient, objectMapper, CcsrRunRecord::runId, CcsrRunRecord::startedAt);
    this.freshOutboxReader = Objects.requireNonNull(freshOutboxReader, "freshOutboxReader");
    this.evidenceFactory = new OfficialVerificationCcsrEvidenceFactory();
    this.zeroTrustActionRepository = Objects.requireNonNull(
            zeroTrustActionRepository, "zeroTrustActionRepository");
}

@Override
public synchronized CcsrRunRecord executeRun(
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
    return "enterprise-ccsr-";
}

@Override
protected String resolveVerificationUserId(String userId, String requestId) {
    return OfficialVerificationRuntimeIsolationSupport.verificationSubjectId(userId, requestId);
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
    resetUserDecisionState(verificationUserId);
}

@Override
protected RequestMetricExecutionArtifacts refineArtifacts(String requestId, RequestMetricExecutionArtifacts artifacts) {
    SecurityDecisionForwardingOutboxRecord decisionOutbox = freshDecisionOutbox(requestId, artifacts.decisionOutbox());
    PromptContextAuditForwardingOutboxRecord promptOutbox = freshPromptAuditOutbox(requestId, artifacts.promptOutbox());
    return new RequestMetricExecutionArtifacts(
            artifacts.events(),
            decisionOutbox,
            promptOutbox,
            parseJson(decisionOutbox != null ? decisionOutbox.getPayloadJson() : null),
            parseJson(promptOutbox != null ? promptOutbox.getPayloadJson() : null)
    );
}

@Override
protected CcsrRunRecord buildRunRecord(RequestMetricExecutionState<EndpointDefinition> state) {
    return evidenceFactory.buildRunRecord(new OfficialVerificationCcsrEvidenceFactory.CcsrRunInput(
            state.endpoint(), state.userId(), state.requestId(), state.runOrdinal(), state.requestedRunCount(),
            state.rerun(), state.contaminationSeed(), state.baselineSeedRequested(), state.request(),
            state.startedAt(), state.completedAt(), state.processingTimeMs(), state.invocation(),
            state.artifacts().events(), state.artifacts().decisionOutbox(), state.artifacts().promptOutbox(),
            state.artifacts().decisionPayload(), state.artifacts().promptPayload()
    ));
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

private void resetUserDecisionState(String userId) {
        if (!StringUtils.hasText(userId)) {
            return;
        }
        zeroTrustActionRepository.removeAllUserData(userId.trim());
    }

    private SecurityDecisionForwardingOutboxRecord freshDecisionOutbox(
            String requestId,
            SecurityDecisionForwardingOutboxRecord fallback
    ) {
        return freshOutboxReader.findFreshDecisionOutbox(requestId).orElse(fallback);
    }

    private PromptContextAuditForwardingOutboxRecord freshPromptAuditOutbox(
            String requestId,
            PromptContextAuditForwardingOutboxRecord fallback
    ) {
        return freshOutboxReader.awaitPromptAuditOutbox(
                requestId,
                OfficialVerificationRuntimePollingSupport.DEFAULT_ARTIFACT_TIMEOUT,
                true
        ).orElse(fallback);
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
        headers.set(OfficialVerificationProbeHeaders.USER_AGENT, CCSR_BROWSER_USER_AGENT);
        headers.set(FORWARDED_FOR_HEADER, CCSR_CLIENT_IP);
        headers.set(DEVICE_ID_HEADER, CCSR_DEVICE_ID);
        headers.set(SIMULATED_USER_AGENT_HEADER, CCSR_BROWSER_USER_AGENT);
        headers.set(SIMULATED_USER_AGENT_LABEL_HEADER, CCSR_USER_AGENT_LABEL);
        headers.set(RESOURCE_ID_HEADER, StringUtils.hasText(resourceId) ? resourceId.trim() : "resource-001");
        headers.set(RUN_COUNT_HEADER, String.valueOf(requestedRunCount));
        headers.set(CONTAMINATION_SEED_HEADER, String.valueOf(contaminationSeed));
        headers.set(BASELINE_SEED_HEADER, String.valueOf(baselineSeedRequested));
        headers.set(USER_ID_HEADER, userId);
        if (request == null) {
            return;
        }
        copyHeader(request, headers, OfficialVerificationProbeHeaders.COOKIE);
        copyHeader(request, headers, OfficialVerificationProbeHeaders.AUTHORIZATION);
        copyHeader(request, headers, "X-XSRF-TOKEN");
        copyVerificationBridgeHeaders(request, headers);
    }

    record EndpointDefinition(String key, String label, String path, String resourceId) {
    }

    public record CcsrRunSummary(
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

    public record CcsrRunRecord(
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
            List<CcsrCheckResult> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<CcsrEventItem> events,
            Map<String, Object> rawEvidence) implements OfficialVerificationDetailedRunRecordView<CcsrCheckResult, CcsrEventItem> {

        public CcsrRunSummary toSummary() {
            return new CcsrRunSummary(
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

    public record CcsrCheckResult(
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) implements OfficialVerificationCheckResultView {
    }

    public record CcsrEventItem(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}








