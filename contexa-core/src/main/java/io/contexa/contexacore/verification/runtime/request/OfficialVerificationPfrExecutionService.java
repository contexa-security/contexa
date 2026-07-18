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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

@Transactional(transactionManager = "contexaTransactionManager")
public class OfficialVerificationPfrExecutionService extends AbstractOfficialVerificationRequestMetricExecutionService<OfficialVerificationPfrExecutionService.PfrRunRecord, OfficialVerificationPfrExecutionService.EndpointDefinition> implements OfficialVerificationPfrExecutor {

    private final OfficialVerificationPfrEvidenceFactory evidenceFactory = new OfficialVerificationPfrEvidenceFactory();

    static final OfficialVerificationContractMetadataSupport.ContractStatus CONTRACT_STATUS =
            OfficialVerificationContractMetadataSupport.aligned(
                    "PFR",
                    OfficialVerificationPfrExecutionService.class.getName(),
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
    public OfficialVerificationPfrExecutionService(
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            OfficialVerificationProbeClient probeClient,
            ObjectMapper objectMapper
    ) {
        super("PFR", decisionOutboxRepository, promptAuditOutboxRepository, analysisEventStore, probeClient, objectMapper, PfrRunRecord::runId, PfrRunRecord::startedAt);
    }

    @Override
    public synchronized PfrRunRecord executeRun(
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
        return "enterprise-pfr-";
    }

    @Override
    protected PfrRunRecord buildRunRecord(RequestMetricExecutionState<EndpointDefinition> state) {
        Map<String, Object> decisionMetadata = evidenceFactory.firstMetadata(state.artifacts().events(), "DECISION_APPLIED");
        Map<String, Object> decisionAttributes = evidenceFactory.map(state.artifacts().decisionPayload().get("attributes"));
        Map<String, Object> promptTelemetry = OfficialVerificationRuntimeEvidenceSupport.resolvePromptTelemetry(
                decisionMetadata,
                decisionAttributes,
                state.artifacts().decisionPayload(),
                state.artifacts().promptPayload()
        );
        List<PfrCheckResult> checks = evidenceFactory.buildChecks(
                decisionMetadata,
                promptTelemetry,
                state.artifacts().decisionPayload(),
                decisionAttributes,
                state.artifacts().promptPayload()
        );
        int totalChecks = checks.size();
        int passedChecks = (int) checks.stream().filter(PfrCheckResult::pass).count();
        double score = totalChecks == 0 ? 0.0d : (passedChecks * 100.0d) / totalChecks;
        PfrRunAssembly assembly = new PfrRunAssembly(
                decisionMetadata, decisionAttributes, promptTelemetry, checks, totalChecks, passedChecks, score);
        return assembleRunRecord(state, assembly);    }
    private PfrRunRecord assembleRunRecord(RequestMetricExecutionState<EndpointDefinition> state, PfrRunAssembly assembly) {
        return new PfrRunRecord(
                UUID.randomUUID().toString(),
                state.runOrdinal(),
                state.endpoint().key(),
                state.endpoint().label(),
                state.requestId(),
                assembly.score(),
                assembly.passedChecks(),
                assembly.totalChecks(),
                state.processingTimeMs(),
                assembly.score() >= 95.0d ? "Threshold passed" : "Threshold failed",
                assembly.score() >= 95.0d ? "success" : "error",
                evidenceFactory.buildMessage(assembly.score()),
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
                evidenceFactory.buildPfrEventFacts(state.artifacts().events(), assembly.decisionMetadata(), assembly.promptTelemetry()),
                evidenceFactory.buildPfrPromptFacts(assembly.promptTelemetry(), state.artifacts().decisionPayload(), state.artifacts().promptPayload()),
                evidenceFactory.buildPfrAnalysisFacts(assembly.promptTelemetry(), state.artifacts().decisionPayload(), state.artifacts().decisionOutbox(), state.artifacts().promptPayload()),
                state.artifacts().events().stream().map(evidenceFactory::toPfrEventItem).toList(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                        evidenceFactory.buildPfrRawEvidence(
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
                                assembly.decisionAttributes()
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
    private record PfrRunAssembly(
            Map<String, Object> decisionMetadata,
            Map<String, Object> decisionAttributes,
            Map<String, Object> promptTelemetry,
            List<PfrCheckResult> checks,
            int totalChecks,
            int passedChecks,
            double score) {
    }
    record EndpointDefinition(String key, String label, String path, String resourceId) {
    }

    public record PfrRunSummary(
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

    public record PfrRunRecord(
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
            List<PfrCheckResult> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<PfrEventItem> events,
            Map<String, Object> rawEvidence) implements OfficialVerificationDetailedRunRecordView<PfrCheckResult, PfrEventItem> {

        public PfrRunSummary toSummary() {
            return new PfrRunSummary(
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

    public record PfrCheckResult(
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) implements OfficialVerificationCheckResultView {
    }

    public record PfrEventItem(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}





