package io.contexa.contexacore.verification.runtime.longhorizon;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Transactional(transactionManager = "contexaTransactionManager")
public class OfficialVerificationRpiExecutionService extends AbstractOfficialVerificationLongHorizonMetricExecutionService<OfficialVerificationRpiExecutionService.RpiRunRecord, ProgressionRoundPlan, RoundSnapshot, OfficialVerificationRpiExecutionService.RpiCheckResult, OfficialVerificationRpiExecutionService.RpiEventItem> implements OfficialVerificationRpiExecutor {

    private static final String RESOURCE_ID_HEADER = "X-Contexa-Official-Verification-Resource-Id";
    private static final String RUN_COUNT_HEADER = "X-Contexa-Official-Verification-Requested-Run-Count";
    private static final String CONTAMINATION_SEED_HEADER = "X-Contexa-Official-Verification-Contamination-Seed";
    private static final String BASELINE_SEED_HEADER = "X-Contexa-Official-Verification-Baseline-Seed";
    private static final String USER_ID_HEADER = "X-Contexa-Official-Verification-User-Id";
    private static final String SESSION_ID_HEADER = "X-Contexa-Official-Verification-Session-Id";
    private static final String OBSERVED_AT_HEADER = "X-Contexa-Observed-At";
    private static final String ROUND_KEY_HEADER = "X-Contexa-Round-Key";
    private static final String BEHAVIOR_PHASE_HEADER = "X-Contexa-Behavior-Phase";
    private static final String SCENARIO_HEADER = "X-Contexa-Scenario";
    private static final String EXPECTED_ACTION_HEADER = "X-Contexa-Expected-Action";
    private static final String DEMO_RUN_ID_HEADER = "X-Contexa-Demo-Run-Id";
    private static final String SIMULATED_USER_AGENT_HEADER = "X-Simulated-User-Agent";
    private static final String SIMULATED_USER_AGENT_LABEL_HEADER = "X-Simulated-User-Agent-Label";
    private static final String DEMO_PHASE_HEADER = "X-Contexa-Demo-Phase";
    private static final String ANOMALY_SIGNAL_HEADER = "X-Contexa-Anomaly-Signal";
    private static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";
    private static final String DEVICE_ID_HEADER = "X-Device-Id";
    private static final String AUTH_MODE_HEADER = "X-Contexa-Auth-Mode";
    private static final String TOKEN_SOURCE_HEADER = "X-Contexa-Token-Source";
    private static final String AUTH_CARRIER_HEADER = "X-Contexa-Auth-Carrier";
    private static final String AUTH_SUBJECT_HEADER = "X-Contexa-Auth-Subject";
    private static final String AUTHORIZATION_PRESENT_HEADER = "X-Contexa-Authorization-Present";
    private static final Duration REPOSITORY_DECISION_WAIT_TIMEOUT = Duration.ofSeconds(5);
    private final ZeroTrustActionRepository zeroTrustActionRepository;
    private final OfficialVerificationRpiEvidenceFactory evidenceFactory;
    private final OfficialVerificationRpiRoundPlanFactory roundPlanFactory;

    public OfficialVerificationRpiExecutionService(
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            OfficialVerificationProbeClient probeClient,
            ObjectMapper objectMapper,
            ZeroTrustActionRepository zeroTrustActionRepository
    ) {
        super(
                "RPI",
                decisionOutboxRepository,
                promptAuditOutboxRepository,
                analysisEventStore,
                probeClient,
                objectMapper,
                RpiRunRecord::runId,
                RpiRunRecord::startedAt
        );
        this.zeroTrustActionRepository = Objects.requireNonNull(
                zeroTrustActionRepository, "zeroTrustActionRepository");
        this.evidenceFactory = new OfficialVerificationRpiEvidenceFactory();
        this.roundPlanFactory = new OfficialVerificationRpiRoundPlanFactory();
    }

    @Override
    public synchronized RpiRunRecord executeRun(
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
        return executeLongHorizonRunTemplate(
                userId,
                endpointKey,
                resourceId,
                requestPath,
                requestedRunCount,
                rerun,
                contaminationSeed,
                baselineSeedRequested,
                request,
                UUID.randomUUID().toString(),
                nextRunOrdinal(userId)
        );
    }

    @Override
    public synchronized RpiRunRecord executeRun(
            String userId,
            String endpointKey,
            String resourceId,
            String requestPath,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request,
            String runId,
            int runOrdinal
    ) {
        return executeLongHorizonRunTemplate(
                userId,
                endpointKey,
                resourceId,
                requestPath,
                requestedRunCount,
                rerun,
                contaminationSeed,
                baselineSeedRequested,
                request,
                runId,
                runOrdinal
        );
    }

    @Override
    protected int minimumRounds() {
        return roundPlanFactory.minimumRounds();
    }

    @Override
    protected OfficialVerificationContractMetadataSupport.ContractStatus buildContractStatus(
            String endpointKey,
            String resourceId,
            String requestPath,
            int horizonRounds
    ) {
        return roundPlanFactory.contractStatus(horizonRounds);
    }

    @Override
    protected List<ProgressionRoundPlan> buildRoundPlans(
            String userId,
            String endpointKey,
            String resourceId,
            String requestPath,
            int horizonRounds
    ) {
        return roundPlanFactory.buildRoundPlans(userId, horizonRounds);
    }
    @Override
    protected long interRoundDelayMs(ProgressionRoundPlan plan) {
        return plan.cooldownBeforeRoundMs();
    }

    @Override
    protected RoundSnapshot executeRound(
            ProgressionRoundPlan plan,
            int roundIndex,
            int horizonRounds,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request
    ) {
        String requestId = nextMetricRequestId("enterprise-rpi-");
        Map<String, Object> invocation = invokeProbe(
                plan,
                requestId,
                horizonRounds,
                contaminationSeed,
                baselineSeedRequested,
                request
        );
        OfficialVerificationRuntimePollingSupport.ArtifactSnapshot artifactSnapshot = OfficialVerificationRuntimePollingSupport.awaitArtifacts(
                requestId,
                OfficialVerificationRuntimePollingSupport.DEFAULT_ARTIFACT_TIMEOUT,
                analysisEventStore,
                decisionOutboxRepository,
                promptAuditOutboxRepository,
                OfficialVerificationRuntimePollingSupport.ArtifactWaitMode.REQUIRE_TERMINAL);
        if (OfficialVerificationRuntimePollingSupport.awaitRepositoryDecisionStateBestEffort(
                plan.verificationUserId(),
                requestId,
                REPOSITORY_DECISION_WAIT_TIMEOUT,
                zeroTrustActionRepository)) {
            artifactSnapshot = refreshArtifacts(requestId, artifactSnapshot);
        }
        if (!hasTerminalEvent(artifactSnapshot.events())) {
            sleep(nonTerminalSettleDelayMs(plan.cooldownBeforeRoundMs()));
            artifactSnapshot = refreshArtifacts(requestId, artifactSnapshot);
        }
        List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events = artifactSnapshot.events();
        SecurityDecisionForwardingOutboxRecord decisionOutbox = artifactSnapshot.decisionOutbox();
        PromptContextAuditForwardingOutboxRecord promptOutbox = artifactSnapshot.promptOutbox();
        Map<String, Object> decisionPayload = parseJson(decisionOutbox != null ? decisionOutbox.getPayloadJson() : null);
        Map<String, Object> promptPayload = parseJson(promptOutbox != null ? promptOutbox.getPayloadJson() : null);
        return evidenceFactory.createRoundSnapshot(
                plan,
                roundIndex + 1,
                requestId,
                invocation,
                events,
                decisionOutbox,
                promptOutbox,
                decisionPayload,
                promptPayload
        );
    }
    @Override
    protected List<RpiEventItem> toEventItems(RoundSnapshot round) {
        return evidenceFactory.toEventItems(round);
    }
    @Override
    protected RpiRunRecord buildRunRecord(LongHorizonExecutionState<RoundSnapshot, RpiCheckResult, RpiEventItem> state) {
        RequestedTarget requestedTarget = roundPlanFactory.resolveRequestedTarget(
                state.endpointKey(), state.resourceId(), state.requestPath()
        );
        return evidenceFactory.buildRunRecord(new OfficialVerificationRpiEvidenceFactory.RpiRunInput(
                state.runId(), state.runOrdinal(), requestedTarget, state.userId(), state.requestedRunCount(),
                state.horizonRounds(), state.rerun(), state.contaminationSeed(), state.baselineSeedRequested(),
                state.request(), state.startedAt(), state.completedAt(), state.score(), state.passedChecks(),
                state.totalChecks(), state.processingTimeMs(), state.success(), state.checks(), state.rounds(),
                state.aggregatedEvents(), state.contractStatus()
        ));
    }
    private Map<String, Object> invokeProbe(
            ProgressionRoundPlan plan,
            String requestId,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request
    ) {
        return invokeProbeRequest(
                request,
                plan.requestPath(),
                headers -> forwardHeaders(
                        headers,
                        request,
                        plan,
                        requestId,
                        requestedRunCount,
                        contaminationSeed,
                        baselineSeedRequested
                )
        );
    }

    private void forwardHeaders(
            OfficialVerificationProbeHeaders headers,
            OfficialVerificationExecutionRequest request,
            ProgressionRoundPlan plan,
            String requestId,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested
    ) {
        headers.set("X-Request-ID", requestId);
        headers.set(RESOURCE_ID_HEADER, plan.resourceId());
        headers.set(RUN_COUNT_HEADER, String.valueOf(requestedRunCount));
        headers.set(CONTAMINATION_SEED_HEADER, String.valueOf(contaminationSeed));
        headers.set(BASELINE_SEED_HEADER, String.valueOf(baselineSeedRequested));
        headers.set(OfficialVerificationProbeHeaders.ACCEPT, "application/json");
        headers.set(OfficialVerificationProbeHeaders.USER_AGENT, plan.browserUserAgent());
        headers.set(FORWARDED_FOR_HEADER, plan.clientIp());
        headers.set(OBSERVED_AT_HEADER, plan.observedAt().toString());
        headers.set(SCENARIO_HEADER, plan.scenarioHeader());
        headers.set(EXPECTED_ACTION_HEADER, plan.expectedActionHeader());
        headers.set(DEMO_RUN_ID_HEADER, plan.benchmarkRunId());
        headers.set(DEMO_PHASE_HEADER, plan.roundNumber() == 1 ? "INITIAL" : "FOLLOW_UP");
        headers.set(ROUND_KEY_HEADER, plan.roundKey());
        headers.set(BEHAVIOR_PHASE_HEADER, plan.behaviorPhase());
        headers.set(ANOMALY_SIGNAL_HEADER, plan.anomalySignal());
        headers.set(SIMULATED_USER_AGENT_HEADER, plan.browserUserAgent());
        headers.set(SIMULATED_USER_AGENT_LABEL_HEADER, plan.simulatedUserAgentLabel());
        headers.set(DEVICE_ID_HEADER, plan.deviceId());
        headers.set(USER_ID_HEADER, plan.verificationUserId());
        headers.set(SESSION_ID_HEADER, plan.sessionId());
        headers.set(AUTH_MODE_HEADER, "cookie");
        headers.set(TOKEN_SOURCE_HEADER, "none");
        headers.set(AUTH_CARRIER_HEADER, "SESSION_COOKIE_ONLY");
        headers.set(AUTH_SUBJECT_HEADER, plan.verificationUserId());
        headers.set(AUTHORIZATION_PRESENT_HEADER, "false");
        if (request == null) {
            return;
        }
        copyHeader(request, headers, OfficialVerificationProbeHeaders.COOKIE);
        copyHeader(request, headers, OfficialVerificationProbeHeaders.AUTHORIZATION);
        copyHeader(request, headers, "X-XSRF-TOKEN");
    }

    @Override
    protected List<RpiCheckResult> buildChecks(List<RoundSnapshot> rounds) {
        return evidenceFactory.buildChecks(rounds);
    }
    private OfficialVerificationRuntimePollingSupport.ArtifactSnapshot refreshArtifacts(
            String requestId,
            OfficialVerificationRuntimePollingSupport.ArtifactSnapshot currentSnapshot
    ) {
        List<OfficialVerificationAnalysisEventStore.AnalysisEvent> refreshedEvents = analysisEventStore.findByRequestId(requestId);
        SecurityDecisionForwardingOutboxRecord refreshedDecisionOutbox =
                decisionOutboxRepository.findTopByCorrelationIdOrderByIdDesc(requestId).orElse(currentSnapshot.decisionOutbox());
        PromptContextAuditForwardingOutboxRecord refreshedPromptOutbox =
                promptAuditOutboxRepository.findTopByCorrelationIdOrderByIdDesc(requestId).orElse(currentSnapshot.promptOutbox());
        return new OfficialVerificationRuntimePollingSupport.ArtifactSnapshot(
                refreshedEvents,
                refreshedDecisionOutbox,
                refreshedPromptOutbox
        );
    }

    private boolean hasTerminalEvent(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events) {
        return events.stream().anyMatch(event ->
                "DECISION_APPLIED".equalsIgnoreCase(event.type()) || "ERROR".equalsIgnoreCase(event.type()));
    }

    private long nonTerminalSettleDelayMs(long configuredCooldownBeforeRoundMs) {
        return Math.max(configuredCooldownBeforeRoundMs, 4_000L);
    }

    public record RpiRunSummary(
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

    public record RpiRunRecord(
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
            List<RpiCheckResult> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<RpiEventItem> events,
            Map<String, Object> rawEvidence) implements OfficialVerificationDetailedRunRecordView<RpiCheckResult, RpiEventItem> {

        public RpiRunSummary toSummary() {
            return new RpiRunSummary(
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

    public record RpiCheckResult(
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) implements OfficialVerificationCheckResultView {
    }

    public record RpiEventItem(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}










