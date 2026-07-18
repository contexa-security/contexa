package io.contexa.contexacore.verification.runtime.longhorizon;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractScenario;
import io.contexa.contexacore.verification.runtime.OfficialVerificationExecutionRequest;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Transactional(transactionManager = "contexaTransactionManager")
public class OfficialVerificationBmaExecutionService extends AbstractOfficialVerificationPromptLongHorizonExecutionService<OfficialVerificationBmaExecutionService.BmaRunRecord, OfficialVerificationBmaExecutionService.RoundSnapshot, OfficialVerificationBmaExecutionService.BmaCheckResult, OfficialVerificationBmaExecutionService.BmaEventItem> implements OfficialVerificationBmaExecutor {
    private final OfficialVerificationBmaEvidenceFactory evidenceFactory;
    private static final String SCENARIO_SELECTOR = OfficialVerificationPromptContractReplaySupport.EXTENDED_SCENARIO_SELECTOR;

    private static final String RESOURCE_ID_HEADER = "X-Contexa-Official-Verification-Resource-Id";
    private static final String RUN_COUNT_HEADER = "X-Contexa-Official-Verification-Requested-Run-Count";
    private static final String CONTAMINATION_SEED_HEADER = "X-Contexa-Official-Verification-Contamination-Seed";
    private static final String BASELINE_SEED_HEADER = "X-Contexa-Official-Verification-Baseline-Seed";
    private static final String USER_ID_HEADER = "X-Contexa-Official-Verification-User-Id";
    private static final String OBSERVED_AT_HEADER = "X-Contexa-Observed-At";
    private static final String ROUND_KEY_HEADER = "X-Contexa-Round-Key";
    private static final String BEHAVIOR_PHASE_HEADER = "X-Contexa-Behavior-Phase";
    private static final String SCENARIO_HEADER = "X-Contexa-Scenario";
    private static final String SIMULATED_USER_AGENT_HEADER = "X-Simulated-User-Agent";
    private static final String SIMULATED_USER_AGENT_LABEL_HEADER = "X-Simulated-User-Agent-Label";
    private static final String DEMO_PHASE_HEADER = "X-Contexa-Demo-Phase";
    private static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";
    private static final int MIN_PROGRESSION_ROUNDS = 3;
    public OfficialVerificationBmaExecutionService(
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            OfficialVerificationProbeClient probeClient,
            ObjectMapper objectMapper
    ) {
        super("BMA", decisionOutboxRepository, promptAuditOutboxRepository, analysisEventStore, probeClient, objectMapper, BmaRunRecord::runId, BmaRunRecord::startedAt);
        this.evidenceFactory = new OfficialVerificationBmaEvidenceFactory();
    }

    @Override
    public synchronized BmaRunRecord executeRun(
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
    public synchronized BmaRunRecord executeRun(
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
        return MIN_PROGRESSION_ROUNDS;
    }

    @Override
    protected OfficialVerificationContractMetadataSupport.ContractStatus buildContractStatus(int horizonRounds) {
        List<OfficialVerificationPromptContractScenario> contracts = OfficialVerificationPromptContractReplaySupport.resolveScenarios(SCENARIO_SELECTOR, horizonRounds);
        return OfficialVerificationContractMetadataSupport.promptScenarioAligned(
                "BMA",
                SCENARIO_SELECTOR,
                contracts.size(),
                horizonRounds,
                OfficialVerificationBmaExecutionService.class.getName(),
                "executeRun / buildChecks / buildRequestFacts / buildRawEvidence",
                "scenarioSelector"
        );
    }

    @Override
    protected List<OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan> buildRoundPlans(String userId, int horizonRounds) {
        List<OfficialVerificationPromptContractScenario> contracts = OfficialVerificationPromptContractReplaySupport.resolveScenarios(SCENARIO_SELECTOR, horizonRounds);
        return OfficialVerificationPromptContractReplaySupport.buildAlignedRoundPlans(
                contracts,
                userId,
                "enterprise-bma-run",
                OfficialVerificationPromptContractReplaySupport.STANDARD_ENDPOINT_KEYS
        );
    }

    @Override
    protected long interRoundDelayMs(OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan plan) {
        return OfficialVerificationLongHorizonExecutionSupport.interRoundDelayMs(plan.cooldownBeforeRoundMs());
    }

    @Override
    protected RoundSnapshot executeRound(
            OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan plan,
            int roundIndex,
            int horizonRounds,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request
    ) {
        String requestId = nextMetricRequestId("enterprise-bma-");
        Map<String, Object> invocation = invokeProbe(
                plan,
                requestId,
                horizonRounds,
                roundIndex + 1,
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
        List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events = artifactSnapshot.events();
        SecurityDecisionForwardingOutboxRecord decisionOutbox = artifactSnapshot.decisionOutbox();
        PromptContextAuditForwardingOutboxRecord promptOutbox = artifactSnapshot.promptOutbox();
        Map<String, Object> decisionPayload = parseJson(decisionOutbox != null ? decisionOutbox.getPayloadJson() : null);
        Map<String, Object> promptPayload = parseJson(promptOutbox != null ? promptOutbox.getPayloadJson() : null);
        return evidenceFactory.createRoundSnapshot(
                plan, roundIndex + 1, requestId, invocation, events,
                decisionOutbox, promptOutbox, decisionPayload, promptPayload
        );
    }
    @Override
    protected List<BmaEventItem> toEventItems(RoundSnapshot round) {
        return evidenceFactory.toEventItems(round);
    }

    @Override
    protected List<BmaCheckResult> buildChecks(List<RoundSnapshot> rounds) {
        return evidenceFactory.buildChecks(rounds);
    }

    @Override
    protected BmaRunRecord buildRunRecord(LongHorizonExecutionState<RoundSnapshot, BmaCheckResult, BmaEventItem> state) {
        return evidenceFactory.buildRunRecord(new OfficialVerificationBmaEvidenceFactory.BmaRunInput(
                state.runId(), state.runOrdinal(), state.userId(), state.requestedRunCount(), state.horizonRounds(),
                state.rerun(), state.contaminationSeed(), state.baselineSeedRequested(), state.request(),
                state.startedAt(), state.completedAt(), state.score(), state.passedChecks(), state.totalChecks(),
                state.processingTimeMs(), state.success(), state.checks(), state.rounds(), state.aggregatedEvents(),
                state.contractStatus()
        ));
    }
    private Map<String, Object> invokeProbe(
            OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan plan,
            String requestId,
            int requestedRunCount,
            int roundNumber,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request
    ) {
        return invokeProbeRequest(
                request,
                plan.endpoint().path(),
                headers -> forwardHeaders(
                        headers,
                        request,
                        plan,
                        requestId,
                        requestedRunCount,
                        roundNumber,
                        contaminationSeed,
                        baselineSeedRequested
                )
        );
    }

    private void forwardHeaders(
            OfficialVerificationProbeHeaders headers,
            OfficialVerificationExecutionRequest request,
            OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan plan,
            String requestId,
            int requestedRunCount,
            int roundNumber,
            boolean contaminationSeed,
            boolean baselineSeedRequested
    ) {
        headers.set("X-Request-ID", requestId);
        headers.set(RESOURCE_ID_HEADER, plan.endpoint().resourceId());
        headers.set(RUN_COUNT_HEADER, String.valueOf(requestedRunCount));
        headers.set(CONTAMINATION_SEED_HEADER, String.valueOf(contaminationSeed));
        headers.set(BASELINE_SEED_HEADER, String.valueOf(baselineSeedRequested));
        headers.set(OfficialVerificationProbeHeaders.USER_AGENT, plan.browserUserAgent());
        headers.set(FORWARDED_FOR_HEADER, plan.clientIp());
        headers.set(OBSERVED_AT_HEADER, plan.observedAt().toString());
        headers.set(SCENARIO_HEADER, plan.scenarioHeader());
        headers.set(DEMO_PHASE_HEADER, roundNumber == 1 ? "INITIAL" : "FOLLOW_UP");
        headers.set("X-Contexa-Demo-Run-Id", plan.benchmarkRunId());
        headers.set(ROUND_KEY_HEADER, plan.roundKey());
        headers.set(BEHAVIOR_PHASE_HEADER, plan.behaviorPhase());
        headers.set("X-Contexa-Expected-Action", plan.expectedActionHeader());
        headers.set("X-Device-Id", plan.deviceId());
        headers.set("X-Contexa-Official-Verification-Session-Id", plan.sessionId());
        headers.set(SIMULATED_USER_AGENT_HEADER, plan.browserUserAgent());
        headers.set(SIMULATED_USER_AGENT_LABEL_HEADER, plan.simulatedUserAgentLabel());
        headers.set(USER_ID_HEADER, plan.verificationUserId());
        headers.set("X-Contexa-Auth-Mode", "cookie");
        headers.set("X-Contexa-Token-Source", "none");
        headers.set("X-Contexa-Auth-Carrier", "SESSION_COOKIE_ONLY");
        headers.set("X-Contexa-Auth-Subject", plan.verificationUserId());
        headers.set("X-Contexa-Authorization-Present", "false");
        if (request == null) {
            return;
        }
        copyHeader(request, headers, OfficialVerificationProbeHeaders.COOKIE);
        copyHeader(request, headers, OfficialVerificationProbeHeaders.AUTHORIZATION);
        copyHeader(request, headers, "X-XSRF-TOKEN");
    }

    record RoundSnapshot(
            OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan plan,
            int roundNumber,
            String requestId,
            Map<String, Object> invocation,
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptOutbox,
            Map<String, Object> decisionPayload,
            Map<String, Object> promptPayload,
            Map<String, Object> decisionMetadata,
            Map<String, Object> decisionAttributes,
            Map<String, Object> promptTelemetry,
            int relatedDocumentsCount,
            int observationCount,
            boolean baselineContextPresent,
            boolean requestParityAligned,
            String workProfileSummary
    ) {
    }

    public record BmaRunSummary(
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

    public record BmaRunRecord(
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
            List<BmaCheckResult> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<BmaEventItem> events,
            Map<String, Object> rawEvidence) implements OfficialVerificationDetailedRunRecordView<BmaCheckResult, BmaEventItem> {

        public BmaRunSummary toSummary() {
            return new BmaRunSummary(
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

    public record BmaCheckResult(
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) implements OfficialVerificationCheckResultView {
    }

    public record BmaEventItem(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}





