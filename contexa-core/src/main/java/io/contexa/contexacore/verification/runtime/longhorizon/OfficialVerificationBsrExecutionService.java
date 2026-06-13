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
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
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
public class OfficialVerificationBsrExecutionService extends AbstractOfficialVerificationPromptLongHorizonExecutionService<OfficialVerificationBsrExecutionService.BsrRunRecord, OfficialVerificationBsrExecutionService.RoundSnapshot, OfficialVerificationBsrExecutionService.BsrCheckResult, OfficialVerificationBsrExecutionService.BsrEventItem> implements OfficialVerificationBsrExecutor {
    private static final String SCENARIO_SELECTOR = OfficialVerificationPromptContractReplaySupport.EXTENDED_SCENARIO_SELECTOR;

    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE = new ParameterizedTypeReference<>() {
    };
    private static final DateTimeFormatter KOREA_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withLocale(Locale.KOREA)
            .withZone(ZoneId.of("Asia/Seoul"));
    private static final String RESOURCE_ID_HEADER = "X-Contexa-Official-Verification-Resource-Id";
    private static final String RUN_COUNT_HEADER = "X-Contexa-Official-Verification-Requested-Run-Count";
    private static final String CONTAMINATION_SEED_HEADER = "X-Contexa-Official-Verification-Contamination-Seed";
    private static final String BASELINE_SEED_HEADER = "X-Contexa-Official-Verification-Baseline-Seed";
    private static final String USER_ID_HEADER = "X-Contexa-Official-Verification-User-Id";
    private static final String OBSERVED_AT_HEADER = "X-Contexa-Observed-At";
    private static final String ROUND_KEY_HEADER = "X-Contexa-Round-Key";
    private static final String BEHAVIOR_PHASE_HEADER = "X-Contexa-Behavior-Phase";
    private static final String ANOMALY_SIGNAL_HEADER = "X-Contexa-Anomaly-Signal";
    private static final String SIMULATED_USER_AGENT_HEADER = "X-Simulated-User-Agent";
    private static final String SIMULATED_USER_AGENT_LABEL_HEADER = "X-Simulated-User-Agent-Label";
    private static final String DEMO_PHASE_HEADER = "X-Contexa-Demo-Phase";
    private static final String SCENARIO_HEADER = "X-Contexa-Scenario";
    private static final int MIN_BEHAVIORAL_ROUNDS = 3;
    private static final Pattern OBSERVATIONS_PATTERN = Pattern.compile("(?i)\\bObservations\\s+(\\d+)\\b");
    private static final Pattern OBSERVATIONS_KEY_VALUE_PATTERN = Pattern.compile("(?i)\\bobservations\\s*[=:]\\s*(\\d+)\\b");
    private static final Pattern OBSERVATION_COUNT_PATTERN = Pattern.compile("(?i)\\bobservationCount\\s*[=:]\\s*(\\d+)\\b");
    private static final String STABLE_CLIENT_IP = "198.51.100.24";
    private static final String STABLE_BROWSER_USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    private static final String STABLE_USER_AGENT_LABEL = "Chrome on Windows 10";
    private static final Duration ROUND_STEP = Duration.ofMinutes(12);    public OfficialVerificationBsrExecutionService(
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            WebClient.Builder webClientBuilder,
            ObjectMapper objectMapper
    ) {
        super("BSR", decisionOutboxRepository, promptAuditOutboxRepository, analysisEventStore, webClientBuilder, objectMapper, BsrRunRecord::runId, BsrRunRecord::startedAt);
    }

    @Override
    public synchronized BsrRunRecord executeRun(
            String userId,
            String endpointKey,
            String resourceId,
            String requestPath,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            HttpServletRequest request
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
    public synchronized BsrRunRecord executeRun(
            String userId,
            String endpointKey,
            String resourceId,
            String requestPath,
            int requestedRunCount,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            HttpServletRequest request,
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
        return MIN_BEHAVIORAL_ROUNDS;
    }

    @Override
    protected OfficialVerificationContractMetadataSupport.ContractStatus buildContractStatus(int horizonRounds) {
        List<OfficialVerificationPromptContractScenario> contracts = OfficialVerificationPromptContractReplaySupport.resolveScenarios(SCENARIO_SELECTOR, horizonRounds);
        return OfficialVerificationContractMetadataSupport.promptScenarioAligned(
                "BSR",
                SCENARIO_SELECTOR,
                contracts.size(),
                horizonRounds,
                OfficialVerificationBsrExecutionService.class.getName(),
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
                "enterprise-bsr-run",
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
            HttpServletRequest request
    ) {
        String requestId = nextMetricRequestId("enterprise-bsr-");
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
        List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events = artifactSnapshot.events();
        SecurityDecisionForwardingOutboxRecord decisionOutbox = artifactSnapshot.decisionOutbox();
        PromptContextAuditForwardingOutboxRecord promptOutbox = artifactSnapshot.promptOutbox();
        Map<String, Object> decisionPayload = parseJson(decisionOutbox != null ? decisionOutbox.getPayloadJson() : null);
        Map<String, Object> promptPayload = parseJson(promptOutbox != null ? promptOutbox.getPayloadJson() : null);
        Map<String, Object> decisionMetadata = firstMetadata(events, "DECISION_APPLIED");
        Map<String, Object> decisionAttributes = map(decisionPayload.get("attributes"));
        Map<String, Object> promptTelemetry = OfficialVerificationRuntimeEvidenceSupport.resolvePromptTelemetry(
                decisionMetadata,
                decisionAttributes,
                decisionPayload,
                promptPayload
        );
        String workProfileSummary = workProfileSummary(decisionPayload, decisionAttributes);
        int relatedDocumentsCount = relatedDocumentsCount(promptPayload, decisionMetadata);
        int observationCount = observationCount(decisionPayload, decisionAttributes, decisionMetadata, workProfileSummary);
        boolean baselineContextPresent = baselineContextPresent(decisionPayload, decisionAttributes, decisionMetadata, workProfileSummary);
        boolean requestParityAligned =
                sameValue(requestId, text(invocation, "requestId"))
                        && sameValue(requestId, text(decisionPayload, "correlationId"))
                        && sameValue(requestId, text(promptPayload, "correlationId"));

        return new RoundSnapshot(
                plan,
                roundIndex + 1,
                requestId,
                invocation,
                events,
                decisionOutbox,
                promptOutbox,
                decisionPayload,
                promptPayload,
                decisionMetadata,
                decisionAttributes,
                promptTelemetry,
                relatedDocumentsCount,
                observationCount,
                baselineContextPresent,
                requestParityAligned,
                workProfileSummary
        );
    }

    @Override
    protected List<BsrEventItem> toEventItems(RoundSnapshot round) {
        return round.events().stream().map(this::toBsrEventItem).toList();
    }

    @Override
    protected List<BsrCheckResult> buildChecks(List<RoundSnapshot> rounds) {
        return buildChecksInternal(rounds);
    }

    @Override
    protected BsrRunRecord buildRunRecord(LongHorizonExecutionState<RoundSnapshot, BsrCheckResult, BsrEventItem> state) {
        RoundSnapshot lastRound = state.rounds().get(state.rounds().size() - 1);
        return new BsrRunRecord(
                state.runId(),
                state.runOrdinal(),
                lastRound.plan().endpoint().key(),
                lastRound.plan().endpoint().label(),
                lastRound.requestId(),
                state.score(),
                state.passedChecks(),
                state.totalChecks(),
                state.processingTimeMs(),
                state.success() ? "Threshold passed" : "Threshold failed",
                state.success() ? "success" : "error",
                buildMessage(state.score(), state.rounds()),
                KOREA_TIME.format(state.startedAt()),
                KOREA_TIME.format(state.completedAt()),
                state.checks(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRequestFacts(
                        buildRequestFacts(state.userId(), state.requestedRunCount(), state.horizonRounds(), state.rerun(), state.contaminationSeed(), state.baselineSeedRequested(), state.rounds(), state.contractStatus()),
                        state.request()
                ),
                buildEventFacts(state.rounds()),
                buildPromptFacts(state.rounds()),
                buildAnalysisFacts(state.rounds()),
                state.aggregatedEvents(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                        buildRawEvidence(state.userId(), state.requestedRunCount(), state.horizonRounds(), state.rerun(), state.contaminationSeed(), state.baselineSeedRequested(), state.rounds(), state.contractStatus()),
                        state.request()
                )
        );
    }

    private Map<String, Object> invokeProbe(
            OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan plan,
            String requestId,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            HttpServletRequest request
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
                        contaminationSeed,
                        baselineSeedRequested
                )
        );
    }

    private void forwardHeaders(
            HttpHeaders headers,
            HttpServletRequest request,
            OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan plan,
            String requestId,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested
    ) {
        headers.set("X-Request-ID", requestId);
        headers.set(RESOURCE_ID_HEADER, plan.endpoint().resourceId());
        headers.set(RUN_COUNT_HEADER, String.valueOf(requestedRunCount));
        headers.set(CONTAMINATION_SEED_HEADER, String.valueOf(contaminationSeed));
        headers.set(BASELINE_SEED_HEADER, String.valueOf(baselineSeedRequested));
        headers.set(USER_ID_HEADER, plan.verificationUserId());
        headers.set(HttpHeaders.USER_AGENT, plan.browserUserAgent());
        headers.set(HttpHeaders.ACCEPT, "application/json");
        headers.set("X-Forwarded-For", plan.clientIp());
        headers.set(OBSERVED_AT_HEADER, plan.observedAt().toString());
        headers.set(ROUND_KEY_HEADER, plan.roundKey());
        headers.set(BEHAVIOR_PHASE_HEADER, plan.behaviorPhase());
        headers.set(ANOMALY_SIGNAL_HEADER, plan.anomalySignal());
        headers.set(SIMULATED_USER_AGENT_HEADER, plan.browserUserAgent());
        headers.set(SIMULATED_USER_AGENT_LABEL_HEADER, plan.simulatedUserAgentLabel());
        headers.set(DEMO_PHASE_HEADER, plan.roundNumber() == 1 ? "INITIAL" : "FOLLOW_UP");
        headers.set("X-Contexa-Demo-Run-Id", plan.benchmarkRunId());
        headers.set(SCENARIO_HEADER, plan.scenarioHeader());
        headers.set("X-Contexa-Expected-Action", plan.expectedActionHeader());
        headers.set("X-Device-Id", plan.deviceId());
        headers.set("X-Contexa-Official-Verification-Session-Id", plan.sessionId());
        headers.set("X-Contexa-Auth-Mode", "cookie");
        headers.set("X-Contexa-Token-Source", "none");
        headers.set("X-Contexa-Auth-Carrier", "SESSION_COOKIE_ONLY");
        headers.set("X-Contexa-Auth-Subject", plan.verificationUserId());
        headers.set("X-Contexa-Authorization-Present", "false");
        if (request == null) {
            return;
        }
        copyHeader(request, headers, HttpHeaders.COOKIE);
        copyHeader(request, headers, HttpHeaders.AUTHORIZATION);
        copyHeader(request, headers, "X-XSRF-TOKEN");
    }

    private List<BsrCheckResult> buildChecksInternal(List<RoundSnapshot> rounds) {
        List<BsrCheckResult> checks = new ArrayList<>();
        if (rounds.size() < 3) {
            checks.add(check("behavioral surprise rounds are captured", ">= 3", String.valueOf(rounds.size()), false, "rounds"));
            return List.copyOf(checks);
        }

        for (int index = 1; index < rounds.size(); index++) {
            RoundSnapshot previous = rounds.get(index - 1);
            RoundSnapshot current = rounds.get(index);
            if (!sameValue(previous.plan().scenarioKey(), current.plan().scenarioKey())) {
                continue;
            }
            boolean anomalyRound = "ANOMALY".equalsIgnoreCase(current.plan().behaviorPhase());
            boolean recoveryRound = "RECOVERY".equalsIgnoreCase(current.plan().behaviorPhase())
                    || current.plan().semanticMarkers().contains("EXPECT_RECOVERY_AFTER_ANOMALY");
            if (!anomalyRound && !recoveryRound) {
                continue;
            }
            int expectedDocs = Math.min(index, 12);
            checks.add(check(
                    "round " + (index + 1) + " behavior phase is preserved",
                    current.plan().behaviorPhase(),
                    value(behaviorPhase(current)),
                    sameValue(current.plan().behaviorPhase(), behaviorPhase(current)),
                    "rounds[" + index + "].decisionMetadata.behaviorPhase"
            ));
            checks.add(check(
                    "round " + (index + 1) + " anomaly signal is preserved",
                    current.plan().anomalySignal(),
                    value(anomalySignal(current)),
                    sameValue(current.plan().anomalySignal(), anomalySignal(current)),
                    "rounds[" + index + "].decisionMetadata.anomalySignal"
            ));
            checks.add(check(
                    "round " + (index + 1) + " current request path is preserved",
                    current.plan().endpoint().path(),
                    value(requestPath(current)),
                    sameValue(current.plan().endpoint().path(), requestPath(current)),
                    "rounds[" + index + "].decisionMetadata.requestPath"
            ));
            checks.add(check(
                    "round " + (index + 1) + " previous path is referenced",
                    previous.plan().endpoint().path(),
                    value(previousPath(current)),
                    sameValue(previous.plan().endpoint().path(), previousPath(current)),
                    "rounds[" + index + "].decisionMetadata.previousPath"
            ));
            checks.add(check(
                    "round " + (index + 1) + " sequence or cadence evidence is preserved",
                    current.plan().anomalySignal(),
                    signalEvidenceSummary(current),
                    signalSpecificEvidencePresent(current),
                    "rounds[" + index + "].decisionMetadata"
            ));
            checks.add(check(
                    "round " + (index + 1) + " session history support is present",
                    "relatedDocs>=" + expectedDocs + " or observed work pattern",
                    sessionHistorySupportSummary(current),
                    hasSessionHistorySupport(current, index),
                    "rounds[" + index + "].decisionPayload.workProfileSummary/promptAuditOutbox.payload.contexts"
            ));
            if (recoveryRound) {
                checks.add(check(
                        "round " + (index + 1) + " recovery keeps observed work pattern context",
                        "true",
                        Boolean.toString(hasSessionHistorySupport(current, index)),
                        hasSessionHistorySupport(current, index),
                        "rounds[" + index + "].decisionPayload.workProfileSummary/promptAuditOutbox.payload.contexts"
                ));
            }
        }
        return List.copyOf(checks);
    }

    private BsrCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new BsrCheckResult(label, value(expected), value(actual), pass, source);
    }

    private Map<String, String> buildRequestFacts(
            String userId,
            int requestedRunCount,
            int horizonRounds,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            List<RoundSnapshot> rounds,
            OfficialVerificationContractMetadataSupport.ContractStatus contractStatus
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("verificationUser", value(userId));
        facts.put("anchorEndpoint", rounds.get(0).plan().endpoint().label());
        facts.put("resourceId", rounds.get(0).plan().endpoint().resourceId());
        facts.put("requestedRunCount", String.valueOf(requestedRunCount));
        facts.put("behavioralRoundCount", String.valueOf(horizonRounds));
        facts.put("firstRequestId", value(rounds.get(0).requestId()));
        facts.put("finalRequestId", value(rounds.get(rounds.size() - 1).requestId()));
        facts.put("rerun", rerun ? "yes" : "no");
        facts.put("contaminationSeed", contaminationSeed ? "enabled" : "disabled");
        facts.put("baselineSeedRequested", baselineSeedRequested ? "enabled" : "disabled");
        facts.put("coarseSignalsStable", Boolean.toString(coarseSignalsStable(rounds)));
        facts.put("scenarioSelector", SCENARIO_SELECTOR);
        facts.put("scenarioCount", String.valueOf(rounds.stream().map(round -> round.plan().scenarioKey()).distinct().count()));
        return OfficialVerificationContractMetadataSupport.withRequestFacts(facts, contractStatus);
    }

    private Map<String, String> buildEventFacts(List<RoundSnapshot> rounds) {
        Map<String, String> facts = new LinkedHashMap<>();
        int totalEventCount = rounds.stream().mapToInt(round -> round.events().size()).sum();
        int previousPathRoundCount = (int) rounds.stream().skip(1).filter(round -> StringUtils.hasText(previousPath(round))).count();
        facts.put("roundCount", String.valueOf(rounds.size()));
        facts.put("totalEventCount", String.valueOf(totalEventCount));
        facts.put("stableClientIp", Boolean.toString(sameClientIpAcrossRounds(rounds)));
        facts.put("stableUserAgent", Boolean.toString(sameUserAgentAcrossRounds(rounds)));
        facts.put("firstRequestId", value(rounds.get(0).requestId()));
        facts.put("finalRequestId", value(rounds.get(rounds.size() - 1).requestId()));
        facts.put("previousPathRoundCount", String.valueOf(previousPathRoundCount));
        facts.put("finalRequestPath", value(requestPath(rounds.get(rounds.size() - 1))));
        return facts;
    }

    private Map<String, String> buildPromptFacts(List<RoundSnapshot> rounds) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("round2RelatedDocuments", rounds.size() > 1 ? String.valueOf(rounds.get(1).relatedDocumentsCount()) : "n/a");
        facts.put("round3RelatedDocuments", rounds.size() > 2 ? String.valueOf(rounds.get(2).relatedDocumentsCount()) : "n/a");
        facts.put("baselineContextRoundCount", String.valueOf(rounds.stream().filter(RoundSnapshot::baselineContextPresent).count()));
        facts.put("previousPathRoundCount", String.valueOf(rounds.stream().skip(1).filter(round -> StringUtils.hasText(previousPath(round))).count()));
        facts.put("finalRelatedDocumentsCount", String.valueOf(rounds.get(rounds.size() - 1).relatedDocumentsCount()));
        return facts;
    }

    private Map<String, String> buildAnalysisFacts(List<RoundSnapshot> rounds) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("behaviorPhaseChain", phaseChain(rounds));
        facts.put("anomalySignalChain", signalChain(rounds));
        facts.put("round1ObservationCount", String.valueOf(rounds.get(0).observationCount()));
        facts.put("finalObservationCount", String.valueOf(rounds.get(rounds.size() - 1).observationCount()));
        facts.put("finalWorkProfileSummary", value(rounds.get(rounds.size() - 1).workProfileSummary()));
        facts.put("coarseSignalsStable", Boolean.toString(coarseSignalsStable(rounds)));
        return facts;
    }

    private Map<String, Object> buildRawEvidence(
            String userId,
            int requestedRunCount,
            int horizonRounds,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            List<RoundSnapshot> rounds,
            OfficialVerificationContractMetadataSupport.ContractStatus contractStatus
    ) {
        List<Map<String, Object>> roundEvidence = new ArrayList<>(rounds.size());
        for (RoundSnapshot round : rounds) {
            roundEvidence.add(buildRoundEvidence(round));
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("behavioralRoundCount", horizonRounds);
        summary.put("coarseSignalsStable", coarseSignalsStable(rounds));
        summary.put("previousPathRoundCount", rounds.stream().skip(1).filter(round -> StringUtils.hasText(previousPath(round))).count());
        summary.put("sessionHistorySupportRoundCount", rounds.stream().skip(1).filter(round -> hasSessionHistorySupport(round, Math.max(1, round.roundNumber() - 1))).count());
        summary.put("requestParityAligned", rounds.stream().allMatch(RoundSnapshot::requestParityAligned));
        summary.put("finalRelatedDocumentsCount", rounds.get(rounds.size() - 1).relatedDocumentsCount());
        summary.put("finalObservationCount", rounds.get(rounds.size() - 1).observationCount());

        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("requestedPreset", Map.of(
                "verificationUser", value(userId),
                "endpointKey", rounds.get(0).plan().endpoint().key(),
                "endpointLabel", rounds.get(0).plan().endpoint().label(),
                "resourceId", rounds.get(0).plan().endpoint().resourceId(),
                "requestedRunCount", requestedRunCount,
                "behavioralRoundCount", horizonRounds,
                "rerun", rerun,
                "contaminationSeed", contaminationSeed,
                "baselineSeedRequested", baselineSeedRequested
        ));
        summary.put("scenarioSelector", SCENARIO_SELECTOR);
        summary.put("scenarioCount", rounds.stream().map(round -> round.plan().scenarioKey()).distinct().count());
        evidence.put("behavioralSummary", Map.copyOf(summary));
        evidence.put("rounds", List.copyOf(roundEvidence));
        return OfficialVerificationContractMetadataSupport.withRawEvidence(evidence, contractStatus);
    }

    private Map<String, Object> buildRoundEvidence(RoundSnapshot round) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("round", round.roundNumber());
        evidence.put("plan", Map.of(
                "roundKey", round.plan().roundKey(),
                "behaviorPhase", round.plan().behaviorPhase(),
                "anomalySignal", round.plan().anomalySignal(),
                "clientIp", round.plan().clientIp(),
                "browserUserAgent", round.plan().browserUserAgent(),
                "simulatedUserAgentLabel", round.plan().simulatedUserAgentLabel(),
                "observedAt", round.plan().observedAt().toString(),
                "semanticMarkers", round.plan().semanticMarkers(),
                "expectationNote", round.plan().expectationNote()
        ));
        evidence.put("requestId", round.requestId());
        evidence.put("responseRequestId", text(round.invocation(), "requestId"));
        evidence.put("requestPath", requestPath(round));
        evidence.put("previousPath", previousPath(round));
        evidence.put("relatedDocumentsCount", round.relatedDocumentsCount());
        evidence.put("observationCount", round.observationCount());
        evidence.put("baselineContextPresent", round.baselineContextPresent());
        evidence.put("requestParityAligned", round.requestParityAligned());
        evidence.put("workProfileSummary", round.workProfileSummary());
        evidence.put("invocation", round.invocation());
        evidence.put("analysisEvents", round.events());
        evidence.put("decisionMetadata", round.decisionMetadata());
        evidence.put("decisionAttributes", round.decisionAttributes());
        evidence.put("promptTelemetry", round.promptTelemetry());
        evidence.put("decisionOutbox", OfficialVerificationRuntimeEvidenceSupport.decisionOutboxSnapshot(
                round.decisionOutbox(),
                round.decisionPayload()
        ));
        evidence.put("promptAuditOutbox", OfficialVerificationRuntimeEvidenceSupport.promptAuditOutboxSnapshot(
                round.promptOutbox(),
                round.promptPayload()
        ));
        return evidence;
    }

    private Map<String, Object> firstMetadata(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events, String type) {
        return events.stream()
                .filter(item -> type.equalsIgnoreCase(item.type()))
                .map(OfficialVerificationAnalysisEventStore.AnalysisEvent::metadata)
                .filter(item -> item != null && !item.isEmpty())
                .findFirst()
                .map(LinkedHashMap::new)
                .orElseGet(LinkedHashMap::new);
    }

    private Map<String, Object> firstPresent(Map<String, Object>... sources) {
        for (Map<String, Object> source : sources) {
            if (source != null && !source.isEmpty()) {
                return source;
            }
        }
        return Map.of();
    }

    private Map<String, Object> map(Object value) {
        if (value instanceof Map<?, ?> raw) {
            Map<String, Object> normalized = new LinkedHashMap<>();
            raw.forEach((key, item) -> {
                if (key != null && item != null) {
                    normalized.put(String.valueOf(key), item);
                }
            });
            return Map.copyOf(normalized);
        }
        return Map.of();
    }

    private int integer(Map<String, Object> source, String... keys) {
        if (source == null) {
            return 0;
        }
        for (String key : keys) {
            Object value = source.get(key);
            if (value instanceof Number number) {
                return number.intValue();
            }
            if (value instanceof String textValue) {
                try {
                    return Integer.parseInt(textValue.trim());
                }
                catch (NumberFormatException ignored) {
                }
            }
        }
        return 0;
    }

    private long longValue(Map<String, Object> source, String... keys) {
        if (source == null) {
            return -1L;
        }
        for (String key : keys) {
            Object value = source.get(key);
            if (value instanceof Number number) {
                return number.longValue();
            }
            if (value instanceof String textValue) {
                try {
                    return Long.parseLong(textValue.trim());
                }
                catch (NumberFormatException ignored) {
                }
            }
        }
        return -1L;
    }

    private boolean containsValue(Map<String, Object> source, String... keys) {
        if (source == null) {
            return false;
        }
        for (String key : keys) {
            if (source.containsKey(key) && source.get(key) != null) {
                return true;
            }
        }
        return false;
    }

    private int relatedDocumentsCount(Map<String, Object> promptPayload, Map<String, Object> decisionMetadata) {
        int allowedDocumentCount = integer(promptPayload, "allowedDocumentCount");
        if (allowedDocumentCount > 0) {
            return allowedDocumentCount;
        }
        Object contexts = promptPayload.get("contexts");
        if (contexts instanceof List<?> items && !items.isEmpty()) {
            return items.size();
        }
        return integer(decisionMetadata, "relatedDocumentsCount");
    }

    private String workProfileSummary(Map<String, Object> decisionPayload, Map<String, Object> decisionAttributes) {
        String direct = text(decisionPayload, "workProfileSummary", "workProfile");
        if (StringUtils.hasText(direct)) {
            return direct;
        }
        return text(decisionAttributes, "workProfileSummary", "workProfile");
    }

    private int observationCount(
            Map<String, Object> decisionPayload,
            Map<String, Object> decisionAttributes,
            Map<String, Object> decisionMetadata,
            String workProfileSummary
    ) {
        int direct = integer(decisionPayload, "observationCount");
        if (direct > 0) {
            return direct;
        }
        direct = integer(decisionAttributes, "observationCount");
        if (direct > 0) {
            return direct;
        }
        direct = integer(decisionMetadata, "observationCount");
        if (direct > 0) {
            return direct;
        }
        direct = extractObservationCount(workProfileSummary);
        return direct >= 0 ? direct : -1;
    }

    private int extractObservationCount(String workProfileSummary) {
        if (!StringUtils.hasText(workProfileSummary)) {
            return -1;
        }
        for (Pattern pattern : List.of(OBSERVATIONS_PATTERN, OBSERVATIONS_KEY_VALUE_PATTERN, OBSERVATION_COUNT_PATTERN)) {
            Matcher matcher = pattern.matcher(workProfileSummary);
            if (matcher.find()) {
                try {
                    return Integer.parseInt(matcher.group(1));
                }
                catch (NumberFormatException ignored) {
                    return -1;
                }
            }
        }
        return -1;
    }

    private boolean baselineContextPresent(
            Map<String, Object> decisionPayload,
            Map<String, Object> decisionAttributes,
            Map<String, Object> decisionMetadata,
            String workProfileSummary
    ) {
        if (StringUtils.hasText(workProfileSummary)) {
            return true;
        }
        return booleanValue(decisionAttributes.get("baselineEstablished"))
                || booleanValue(decisionAttributes.get("personalBaselineEstablished"))
                || booleanValue(decisionAttributes.get("organizationBaselineEstablished"))
                || booleanValue(decisionMetadata.get("baselineEstablished"))
                || booleanValue(decisionMetadata.get("personalBaselineEstablished"))
                || booleanValue(decisionMetadata.get("organizationBaselineEstablished"))
                || containsValue(decisionPayload, "workProfileSummary");
    }

    private boolean booleanValue(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String textValue) {
            return Boolean.parseBoolean(textValue.trim());
        }
        return false;
    }

    private String text(Map<String, Object> source, String... keys) {
        if (source == null) {
            return null;
        }
        for (String key : keys) {
            Object value = source.get(key);
            if (value == null) {
                continue;
            }
            String normalized = String.valueOf(value).trim();
            if (!normalized.isBlank()) {
                return normalized;
            }
        }
        return null;
    }

    private String value(String input) {
        return StringUtils.hasText(input) ? input : "n/a";
    }

    private boolean sameValue(String left, String right) {
        return StringUtils.hasText(left) && left.equals(right);
    }

    private boolean coarseSignalsStable(List<RoundSnapshot> rounds) {
        return sameClientIpAcrossRounds(rounds) && sameUserAgentAcrossRounds(rounds);
    }

    private boolean sameClientIpAcrossRounds(List<RoundSnapshot> rounds) {
        LinkedHashSet<String> clientIps = new LinkedHashSet<>();
        for (RoundSnapshot round : rounds) {
            String clientIp = text(round.decisionMetadata(), "clientIp");
            if (!StringUtils.hasText(clientIp)) {
                clientIp = round.plan().clientIp();
            }
            clientIps.add(value(clientIp));
        }
        return clientIps.size() == 1;
    }

    private boolean sameUserAgentAcrossRounds(List<RoundSnapshot> rounds) {
        LinkedHashSet<String> userAgents = new LinkedHashSet<>();
        for (RoundSnapshot round : rounds) {
            String userAgent = text(round.decisionMetadata(), "userAgent", "simulatedUserAgentLabel");
            if (!StringUtils.hasText(userAgent)) {
                userAgent = round.plan().browserUserAgent();
            }
            userAgents.add(value(userAgent));
        }
        return userAgents.size() == 1;
    }

    private String requestPath(RoundSnapshot round) {
        String fromInvocation = text(round.invocation(), "requestPath");
        if (StringUtils.hasText(fromInvocation)) {
            return fromInvocation;
        }
        String fromMetadata = text(round.decisionMetadata(), "requestPath");
        if (StringUtils.hasText(fromMetadata)) {
            return fromMetadata;
        }
        return round.plan().endpoint().path();
    }

    private String previousPath(RoundSnapshot round) {
        String fromMetadata = text(round.decisionMetadata(), "previousPath");
        if (StringUtils.hasText(fromMetadata)) {
            return fromMetadata;
        }
        return text(round.decisionAttributes(), "previousPath");
    }

    private String behaviorPhase(RoundSnapshot round) {
        String fromMetadata = text(round.decisionMetadata(), "behaviorPhase");
        if (StringUtils.hasText(fromMetadata)) {
            return fromMetadata;
        }
        return text(round.decisionAttributes(), "behaviorPhase");
    }

    private String anomalySignal(RoundSnapshot round) {
        String fromMetadata = text(round.decisionMetadata(), "anomalySignal");
        if (StringUtils.hasText(fromMetadata)) {
            return fromMetadata;
        }
        return text(round.decisionAttributes(), "anomalySignal");
    }

    private boolean hasSessionHistorySupport(RoundSnapshot round, int roundIndex) {
        int expectedDocs = Math.min(roundIndex, 12);
        return round.relatedDocumentsCount() >= expectedDocs
                || round.baselineContextPresent()
                || round.observationCount() > 0
                || containsValue(round.decisionPayload(), "workProfileSummary", "behaviorPatterns", "evidenceList");
    }

    private String sessionHistorySupportSummary(RoundSnapshot round) {
        return "relatedDocs=" + round.relatedDocumentsCount()
                + ", baseline=" + round.baselineContextPresent()
                + ", observations=" + round.observationCount();
    }

    private boolean signalSpecificEvidencePresent(RoundSnapshot round) {
        String anomalySignal = anomalySignal(round);
        if (!StringUtils.hasText(anomalySignal) || "NONE".equalsIgnoreCase(anomalySignal)) {
            return true;
        }
        if (anomalySignal.contains("DEVICE")) {
            return sameValue(round.plan().browserUserAgent(), text(round.decisionMetadata(), "userAgent"))
                    || sameValue(round.plan().simulatedUserAgentLabel(), text(round.decisionMetadata(), "simulatedUserAgentLabel"))
                    || booleanValue(round.decisionMetadata().get("isNewDevice"));
        }
        if (anomalySignal.contains("NETWORK")) {
            return sameValue(round.plan().clientIp(), text(round.decisionMetadata(), "clientIp"))
                    || containsValue(round.decisionMetadata(), "geoCountry", "geoCity");
        }
        if (anomalySignal.contains("CADENCE")) {
            return StringUtils.hasText(previousPath(round))
                    || longValue(round.decisionMetadata(), "lastRequestIntervalMs") >= 0L;
        }
        if (anomalySignal.contains("SEQUENCE")) {
            return StringUtils.hasText(previousPath(round))
                    && (round.relatedDocumentsCount() > 0 || round.observationCount() > 0 || round.baselineContextPresent());
        }
        if (anomalySignal.contains("RESOURCE")
                || anomalySignal.contains("CRITICAL")
                || anomalySignal.contains("NORMALIZATION")) {
            String sensitivity = text(round.decisionMetadata(), "resourceSensitivity");
            return sameValue(round.plan().endpoint().path(), requestPath(round))
                    && StringUtils.hasText(sensitivity)
                    && !"UNKNOWN".equalsIgnoreCase(sensitivity);
        }
        return sameValue(round.plan().endpoint().path(), requestPath(round));
    }

    private String signalEvidenceSummary(RoundSnapshot round) {
        return "signal=" + value(anomalySignal(round))
                + ", requestPath=" + value(requestPath(round))
                + ", previousPath=" + value(previousPath(round))
                + ", clientIp=" + value(text(round.decisionMetadata(), "clientIp"))
                + ", userAgent=" + value(text(round.decisionMetadata(), "userAgent", "simulatedUserAgentLabel"));
    }

    private String phaseChain(List<RoundSnapshot> rounds) {
        return rounds.stream()
                .map(this::behaviorPhase)
                .map(this::value)
                .reduce((left, right) -> left + " -> " + right)
                .orElse("n/a");
    }

    private String signalChain(List<RoundSnapshot> rounds) {
        return rounds.stream()
                .map(this::anomalySignal)
                .map(this::value)
                .reduce((left, right) -> left + " -> " + right)
                .orElse("n/a");
    }

    private String buildMessage(double score, List<RoundSnapshot> rounds) {
        if (rounds.size() < MIN_BEHAVIORAL_ROUNDS) {
            return "BSR could not capture enough enterprise rounds to validate behavioral surprise and recovery.";
        }
        if (score < 95.0d) {
            return "BSR detected anomaly or recovery rounds where sequence history, cadence evidence, or observed work pattern context was not preserved.";
        }
        return "BSR confirms that behavioral surprise and recovery remain traceable across anomaly and normalization rounds.";
    }

    private BsrEventItem toBsrEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new BsrEventItem(
                value(event.type()),
                value(event.layer()),
                value(event.status()),
                value(event.requestPath())
        );
    }

    private List<BehavioralRoundPlan> buildRoundPlans(String endpointKey, String resourceId, int horizonRounds, String requestPath) {
        List<BehavioralRoundPlan> plans = new ArrayList<>(horizonRounds);
        Instant baseObservedAt = Instant.now().minus(Duration.ofHours(2));
        String anchor = StringUtils.hasText(endpointKey) ? endpointKey.trim().toLowerCase(Locale.ROOT) : "sensitive";
        String anomalyEndpoint = "normal".equals(anchor) ? "sensitive" : anchor;
        List<String> pathSequence = List.of("normal", anomalyEndpoint, "critical", anomalyEndpoint, "normal");
        List<String> phaseSequence = List.of("BASELINE", "ANOMALY", "RECOVERY", "RECOVERY", "RECOVERY");
        List<String> signalSequence = List.of("NONE", "RESOURCE_SEQUENCE", "CRITICAL_SEQUENCE", "RESOURCE_NORMALIZATION", "CADENCE_SEQUENCE");
        for (int index = 0; index < horizonRounds; index++) {
            String roundEndpointKey = pathSequence.get(Math.min(index, pathSequence.size() - 1));
            EndpointDefinition roundEndpoint = resolveEndpoint(roundEndpointKey, resourceId + "-bsr-r" + (index + 1), requestPath);
            boolean baselineRound = index == 0;
            boolean anomalyRound = index == 1;
            plans.add(new BehavioralRoundPlan(
                    "BSR-R" + (index + 1),
                    index + 1,
                    roundEndpoint,
                    STABLE_CLIENT_IP,
                    STABLE_BROWSER_USER_AGENT,
                    STABLE_USER_AGENT_LABEL,
                    baseObservedAt.plus(ROUND_STEP.multipliedBy(index)),
                    phaseSequence.get(Math.min(index, phaseSequence.size() - 1)),
                    signalSequence.get(Math.min(index, signalSequence.size() - 1)),
                    baselineRound
                            ? "Baseline control round"
                            : anomalyRound
                            ? "Anomaly round that disrupts the behavioral sequence"
                            : "Recovery round that should retain prior sequence context",
                    baselineRound
                            ? List.of("EXPECT_HISTORY_BUILDUP")
                            : anomalyRound
                            ? List.of("EXPECT_PREVIOUS_PATH", "EXPECT_SEQUENCE_SURPRISE", "EXPECT_OBSERVED_WORK_PATTERN")
                            : List.of("EXPECT_PREVIOUS_PATH", "EXPECT_RECOVERY_AFTER_ANOMALY", "EXPECT_OBSERVED_WORK_PATTERN")
            ));
        }
        return List.copyOf(plans);
    }

    private EndpointDefinition resolveEndpoint(String endpointKey, String resourceId, String requestPath) {
        OfficialVerificationReplayPathSupport.ReplayTarget replayTarget = OfficialVerificationReplayPathSupport.retargetProbeTarget(
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
    private String normalizeResourceId(String resourceId) {
        String normalized = StringUtils.hasText(resourceId) ? resourceId.trim() : "resource-001";
        normalized = normalized.replaceAll("[^A-Za-z0-9._-]", "-");
        return normalized.isBlank() ? "resource-001" : normalized;
    }

    private record EndpointDefinition(String key, String label, String path, String resourceId) {
    }

    private record BehavioralRoundPlan(
            String roundKey,
            int roundNumber,
            EndpointDefinition endpoint,
            String clientIp,
            String browserUserAgent,
            String simulatedUserAgentLabel,
            Instant observedAt,
            String behaviorPhase,
            String anomalySignal,
            String expectationNote,
            List<String> semanticMarkers
    ) {
        private BehavioralRoundPlan {
            semanticMarkers = semanticMarkers == null ? List.of() : List.copyOf(semanticMarkers);
        }

        private boolean anomalyExpected() {
            return StringUtils.hasText(anomalySignal) && !"NONE".equalsIgnoreCase(anomalySignal);
        }
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

    public record BsrRunSummary(
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

    public record BsrRunRecord(
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
            List<BsrCheckResult> checks,
            Map<String, String> requestFacts,
            Map<String, String> eventFacts,
            Map<String, String> promptFacts,
            Map<String, String> analysisFacts,
            List<BsrEventItem> events,
            Map<String, Object> rawEvidence) implements OfficialVerificationDetailedRunRecordView<BsrCheckResult, BsrEventItem> {

        public BsrRunSummary toSummary() {
            return new BsrRunSummary(
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

    public record BsrCheckResult(
            String label,
            String expectedValue,
            String actualValue,
            boolean pass,
            String source) implements OfficialVerificationCheckResultView {
    }

    public record BsrEventItem(
            String type,
            String layer,
            String status,
            String requestPath) implements OfficialVerificationEventItemView {
    }
}






















