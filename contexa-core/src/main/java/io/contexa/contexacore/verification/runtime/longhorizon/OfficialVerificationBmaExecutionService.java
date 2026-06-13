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
    private static final String SCENARIO_HEADER = "X-Contexa-Scenario";
    private static final String SIMULATED_USER_AGENT_HEADER = "X-Simulated-User-Agent";
    private static final String SIMULATED_USER_AGENT_LABEL_HEADER = "X-Simulated-User-Agent-Label";
    private static final String DEMO_PHASE_HEADER = "X-Contexa-Demo-Phase";
    private static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";
    private static final int MIN_PROGRESSION_ROUNDS = 3;
    private static final String STABLE_CLIENT_IP = "198.51.100.24";
    private static final String STABLE_BROWSER_USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    private static final String STABLE_USER_AGENT_LABEL = "Chrome on Windows 10";
    private static final Duration ROUND_STEP = Duration.ofDays(7);
    private static final Pattern OBSERVATIONS_PATTERN = Pattern.compile("(?i)\\bObservations\\s+(\\d+)\\b");
    private static final Pattern OBSERVATIONS_KEY_VALUE_PATTERN = Pattern.compile("(?i)\\bobservations\\s*[=:]\\s*(\\d+)\\b");
    private static final Pattern OBSERVATION_COUNT_PATTERN = Pattern.compile("(?i)\\bobservationCount\\s*[=:]\\s*(\\d+)\\b");    public OfficialVerificationBmaExecutionService(
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            WebClient.Builder webClientBuilder,
            ObjectMapper objectMapper
    ) {
        super("BMA", decisionOutboxRepository, promptAuditOutboxRepository, analysisEventStore, webClientBuilder, objectMapper, BmaRunRecord::runId, BmaRunRecord::startedAt);
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
    public synchronized BmaRunRecord executeRun(
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
            HttpServletRequest request
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
        Map<String, Object> decisionMetadata = firstMetadata(events, "DECISION_APPLIED");
        Map<String, Object> decisionAttributes = map(decisionPayload.get("attributes"));
        Map<String, Object> promptTelemetry = firstPresent(decisionMetadata, decisionAttributes, decisionPayload);
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
    protected List<BmaEventItem> toEventItems(RoundSnapshot round) {
        return round.events().stream().map(this::toBmaEventItem).toList();
    }

    @Override
    protected List<BmaCheckResult> buildChecks(List<RoundSnapshot> rounds) {
        return buildChecksInternal(rounds);
    }

    @Override
    protected BmaRunRecord buildRunRecord(LongHorizonExecutionState<RoundSnapshot, BmaCheckResult, BmaEventItem> state) {
        RoundSnapshot lastRound = state.rounds().get(state.rounds().size() - 1);
        return new BmaRunRecord(
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
            int roundNumber,
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
                        roundNumber,
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
            int roundNumber,
            boolean contaminationSeed,
            boolean baselineSeedRequested
    ) {
        headers.set("X-Request-ID", requestId);
        headers.set(RESOURCE_ID_HEADER, plan.endpoint().resourceId());
        headers.set(RUN_COUNT_HEADER, String.valueOf(requestedRunCount));
        headers.set(CONTAMINATION_SEED_HEADER, String.valueOf(contaminationSeed));
        headers.set(BASELINE_SEED_HEADER, String.valueOf(baselineSeedRequested));
        headers.set(HttpHeaders.USER_AGENT, plan.browserUserAgent());
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
        copyHeader(request, headers, HttpHeaders.COOKIE);
        copyHeader(request, headers, HttpHeaders.AUTHORIZATION);
        copyHeader(request, headers, "X-XSRF-TOKEN");
    }

    private List<BmaCheckResult> buildChecksInternal(List<RoundSnapshot> rounds) {
        List<BmaCheckResult> checks = new ArrayList<>();
        if (rounds.isEmpty()) {
            checks.add(check("baseline maturity rounds are captured", ">= 3", "0", false, "rounds"));
            return List.copyOf(checks);
        }

        checks.add(check(
                "round 1 baseline remains provisional",
                "true",
                Boolean.toString(provisionalBaseline(rounds.get(0))),
                provisionalBaseline(rounds.get(0)),
                "rounds[0].decisionOutbox.payload.workProfileSummary"
        ));

        for (int index = 1; index < rounds.size(); index++) {
            RoundSnapshot previous = rounds.get(index - 1);
            RoundSnapshot current = rounds.get(index);
            checks.add(check(
                    "round " + (index + 1) + " baseline context is present",
                    "true",
                    Boolean.toString(current.baselineContextPresent()),
                    current.baselineContextPresent(),
                    "rounds[" + index + "].decisionOutbox.payload.workProfileSummary"
            ));
            checks.add(check(
                    "round " + (index + 1) + " observation evidence does not regress",
                    ">=" + previous.observationCount(),
                    previous.observationCount() + " -> " + current.observationCount(),
                    observationEvidenceMaintained(previous, current),
                    "rounds[" + index + "].decisionOutbox.payload.workProfileSummary"
            ));
        }
        return List.copyOf(checks);
    }

    private BmaCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new BmaCheckResult(label, value(expected), value(actual), pass, source);
    }

    private Map<String, String> buildRequestFacts(
            String verificationUserId,
            int requestedRunCount,
            int horizonRounds,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            List<RoundSnapshot> rounds,
            OfficialVerificationContractMetadataSupport.ContractStatus contractStatus
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("verificationUser", value(verificationUserId));
        facts.put("endpoint", rounds.get(0).plan().endpoint().label());
        facts.put("resourceId", rounds.get(0).plan().endpoint().resourceId());
        facts.put("requestedRunCount", String.valueOf(requestedRunCount));
        facts.put("progressionRoundCount", String.valueOf(horizonRounds));
        facts.put("firstRequestId", value(rounds.get(0).requestId()));
        facts.put("finalRequestId", value(rounds.get(rounds.size() - 1).requestId()));
        facts.put("rerun", rerun ? "yes" : "no");
        facts.put("contaminationSeed", contaminationSeed ? "enabled" : "disabled");
        facts.put("baselineSeedRequested", baselineSeedRequested ? "enabled" : "disabled");
        facts.put("scenarioSelector", SCENARIO_SELECTOR);
        facts.put("scenarioCount", String.valueOf(rounds.stream().map(round -> round.plan().scenarioKey()).distinct().count()));
        return OfficialVerificationContractMetadataSupport.withRequestFacts(facts, contractStatus);
    }

    private Map<String, String> buildEventFacts(List<RoundSnapshot> rounds) {
        Map<String, String> facts = new LinkedHashMap<>();
        int totalEventCount = rounds.stream().mapToInt(round -> round.events().size()).sum();
        boolean decisionEventPresent = rounds.stream()
                .flatMap(round -> round.events().stream())
                .anyMatch(item -> "DECISION_APPLIED".equalsIgnoreCase(item.type()));
        boolean requestParityAligned = rounds.stream().allMatch(RoundSnapshot::requestParityAligned);
        facts.put("roundCount", String.valueOf(rounds.size()));
        facts.put("totalEventCount", String.valueOf(totalEventCount));
        facts.put("firstRequestId", value(rounds.get(0).requestId()));
        facts.put("finalRequestId", value(rounds.get(rounds.size() - 1).requestId()));
        facts.put("decisionEventPresent", Boolean.toString(decisionEventPresent));
        facts.put("requestParityAligned", Boolean.toString(requestParityAligned));
        facts.put("finalRequestPath", value(text(rounds.get(rounds.size() - 1).invocation(), "requestPath")));
        return facts;
    }

    private Map<String, String> buildPromptFacts(List<RoundSnapshot> rounds) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("initialRoundBaselineProvisional", Boolean.toString(provisionalBaseline(rounds.get(0))));
        facts.put("round2BaselineContextPresent", rounds.size() > 1 ? Boolean.toString(rounds.get(1).baselineContextPresent()) : "n/a");
        facts.put("round3BaselineContextPresent", rounds.size() > 2 ? Boolean.toString(rounds.get(2).baselineContextPresent()) : "n/a");
        facts.put("finalBaselineContextPresent", Boolean.toString(rounds.get(rounds.size() - 1).baselineContextPresent()));
        facts.put("baselineContextRoundCount", String.valueOf(rounds.stream().filter(RoundSnapshot::baselineContextPresent).count()));
        return facts;
    }

    private Map<String, String> buildAnalysisFacts(List<RoundSnapshot> rounds) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("round1ObservationCount", String.valueOf(rounds.get(0).observationCount()));
        facts.put("round2ObservationCount", rounds.size() > 1 ? String.valueOf(rounds.get(1).observationCount()) : "n/a");
        facts.put("round3ObservationCount", rounds.size() > 2 ? String.valueOf(rounds.get(2).observationCount()) : "n/a");
        facts.put("finalObservationCount", String.valueOf(rounds.get(rounds.size() - 1).observationCount()));
        facts.put("observationCountNonDecreasing", Boolean.toString(observationCountsNonDecreasing(rounds)));
        facts.put("initialRoundBaselineProvisional", Boolean.toString(provisionalBaseline(rounds.get(0))));
        facts.put("finalBaselineContextPresent", Boolean.toString(rounds.get(rounds.size() - 1).baselineContextPresent()));
        facts.put("finalWorkProfileSummary", value(rounds.get(rounds.size() - 1).workProfileSummary()));
        return facts;
    }

    private Map<String, Object> buildRawEvidence(
            String verificationUserId,
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
        summary.put("progressionRoundCount", horizonRounds);
        summary.put("relatedDocumentsNonDecreasing", relatedDocumentsNonDecreasing(rounds));
        summary.put("observationCountNonDecreasing", observationCountsNonDecreasing(rounds));
        summary.put("baselineContextRoundCount", rounds.stream().filter(RoundSnapshot::baselineContextPresent).count());
        summary.put("requestParityAligned", rounds.stream().allMatch(RoundSnapshot::requestParityAligned));
        summary.put("finalRelatedDocumentsCount", rounds.get(rounds.size() - 1).relatedDocumentsCount());
        summary.put("finalObservationCount", rounds.get(rounds.size() - 1).observationCount());

        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("requestedPreset", Map.of(
                "verificationUser", value(verificationUserId),
                "endpointKey", rounds.get(0).plan().endpoint().key(),
                "endpointLabel", rounds.get(0).plan().endpoint().label(),
                "resourceId", rounds.get(0).plan().endpoint().resourceId(),
                "requestedRunCount", requestedRunCount,
                "progressionRoundCount", horizonRounds,
                "rerun", rerun,
                "contaminationSeed", contaminationSeed,
                "baselineSeedRequested", baselineSeedRequested
        ));
        summary.put("scenarioSelector", SCENARIO_SELECTOR);
        summary.put("scenarioCount", rounds.stream().map(round -> round.plan().scenarioKey()).distinct().count());
        evidence.put("progressionSummary", Map.copyOf(summary));
        evidence.put("rounds", List.copyOf(roundEvidence));
        return OfficialVerificationContractMetadataSupport.withRawEvidence(evidence, contractStatus);
    }

    private Map<String, Object> buildRoundEvidence(RoundSnapshot round) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("round", round.roundNumber());
        evidence.put("plan", Map.of("scenarioKey", round.plan().scenarioKey(), "scenarioFamily", round.plan().scenarioFamily(), "roundKey", round.plan().roundKey(), "requestPath", round.plan().endpoint().path(), "behaviorPhase", round.plan().behaviorPhase()));
        evidence.put("requestId", round.requestId());
        evidence.put("responseRequestId", text(round.invocation(), "requestId"));
        evidence.put("requestPath", text(round.invocation(), "requestPath"));
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
        evidence.put("decisionOutbox", buildDecisionOutboxEvidence(round));
        evidence.put("promptAuditOutbox", buildPromptAuditOutboxEvidence(round));
        return Collections.unmodifiableMap(new LinkedHashMap<>(evidence));
    }

    private Map<String, Object> buildDecisionOutboxEvidence(RoundSnapshot round) {
        if (round == null || round.decisionOutbox() == null) {
            return Map.of();
        }
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("correlationId", round.decisionOutbox().getCorrelationId());
        evidence.put("status", round.decisionOutbox().getStatus());
        evidence.put("attemptCount", round.decisionOutbox().getAttemptCount());
        evidence.put("deliveredAt", round.decisionOutbox().getDeliveredAt());
        evidence.put("payload", round.decisionPayload());
        return Collections.unmodifiableMap(new LinkedHashMap<>(evidence));
    }

    private Map<String, Object> buildPromptAuditOutboxEvidence(RoundSnapshot round) {
        if (round == null || round.promptOutbox() == null) {
            return Map.of();
        }
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("auditId", round.promptOutbox().getAuditId());
        evidence.put("correlationId", round.promptOutbox().getCorrelationId());
        evidence.put("status", round.promptOutbox().getStatus());
        evidence.put("attemptCount", round.promptOutbox().getAttemptCount());
        evidence.put("deliveredAt", round.promptOutbox().getDeliveredAt());
        evidence.put("payload", round.promptPayload());
        return Collections.unmodifiableMap(new LinkedHashMap<>(evidence));
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

    private boolean relatedDocumentsNonDecreasing(List<RoundSnapshot> rounds) {
        for (int index = 1; index < rounds.size(); index++) {
            if (rounds.get(index).relatedDocumentsCount() < rounds.get(index - 1).relatedDocumentsCount()) {
                return false;
            }
        }
        return true;
    }

    private boolean observationCountsNonDecreasing(List<RoundSnapshot> rounds) {
        for (int index = 1; index < rounds.size(); index++) {
            if (!observationEvidenceMaintained(rounds.get(index - 1), rounds.get(index))) {
                return false;
            }
        }
        return true;
    }

    private boolean observationEvidenceMaintained(RoundSnapshot previous, RoundSnapshot current) {
        if (previous == null || current == null) {
            return false;
        }
        if (current.observationCount() < 0) {
            return current.baselineContextPresent();
        }
        if (previous.observationCount() < 0) {
            return current.baselineContextPresent() && current.observationCount() > 0;
        }
        if (current.observationCount() >= previous.observationCount()) {
            return true;
        }
        return previous.baselineContextPresent()
                && current.baselineContextPresent()
                && current.observationCount() > 0;
    }

    private boolean provisionalBaseline(RoundSnapshot round) {
        if (round == null) {
            return false;
        }
        String workProfileSummary = round.workProfileSummary();
        if (StringUtils.hasText(workProfileSummary)) {
            String normalizedSummary = workProfileSummary.toUpperCase(Locale.ROOT);
            if (normalizedSummary.contains("EVIDENCE STATE PROVISIONAL")) {
                return true;
            }
            if (normalizedSummary.contains("EVIDENCE STATE ESTABLISHED")
                    || normalizedSummary.contains("EVIDENCE STATE MATURE")) {
                return false;
            }
        }
        return !round.baselineContextPresent() || round.observationCount() <= 0;
    }

    private String buildMessage(double score, List<RoundSnapshot> rounds) {
        if (rounds.size() < MIN_PROGRESSION_ROUNDS) {
            return "BMA could not capture enough repeated rounds to validate baseline maturity.";
        }
        if (score < 95.0d) {
            return "BMA detected immature or regressing baseline evidence across repeated enterprise rounds.";
        }
        return "BMA confirms that baseline evidence starts provisional and matures into observed work pattern context across repeated enterprise rounds.";
    }

    private BmaEventItem toBmaEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new BmaEventItem(
                value(event.type()),
                value(event.layer()),
                value(event.status()),
                value(event.requestPath())
        );
    }

    private EndpointDefinition resolveEndpoint(String endpointKey, String resourceId, String requestPath) {
        OfficialVerificationReplayPathSupport.ReplayTarget replayTarget = OfficialVerificationReplayPathSupport.resolveProbeTarget(
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





