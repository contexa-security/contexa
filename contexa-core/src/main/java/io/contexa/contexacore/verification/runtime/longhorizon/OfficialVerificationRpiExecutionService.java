package io.contexa.contexacore.verification.runtime.longhorizon;

import org.springframework.transaction.annotation.Transactional;

import io.contexa.contexacore.verification.runtime.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.repository.PromptContextAuditForwardingOutboxRepository;
import io.contexa.contexacore.repository.SecurityDecisionForwardingOutboxRepository;
import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractRoundPlan;
import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractScenario;
import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractScenarioCatalog;
import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractSessionMode;
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
public class OfficialVerificationRpiExecutionService extends AbstractOfficialVerificationLongHorizonMetricExecutionService<OfficialVerificationRpiExecutionService.RpiRunRecord, OfficialVerificationRpiExecutionService.ProgressionRoundPlan, OfficialVerificationRpiExecutionService.RoundSnapshot, OfficialVerificationRpiExecutionService.RpiCheckResult, OfficialVerificationRpiExecutionService.RpiEventItem> implements OfficialVerificationRpiExecutor {

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
    private static final int MIN_PROGRESSION_ROUNDS = 3;
    private static final String SCENARIO_SELECTOR = "EXTENDED";
    private static final List<String> ALLOWED_ENDPOINT_KEYS = List.of("normal", "sensitive", "critical");
    private static final Duration REPOSITORY_DECISION_WAIT_TIMEOUT = Duration.ofSeconds(5);
    private static final Pattern OBSERVATIONS_PATTERN = Pattern.compile("(?i)\\bObservations\\s+(\\d+)\\b");
    private static final Pattern OBSERVATIONS_KEY_VALUE_PATTERN = Pattern.compile("(?i)\\bobservations\\s*[=:]\\s*(\\d+)\\b");
    private static final Pattern OBSERVATION_COUNT_PATTERN = Pattern.compile("(?i)\\bobservationCount\\s*[=:]\\s*(\\d+)\\b");
    private final ZeroTrustActionRepository zeroTrustActionRepository;

    public OfficialVerificationRpiExecutionService(
            SecurityDecisionForwardingOutboxRepository decisionOutboxRepository,
            PromptContextAuditForwardingOutboxRepository promptAuditOutboxRepository,
            OfficialVerificationAnalysisEventStore analysisEventStore,
            WebClient.Builder webClientBuilder,
            ObjectMapper objectMapper,
            ZeroTrustActionRepository zeroTrustActionRepository
    ) {
        super(
                "RPI",
                decisionOutboxRepository,
                promptAuditOutboxRepository,
                analysisEventStore,
                webClientBuilder,
                objectMapper,
                RpiRunRecord::runId,
                RpiRunRecord::startedAt
        );
        this.zeroTrustActionRepository = zeroTrustActionRepository;
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
            HttpServletRequest request
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
            HttpServletRequest request,
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
        return MIN_PROGRESSION_ROUNDS;
    }

    @Override
    protected OfficialVerificationContractMetadataSupport.ContractStatus buildContractStatus(
            String endpointKey,
            String resourceId,
            String requestPath,
            int horizonRounds
    ) {
        List<OfficialVerificationPromptContractScenario> contracts = OfficialVerificationPromptContractScenarioCatalog.resolve(SCENARIO_SELECTOR)
                .stream()
                .map(scenario -> OfficialVerificationPromptContractScenarioCatalog.resizeScenario(
                        scenario,
                        Math.max(MIN_PROGRESSION_ROUNDS, horizonRounds)
                ))
                .toList();
        return OfficialVerificationContractMetadataSupport.rpiStructureAligned(SCENARIO_SELECTOR, contracts);
    }

    @Override
    protected List<ProgressionRoundPlan> buildRoundPlans(
            String userId,
            String endpointKey,
            String resourceId,
            String requestPath,
            int horizonRounds
    ) {
        List<OfficialVerificationPromptContractScenario> contracts = OfficialVerificationPromptContractScenarioCatalog.resolve(SCENARIO_SELECTOR)
                .stream()
                .map(scenario -> OfficialVerificationPromptContractScenarioCatalog.resizeScenario(
                        scenario,
                        Math.max(MIN_PROGRESSION_ROUNDS, horizonRounds)
                ))
                .toList();
        return buildAlignedRoundPlans(contracts, userId);
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
            HttpServletRequest request
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
        int observationCount = observationCount(decisionPayload, decisionAttributes, decisionMetadata, promptPayload, workProfileSummary);
        boolean baselineContextPresent = baselineContextPresent(decisionPayload, decisionAttributes, decisionMetadata, promptPayload, workProfileSummary);
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
    protected List<RpiEventItem> toEventItems(RoundSnapshot round) {
        return round.events().stream().map(this::toRpiEventItem).toList();
    }

    @Override
    protected RpiRunRecord buildRunRecord(LongHorizonExecutionState<RoundSnapshot, RpiCheckResult, RpiEventItem> state) {
        RequestedTarget requestedTarget = resolveRequestedTarget(
                state.endpointKey(),
                normalizeResourceId(state.resourceId()),
                state.requestPath()
        );
        List<RoundSnapshot> rounds = state.rounds();
        RoundSnapshot lastRound = rounds.get(rounds.size() - 1);
        return new RpiRunRecord(
                state.runId(),
                state.runOrdinal(),
                "rpi-extended",
                "Extended Long-Horizon Scenario Set",
                lastRound.requestId(),
                state.score(),
                state.passedChecks(),
                state.totalChecks(),
                state.processingTimeMs(),
                state.success() ? "Threshold passed" : "Threshold failed",
                state.success() ? "success" : "error",
                buildMessage(state.score(), rounds, state.contractStatus()),
                KOREA_TIME.format(state.startedAt()),
                KOREA_TIME.format(state.completedAt()),
                state.checks(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRequestFacts(
                        buildRequestFacts(
                                requestedTarget,
                                state.userId(),
                                state.requestedRunCount(),
                                state.horizonRounds(),
                                state.rerun(),
                                state.contaminationSeed(),
                                state.baselineSeedRequested(),
                                rounds,
                                state.contractStatus()
                        ),
                        state.request()
                ),
                buildEventFacts(rounds),
                buildPromptFacts(rounds),
                buildAnalysisFacts(rounds),
                state.aggregatedEvents(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                        buildRawEvidence(
                                requestedTarget,
                                state.userId(),
                                state.requestedRunCount(),
                                state.horizonRounds(),
                                state.rerun(),
                                state.contaminationSeed(),
                                state.baselineSeedRequested(),
                                rounds,
                                state.contractStatus()
                        ),
                        state.request()
                )
        );
    }

    private List<ProgressionRoundPlan> buildAlignedRoundPlans(List<OfficialVerificationPromptContractScenario> contracts, String operatorUserId) {
        ArrayList<ProgressionRoundPlan> plans = new ArrayList<>();
        for (int scenarioIndex = 0; scenarioIndex < contracts.size(); scenarioIndex++) {
            OfficialVerificationPromptContractScenario contract = contracts.get(scenarioIndex);
            String benchmarkRunId = contract.scenarioKey().toLowerCase(Locale.ROOT) + "-benchmark-run-1";
            String verificationUserId = OfficialVerificationRuntimeIsolationSupport.verificationSubjectId(
                    operatorUserId,
                    "enterprise-rpi-run-" + UUID.randomUUID() + "-" + contract.scenarioKey().toLowerCase(Locale.ROOT)
            );
            Map<String, String> deviceIdsByAlias = new LinkedHashMap<>();
            String currentSessionId = null;
            int sessionSequence = 0;
            for (int roundIndex = 0; roundIndex < contract.roundPlans().size(); roundIndex++) {
                OfficialVerificationPromptContractRoundPlan round = contract.roundPlans().get(roundIndex);
                if (currentSessionId == null || round.sessionMode() == OfficialVerificationPromptContractSessionMode.NEW_SESSION) {
                    sessionSequence++;
                    currentSessionId = OfficialVerificationRuntimeIsolationSupport.verificationSessionId(
                            benchmarkRunId + ":" + contract.scenarioKey() + ":session-" + sessionSequence
                    );
                }
                String deviceId = deviceIdsByAlias.computeIfAbsent(
                        round.deviceAlias(),
                        alias -> buildDeviceId(contract, alias)
                );
                EndpointDefinition endpoint = resolveContractEndpoint(round.requestPath());
                plans.add(new ProgressionRoundPlan(
                        contract.scenarioKey(),
                        contract.scenarioFamily(),
                        contract.scenarioHeader(),
                        contract.expectedActionHeader(),
                        round.roundKey(),
                        benchmarkRunId,
                        verificationUserId,
                        currentSessionId,
                        scenarioIndex + 1,
                        roundIndex + 1,
                        endpoint.key(),
                        endpoint.label(),
                        endpoint.resourceId(),
                        endpoint.path(),
                        round.clientIp(),
                        round.browserUserAgent(),
                        round.simulatedUserAgentLabel(),
                        round.deviceAlias(),
                        deviceId,
                        round.observedAt().toInstant(),
                        round.sessionMode(),
                        round.cooldownBeforeRoundMs(),
                        round.behaviorPhase(),
                        round.anomalySignal(),
                        round.expectationNote(),
                        round.semanticMarkers()
                ));
            }
        }
        return List.copyOf(plans);
    }

    private RequestedTarget resolveRequestedTarget(String endpointKey, String resourceId, String requestPath) {
        String normalizedPath = OfficialVerificationReplayPathSupport.normalizeReplayPath(requestPath);
        if (StringUtils.hasText(normalizedPath) || StringUtils.hasText(endpointKey) || StringUtils.hasText(resourceId)) {
            OfficialVerificationReplayPathSupport.ReplayTarget replayTarget = OfficialVerificationReplayPathSupport.resolveProbeTarget(
                    endpointKey,
                    resourceId,
                    requestPath,
                    ALLOWED_ENDPOINT_KEYS
            );
            return new RequestedTarget(replayTarget.endpointKey(), replayTarget.resourceId(), replayTarget.requestPath());
        }
        return new RequestedTarget("n/a", normalizeResourceId(resourceId), normalizedPath);
    }

    private String buildDeviceId(OfficialVerificationPromptContractScenario contract, String deviceAlias) {
        String normalizedAlias = StringUtils.hasText(deviceAlias) ? deviceAlias.trim() : "device";
        normalizedAlias = normalizedAlias.replaceAll("[^A-Za-z0-9._:-]", "-");
        return "official-verification-rpi-"
                + contract.scenarioKey().toLowerCase(Locale.ROOT)
                + "-"
                + normalizedAlias.toLowerCase(Locale.ROOT);
    }

    private EndpointDefinition resolveContractEndpoint(String requestPath) {
        OfficialVerificationReplayPathSupport.ReplayTarget replayTarget = OfficialVerificationReplayPathSupport.parseProbeTarget(requestPath, ALLOWED_ENDPOINT_KEYS);
        return new EndpointDefinition(replayTarget.endpointKey(), switch (replayTarget.endpointKey()) {
            case "sensitive" -> "Sensitive Resource";
            case "critical" -> "Critical Resource";
            default -> "Normal Resource";
        }, replayTarget.requestPath(), replayTarget.resourceId());
    }

    private Map<String, Object> invokeProbe(
            ProgressionRoundPlan plan,
            String requestId,
            int requestedRunCount,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            HttpServletRequest request
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
            HttpHeaders headers,
            HttpServletRequest request,
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
        headers.set(HttpHeaders.ACCEPT, "application/json");
        headers.set(HttpHeaders.USER_AGENT, plan.browserUserAgent());
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
        copyHeader(request, headers, HttpHeaders.COOKIE);
        copyHeader(request, headers, HttpHeaders.AUTHORIZATION);
        copyHeader(request, headers, "X-XSRF-TOKEN");
    }

    @Override
    protected List<RpiCheckResult> buildChecks(List<RoundSnapshot> rounds) {
        List<RpiCheckResult> checks = new ArrayList<>();
        if (rounds.isEmpty()) {
            checks.add(check("progression rounds are captured", ">= 3", "0", false, "rounds"));
            return List.copyOf(checks);
        }

        List<List<RoundSnapshot>> scenarios = scenarioGroups(rounds);
        checks.add(check("official RPI scenario selector matches the shared contract", SCENARIO_SELECTOR, SCENARIO_SELECTOR, true, "contract.scenarioSelector"));
        checks.add(check("official RPI scenario count is populated", ">= 1", String.valueOf(scenarios.size()), !scenarios.isEmpty(), "contract.scenarios"));

        for (int scenarioIndex = 0; scenarioIndex < scenarios.size(); scenarioIndex++) {
            List<RoundSnapshot> scenarioRounds = scenarios.get(scenarioIndex);
            RoundSnapshot first = scenarioRounds.get(0);
            String prefix = first.plan().scenarioKey().toLowerCase(Locale.ROOT).replace('_', ' ') + " ";
            checks.add(check(prefix + "captures every contract round", String.valueOf(scenarioRounds.size()), String.valueOf(scenarioRounds.size()), true, "scenarios[" + scenarioIndex + "].rounds"));
            checks.add(check(prefix + "contains both new-session and reuse-session boundaries", "true", Boolean.toString(hasNewAndReuseSessions(scenarioRounds)), hasNewAndReuseSessions(scenarioRounds), "scenarios[" + scenarioIndex + "].roundPlans[*].sessionMode"));
            checks.add(check(prefix + "round 1 related documents start at 0", "0", String.valueOf(scenarioRounds.get(0).relatedDocumentsCount()), scenarioRounds.get(0).relatedDocumentsCount() == 0, scenarioPromptSource(scenarioIndex, 0)));
            checks.add(check(prefix + "round 2 related documents reach >= 1", ">= 1", scenarioRounds.size() > 1 ? String.valueOf(scenarioRounds.get(1).relatedDocumentsCount()) : "missing", scenarioRounds.size() > 1 && scenarioRounds.get(1).relatedDocumentsCount() >= 1, scenarioPromptSource(scenarioIndex, 1)));
            checks.add(check(prefix + "round 3 related documents reach >= 2", ">= 2", scenarioRounds.size() > 2 ? String.valueOf(scenarioRounds.get(2).relatedDocumentsCount()) : "missing", scenarioRounds.size() > 2 && scenarioRounds.get(2).relatedDocumentsCount() >= 2, scenarioPromptSource(scenarioIndex, 2)));
            for (int index = 1; index < scenarioRounds.size(); index++) {
                RoundSnapshot previous = scenarioRounds.get(index - 1);
                RoundSnapshot current = scenarioRounds.get(index);
                checks.add(check(prefix + "round " + (index + 1) + " related documents do not regress", ">= " + previous.relatedDocumentsCount(), previous.relatedDocumentsCount() + " -> " + current.relatedDocumentsCount(), current.relatedDocumentsCount() >= previous.relatedDocumentsCount(), scenarioPromptSource(scenarioIndex, index)));
                checks.add(check(prefix + "round " + (index + 1) + " observation evidence does not regress", ">= " + previous.observationCount(), previous.observationCount() + " -> " + current.observationCount(), observationEvidenceMaintained(previous, current), scenarioAnalysisSource(scenarioIndex, index)));
            }
        }
        return List.copyOf(checks);
    }

    private RpiCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new RpiCheckResult(label, value(expected), value(actual), pass, source);
    }

    private Map<String, String> buildRequestFacts(
            RequestedTarget requestedTarget,
            String userId,
            int requestedRunCount,
            int horizonRounds,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            List<RoundSnapshot> rounds,
            OfficialVerificationContractMetadataSupport.ContractStatus contractStatus
    ) {
        List<List<RoundSnapshot>> scenarios = scenarioGroups(rounds);
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("verificationUser", value(userId));
        facts.put("requestedEndpointKey", value(requestedTarget.endpointKey()));
        facts.put("requestedResourceId", value(requestedTarget.resourceId()));
        facts.put("requestedRequestPath", value(requestedTarget.requestPath()));
        facts.put("scenarioSelector", SCENARIO_SELECTOR);
        facts.put("scenarioCount", String.valueOf(scenarios.size()));
        facts.put("scenarioKeys", String.join(",", scenarioKeys(scenarios)));
        facts.put("requestedRunCount", String.valueOf(requestedRunCount));
        facts.put("progressionRoundCount", String.valueOf(horizonRounds));
        facts.put("totalExecutedRounds", String.valueOf(rounds.size()));
        facts.put("firstRequestId", value(rounds.get(0).requestId()));
        facts.put("finalRequestId", value(rounds.get(rounds.size() - 1).requestId()));
        facts.put("rerun", rerun ? "yes" : "no");
        facts.put("contaminationSeed", contaminationSeed ? "enabled" : "disabled");
        facts.put("baselineSeedRequested", baselineSeedRequested ? "enabled" : "disabled");
        return OfficialVerificationContractMetadataSupport.withRequestFacts(facts, contractStatus);
    }

    private Map<String, String> buildEventFacts(List<RoundSnapshot> rounds) {
        List<List<RoundSnapshot>> scenarios = scenarioGroups(rounds);
        Map<String, String> facts = new LinkedHashMap<>();
        int totalEventCount = rounds.stream().mapToInt(round -> round.events().size()).sum();
        boolean decisionEventPresent = rounds.stream().flatMap(round -> round.events().stream()).anyMatch(item -> "DECISION_APPLIED".equalsIgnoreCase(item.type()));
        boolean requestParityAligned = rounds.stream().allMatch(RoundSnapshot::requestParityAligned);
        facts.put("scenarioCount", String.valueOf(scenarios.size()));
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
        List<List<RoundSnapshot>> scenarios = scenarioGroups(rounds);
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("scenarioRound1MinRelatedDocuments", String.valueOf(minRelatedDocumentsAt(scenarios, 0)));
        facts.put("scenarioRound2MinRelatedDocuments", String.valueOf(minRelatedDocumentsAt(scenarios, 1)));
        facts.put("scenarioRound3MinRelatedDocuments", String.valueOf(minRelatedDocumentsAt(scenarios, 2)));
        facts.put("allScenariosRelatedDocumentsNonDecreasing", Boolean.toString(allScenariosRelatedDocumentsNonDecreasing(scenarios)));
        facts.put("finalRelatedDocumentsMin", String.valueOf(minFinalRelatedDocuments(scenarios)));
        facts.put("lastRetrievalPurpose", value(text(rounds.get(rounds.size() - 1).promptPayload(), "retrievalPurpose")));
        facts.put("baselineContextScenarioCount", String.valueOf(scenarios.stream().filter(this::scenarioBaselineContextPresent).count()));
        return facts;
    }

    private Map<String, String> buildAnalysisFacts(List<RoundSnapshot> rounds) {
        List<List<RoundSnapshot>> scenarios = scenarioGroups(rounds);
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("scenarioRound1ObservationMin", String.valueOf(minObservationCountAt(scenarios, 0)));
        facts.put("scenarioRound2ObservationMin", String.valueOf(minObservationCountAt(scenarios, 1)));
        facts.put("scenarioRound3ObservationMin", String.valueOf(minObservationCountAt(scenarios, 2)));
        facts.put("allScenariosObservationCountNonDecreasing", Boolean.toString(allScenariosObservationCountsNonDecreasing(scenarios)));
        facts.put("finalObservationMin", String.valueOf(minFinalObservationCount(scenarios)));
        facts.put("baselineContextPresent", Boolean.toString(rounds.get(rounds.size() - 1).baselineContextPresent()));
        facts.put("finalWorkProfileSummary", value(rounds.get(rounds.size() - 1).workProfileSummary()));
        return facts;
    }

    private Map<String, Object> buildRawEvidence(
            RequestedTarget requestedTarget,
            String userId,
            int requestedRunCount,
            int horizonRounds,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            List<RoundSnapshot> rounds,
            OfficialVerificationContractMetadataSupport.ContractStatus contractStatus
    ) {
        List<List<RoundSnapshot>> scenarios = scenarioGroups(rounds);
        List<Map<String, Object>> roundEvidence = new ArrayList<>(rounds.size());
        for (RoundSnapshot round : rounds) {
            roundEvidence.add(buildRoundEvidence(round));
        }
        List<Map<String, Object>> scenarioEvidence = new ArrayList<>(scenarios.size());
        for (List<RoundSnapshot> scenarioRounds : scenarios) {
            scenarioEvidence.add(buildScenarioEvidence(scenarioRounds));
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("scenarioSelector", SCENARIO_SELECTOR);
        summary.put("scenarioCount", scenarios.size());
        summary.put("progressionRoundCount", horizonRounds);
        summary.put("totalExecutedRounds", rounds.size());
        summary.put("relatedDocumentsNonDecreasing", allScenariosRelatedDocumentsNonDecreasing(scenarios));
        summary.put("observationCountNonDecreasing", allScenariosObservationCountsNonDecreasing(scenarios));
        summary.put("baselineContextScenarioCount", scenarios.stream().filter(this::scenarioBaselineContextPresent).count());
        summary.put("requestParityAligned", rounds.stream().allMatch(RoundSnapshot::requestParityAligned));
        summary.put("finalRelatedDocumentsMin", minFinalRelatedDocuments(scenarios));
        summary.put("finalObservationMin", minFinalObservationCount(scenarios));
        summary.put("scenarioKeys", scenarioKeys(scenarios));

        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("requestedPreset", Map.of(
                "verificationUser", value(userId),
                "requestedEndpointKey", value(requestedTarget.endpointKey()),
                "requestedResourceId", value(requestedTarget.resourceId()),
                "requestedRequestPath", value(requestedTarget.requestPath()),
                "requestedRunCount", requestedRunCount,
                "progressionRoundCount", horizonRounds,
                "rerun", rerun,
                "contaminationSeed", contaminationSeed,
                "baselineSeedRequested", baselineSeedRequested
        ));
        evidence.put("contractExecution", Map.of(
                "scenarioSelector", SCENARIO_SELECTOR,
                "scenarioCount", scenarios.size(),
                "roundCountPerScenario", horizonRounds,
                "totalExecutedRounds", rounds.size()
        ));
        evidence.put("progressionSummary", Map.copyOf(summary));
        evidence.put("scenarios", List.copyOf(scenarioEvidence));
        evidence.put("rounds", List.copyOf(roundEvidence));
        return OfficialVerificationContractMetadataSupport.withRawEvidence(evidence, contractStatus);
    }

    private Map<String, Object> buildScenarioEvidence(List<RoundSnapshot> scenarioRounds) {
        RoundSnapshot first = scenarioRounds.get(0);
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("scenarioKey", first.plan().scenarioKey());
        evidence.put("scenarioFamily", first.plan().scenarioFamily());
        evidence.put("scenarioHeader", first.plan().scenarioHeader());
        evidence.put("expectedActionHeader", first.plan().expectedActionHeader());
        evidence.put("benchmarkRunId", first.plan().benchmarkRunId());
        evidence.put("verificationUserId", first.plan().verificationUserId());
        evidence.put("roundCount", scenarioRounds.size());
        evidence.put("relatedDocumentsNonDecreasing", relatedDocumentsNonDecreasing(scenarioRounds));
        evidence.put("observationCountNonDecreasing", observationCountsNonDecreasing(scenarioRounds));
        evidence.put("rounds", scenarioRounds.stream().map(this::buildRoundEvidence).toList());
        return evidence;
    }

    private Map<String, Object> buildRoundEvidence(RoundSnapshot round) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        Map<String, Object> roundPlan = new LinkedHashMap<>();
        roundPlan.put("roundKey", round.plan().roundKey());
        roundPlan.put("evaluationRound", round.plan().evaluationRound());
        roundPlan.put("behaviorPhase", round.plan().behaviorPhase());
        roundPlan.put("note", value(round.plan().note()));
        roundPlan.put("resourceId", round.plan().resourceId());
        roundPlan.put("requestPath", round.plan().requestPath());
        roundPlan.put("sessionMode", round.plan().sessionMode().name());
        roundPlan.put("sessionId", round.plan().sessionId());
        roundPlan.put("deviceAlias", round.plan().deviceAlias());
        roundPlan.put("deviceId", round.plan().deviceId());
        roundPlan.put("scenarioHeader", round.plan().scenarioHeader());
        roundPlan.put("expectedActionHeader", round.plan().expectedActionHeader());
        evidence.put("scenarioKey", round.plan().scenarioKey());
        evidence.put("scenarioFamily", round.plan().scenarioFamily());
        evidence.put("round", round.roundNumber());
        evidence.put("roundPlan", Map.copyOf(roundPlan));
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

    private List<List<RoundSnapshot>> scenarioGroups(List<RoundSnapshot> rounds) {
        LinkedHashMap<String, List<RoundSnapshot>> grouped = new LinkedHashMap<>();
        for (RoundSnapshot round : rounds) {
            grouped.computeIfAbsent(round.plan().scenarioKey(), ignored -> new ArrayList<>()).add(round);
        }
        return List.copyOf(grouped.values().stream().map(List::copyOf).toList());
    }

    private String scenarioPromptSource(int scenarioIndex, int roundIndex) {
        return "scenarios[" + scenarioIndex + "].rounds[" + roundIndex + "].promptAuditOutbox.payload.contexts";
    }

    private String scenarioAnalysisSource(int scenarioIndex, int roundIndex) {
        return "scenarios[" + scenarioIndex + "].rounds[" + roundIndex + "].decisionOutbox.payload.workProfileSummary";
    }

    private boolean hasNewAndReuseSessions(List<RoundSnapshot> rounds) {
        boolean hasNew = rounds.stream().anyMatch(round -> round.plan().sessionMode() == OfficialVerificationPromptContractSessionMode.NEW_SESSION);
        boolean hasReuse = rounds.stream().anyMatch(round -> round.plan().sessionMode() == OfficialVerificationPromptContractSessionMode.REUSE_SESSION);
        return hasNew && hasReuse;
    }

    private List<String> scenarioKeys(List<List<RoundSnapshot>> scenarios) {
        return scenarios.stream().map(item -> item.get(0).plan().scenarioKey()).toList();
    }

    private int minRelatedDocumentsAt(List<List<RoundSnapshot>> scenarios, int roundIndex) {
        return scenarios.stream().filter(item -> item.size() > roundIndex).mapToInt(item -> item.get(roundIndex).relatedDocumentsCount()).min().orElse(0);
    }

    private int minObservationCountAt(List<List<RoundSnapshot>> scenarios, int roundIndex) {
        return scenarios.stream().filter(item -> item.size() > roundIndex).mapToInt(item -> item.get(roundIndex).observationCount()).min().orElse(-1);
    }

    private int minFinalRelatedDocuments(List<List<RoundSnapshot>> scenarios) {
        return scenarios.stream().mapToInt(item -> item.get(item.size() - 1).relatedDocumentsCount()).min().orElse(0);
    }

    private int minFinalObservationCount(List<List<RoundSnapshot>> scenarios) {
        return scenarios.stream().mapToInt(item -> item.get(item.size() - 1).observationCount()).min().orElse(-1);
    }

    private boolean scenarioBaselineContextPresent(List<RoundSnapshot> rounds) {
        return rounds.stream().anyMatch(RoundSnapshot::baselineContextPresent);
    }

    private boolean allScenariosRelatedDocumentsNonDecreasing(List<List<RoundSnapshot>> scenarios) {
        return scenarios.stream().allMatch(this::relatedDocumentsNonDecreasing);
    }

    private boolean allScenariosObservationCountsNonDecreasing(List<List<RoundSnapshot>> scenarios) {
        return scenarios.stream().allMatch(this::observationCountsNonDecreasing);
    }

    private String buildMessage(double score, List<RoundSnapshot> rounds, OfficialVerificationContractMetadataSupport.ContractStatus contractStatus) {
        String baseMessage;
        List<List<RoundSnapshot>> scenarios = scenarioGroups(rounds);
        if (scenarios.isEmpty()) {
            baseMessage = "RPI could not resolve any long-horizon scenarios from the official contract.";
        }
        else if (score < 95.0d) {
            baseMessage = "RPI detected regression or insufficient accumulation across the configured long-horizon official scenario set.";
        }
        else {
            baseMessage = "RPI confirms that the configured long-horizon official scenario set preserves and grows retrieval and baseline evidence without regression.";
        }
        if (contractStatus != null && !contractStatus.structureAligned()) {
            return "PROVISIONAL SCORE ONLY. " + baseMessage + " Structural contract is not aligned with the starter TDD source of truth yet: " + contractStatus.structureMismatchReason();
        }
        return baseMessage;
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
            Map<String, Object> promptPayload,
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
        direct = extractObservationCount(text(promptPayload, "userPrompt"));
        if (direct >= 0) {
            return direct;
        }
        direct = extractObservationCount(text(promptPayload, "systemPrompt"));
        if (direct >= 0) {
            return direct;
        }
        direct = extractObservationCount(workProfileSummary);
        return direct >= 0 ? direct : -1;
    }

    private int extractObservationCount(String promptOrSummary) {
        if (!StringUtils.hasText(promptOrSummary)) {
            return -1;
        }
        String marker = "WorkProfileSummary: Window 7d | Observations ";
        int markerStart = promptOrSummary.indexOf(marker);
        if (markerStart >= 0) {
            int numberStart = markerStart + marker.length();
            int numberEnd = numberStart;
            while (numberEnd < promptOrSummary.length() && Character.isDigit(promptOrSummary.charAt(numberEnd))) {
                numberEnd++;
            }
            if (numberEnd > numberStart) {
                try {
                    return Integer.parseInt(promptOrSummary.substring(numberStart, numberEnd));
                }
                catch (NumberFormatException ignored) {
                    return -1;
                }
            }
        }
        for (Pattern pattern : List.of(OBSERVATIONS_PATTERN, OBSERVATIONS_KEY_VALUE_PATTERN, OBSERVATION_COUNT_PATTERN)) {
            Matcher matcher = pattern.matcher(promptOrSummary);
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
            Map<String, Object> promptPayload,
            String workProfileSummary
    ) {
        String userPrompt = text(promptPayload, "userPrompt");
        if (StringUtils.hasText(userPrompt)) {
            if (userPrompt.contains("=== OBSERVED WORK PATTERN CONTEXT ===")
                    || userPrompt.contains("WorkProfileSummary: Window 7d | Observations ")
                    || userPrompt.contains("PersonalBaselineStatus:")) {
                return true;
            }
        }
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

    private RpiEventItem toRpiEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new RpiEventItem(
                value(event.type()),
                value(event.layer()),
                value(event.status()),
                value(event.requestPath())
        );
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

    private String normalizeResourceId(String resourceId) {
        String normalized = StringUtils.hasText(resourceId) ? resourceId.trim() : "resource-001";
        normalized = normalized.replaceAll("[^A-Za-z0-9._-]", "-");
        return normalized.isBlank() ? "resource-001" : normalized;
    }

    private record RequestedTarget(String endpointKey, String resourceId, String requestPath) {
    }

    record ProgressionRoundPlan(
            String scenarioKey,
            String scenarioFamily,
            String scenarioHeader,
            String expectedActionHeader,
            String roundKey,
            String benchmarkRunId,
            String verificationUserId,
            String sessionId,
            int scenarioIndex,
            int roundNumber,
            String endpointKey,
            String endpointLabel,
            String resourceId,
            String requestPath,
            String clientIp,
            String browserUserAgent,
            String simulatedUserAgentLabel,
            String deviceAlias,
            String deviceId,
            Instant observedAt,
            OfficialVerificationPromptContractSessionMode sessionMode,
            long cooldownBeforeRoundMs,
            String behaviorPhase,
            String anomalySignal,
            String note,
            List<String> semanticMarkers
    ) {
        boolean initialRound() {
            return roundNumber == 1;
        }

        boolean evaluationRound() {
            return true;
        }

    }

    private record EndpointDefinition(String key, String label, String path, String resourceId) {
    }

    record RoundSnapshot(
            ProgressionRoundPlan plan,
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










