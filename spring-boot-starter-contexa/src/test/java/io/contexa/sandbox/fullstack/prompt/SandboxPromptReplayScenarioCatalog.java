package io.contexa.sandbox.fullstack.prompt;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Official sandbox replay scenario catalog.
 *
 * The benchmark "when" must model long-running real user behavior, not a static path loop.
 * Each scenario keeps the same authenticated account and builds a multi-session personal baseline
 * across weeks before injecting subtle or abrupt deviations.
 */
public final class SandboxPromptReplayScenarioCatalog {

    private static final String DEFAULT_SCENARIO_HEADER = "NORMAL_USER";
    private static final String DEFAULT_EXPERIMENT_GROUP = "WEBCLIENT_FULLSTACK_BEHAVIOR_BENCHMARK";

    private static final String FAMILY_RESOURCE_SURGE = "RESOURCE_SURGE";
    private static final String FAMILY_RESOURCE_FANOUT = "RESOURCE_FANOUT";
    private static final String FAMILY_DEVICE_SHIFT = "DEVICE_SHIFT";
    private static final String FAMILY_NETWORK_PIVOT = "NETWORK_PIVOT";
    private static final String FAMILY_CADENCE_BURST = "CADENCE_BURST";
    private static final String FAMILY_SEQUENCE_REVERSAL = "SEQUENCE_REVERSAL";
    private static final String FAMILY_LATE_ESCALATION = "LATE_ESCALATION";
    private static final String FAMILY_RECOVERY = "RECOVERY";
    private static final String FAMILY_SPARSE_EVIDENCE = "SPARSE_EVIDENCE";
    private static final String FAMILY_CONFLICTING_CONTEXT = "CONFLICTING_CONTEXT";
    private static final String FAMILY_PARTIAL_MEMORY = "PARTIAL_MEMORY";
    private static final String FAMILY_APPROVAL_AMBIGUITY = "APPROVAL_AMBIGUITY";

    public static final SandboxPromptReplayScenario ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE =
            scenario(
                    "ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE",
                    FAMILY_RESOURCE_SURGE,
                    "Prompt should preserve a long-running sensitive baseline before a same-user critical surge",
                    "ADMIN_SENSITIVE_RESOURCE_SURGE",
                    SandboxPromptLongHorizonScenarioFactory.buildResourceSurgeRounds());

    public static final SandboxPromptReplayScenario ADMIN_SENSITIVE_BASELINE_THEN_UNSEEN_SENSITIVE_FANOUT =
            scenario(
                    "ADMIN_SENSITIVE_BASELINE_THEN_UNSEEN_SENSITIVE_FANOUT",
                    FAMILY_RESOURCE_FANOUT,
                    "Prompt should preserve the baseline and surface unusual fan-out into many unseen sensitive resources",
                    "ADMIN_SENSITIVE_RESOURCE_FANOUT",
                    SandboxPromptLongHorizonScenarioFactory.buildResourceFanoutRounds());

    public static final SandboxPromptReplayScenario ADMIN_SENSITIVE_BASELINE_THEN_DEVICE_SHIFT_SAME_IP =
            scenario(
                    "ADMIN_SENSITIVE_BASELINE_THEN_DEVICE_SHIFT_SAME_IP",
                    FAMILY_DEVICE_SHIFT,
                    "Prompt should preserve same-user baseline and surface a device shift even when IP and work scope stay stable",
                    "ADMIN_DEVICE_SHIFT_SAME_IP",
                    SandboxPromptLongHorizonScenarioFactory.buildDeviceShiftRounds());

    public static final SandboxPromptReplayScenario ADMIN_SENSITIVE_BASELINE_THEN_VPN_PIVOT_SAME_DEVICE =
            scenario(
                    "ADMIN_SENSITIVE_BASELINE_THEN_VPN_PIVOT_SAME_DEVICE",
                    FAMILY_NETWORK_PIVOT,
                    "Prompt should surface a network pivot while keeping the same account, device and work scope",
                    "ADMIN_NETWORK_PIVOT",
                    SandboxPromptLongHorizonScenarioFactory.buildNetworkPivotRounds());

    public static final SandboxPromptReplayScenario ADMIN_SENSITIVE_BASELINE_THEN_CADENCE_BURST =
            scenario(
                    "ADMIN_SENSITIVE_BASELINE_THEN_CADENCE_BURST",
                    FAMILY_CADENCE_BURST,
                    "Prompt should surface an abnormal cadence burst even when account, device, IP and resource family stay almost unchanged",
                    "ADMIN_CADENCE_BURST",
                    SandboxPromptLongHorizonScenarioFactory.buildCadenceBurstRounds());

    public static final SandboxPromptReplayScenario ADMIN_NORMAL_SENSITIVE_BASELINE_THEN_SEQUENCE_REVERSAL =
            scenario(
                    "ADMIN_NORMAL_SENSITIVE_BASELINE_THEN_SEQUENCE_REVERSAL",
                    FAMILY_SEQUENCE_REVERSAL,
                    "Prompt should preserve the learned task order and surface a reversed sequence for the same user",
                    "ADMIN_SEQUENCE_REVERSAL",
                    SandboxPromptLongHorizonScenarioFactory.buildSequenceReversalRounds());

    public static final SandboxPromptReplayScenario ADMIN_MIXED_SCOPE_BASELINE_THEN_LATE_CRITICAL_APPROVAL =
            scenario(
                    "ADMIN_MIXED_SCOPE_BASELINE_THEN_LATE_CRITICAL_APPROVAL",
                    FAMILY_LATE_ESCALATION,
                    "Prompt should accumulate a broad baseline before a late critical escalation on the same account",
                    "ADMIN_LATE_CRITICAL_APPROVAL",
                    SandboxPromptLongHorizonScenarioFactory.buildLateEscalationRounds());

    public static final SandboxPromptReplayScenario ADMIN_CRITICAL_BASELINE_THEN_NORMALIZED_RECOVERY =
            scenario(
                    "ADMIN_CRITICAL_BASELINE_THEN_NORMALIZED_RECOVERY",
                    FAMILY_RECOVERY,
                    "Prompt should learn a critical-heavy baseline and still preserve a temporary normalization detour",
                    "ADMIN_CRITICAL_BASELINE_RECOVERY",
                    SandboxPromptLongHorizonScenarioFactory.buildRecoveryRounds());

    public static final SandboxPromptReplayScenario ADMIN_SPARSE_HISTORY_THEN_HIGH_VALUE_REENTRY =
            scenario(
                    "ADMIN_SPARSE_HISTORY_THEN_HIGH_VALUE_REENTRY",
                    FAMILY_SPARSE_EVIDENCE,
                    "Decision benchmark should keep safe uncertainty when the same account re-enters a high-value path with sparse comparable history",
                    "ADMIN_SPARSE_EVIDENCE_PROFILE",
                    SandboxPromptLongHorizonScenarioFactory.buildSparseEvidenceRounds());

    public static final SandboxPromptReplayScenario ADMIN_STEADY_BASELINE_THEN_CONFLICTING_CONTEXT =
            scenario(
                    "ADMIN_STEADY_BASELINE_THEN_CONFLICTING_CONTEXT",
                    FAMILY_CONFLICTING_CONTEXT,
                    "Decision benchmark should handle mixed network, device and scope signals without overconfident reasoning",
                    "ADMIN_CONFLICTING_CONTEXT_PROFILE",
                    SandboxPromptLongHorizonScenarioFactory.buildConflictingContextRounds());

    public static final SandboxPromptReplayScenario ADMIN_WIDE_FANOUT_THEN_PARTIAL_MEMORY_REENTRY =
            scenario(
                    "ADMIN_WIDE_FANOUT_THEN_PARTIAL_MEMORY_REENTRY",
                    FAMILY_PARTIAL_MEMORY,
                    "Decision benchmark should stay grounded when comparable memory is partial and path-specific recall is thin",
                    "ADMIN_PARTIAL_MEMORY_PROFILE",
                    SandboxPromptLongHorizonScenarioFactory.buildPartialMemoryRounds());

    public static final SandboxPromptReplayScenario ADMIN_MIXED_SCOPE_THEN_APPROVAL_AMBIGUITY =
            scenario(
                    "ADMIN_MIXED_SCOPE_THEN_APPROVAL_AMBIGUITY",
                    FAMILY_APPROVAL_AMBIGUITY,
                    "Decision benchmark should avoid overconfident approval assumptions when critical scope appears under thin approval lineage",
                    "ADMIN_APPROVAL_AMBIGUITY_PROFILE",
                    SandboxPromptLongHorizonScenarioFactory.buildApprovalAmbiguityRounds());

    private static final List<SandboxPromptReplayScenario> ALL_SCENARIOS = List.of(
            ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE,
            ADMIN_SENSITIVE_BASELINE_THEN_UNSEEN_SENSITIVE_FANOUT,
            ADMIN_SENSITIVE_BASELINE_THEN_DEVICE_SHIFT_SAME_IP,
            ADMIN_SENSITIVE_BASELINE_THEN_VPN_PIVOT_SAME_DEVICE,
            ADMIN_SENSITIVE_BASELINE_THEN_CADENCE_BURST,
            ADMIN_NORMAL_SENSITIVE_BASELINE_THEN_SEQUENCE_REVERSAL,
            ADMIN_MIXED_SCOPE_BASELINE_THEN_LATE_CRITICAL_APPROVAL,
            ADMIN_CRITICAL_BASELINE_THEN_NORMALIZED_RECOVERY);

    private static final List<SandboxPromptReplayScenario> DECISION_AMBIGUITY_SCENARIOS = List.of(
            ADMIN_SPARSE_HISTORY_THEN_HIGH_VALUE_REENTRY,
            ADMIN_STEADY_BASELINE_THEN_CONFLICTING_CONTEXT,
            ADMIN_WIDE_FANOUT_THEN_PARTIAL_MEMORY_REENTRY,
            ADMIN_MIXED_SCOPE_THEN_APPROVAL_AMBIGUITY);

    private static final List<SandboxPromptReplayScenario> DECISION_OFFICIAL_SCENARIOS =
            concat(ALL_SCENARIOS, DECISION_AMBIGUITY_SCENARIOS);

    private static final Map<String, SandboxPromptReplayScenario> BY_KEY = DECISION_OFFICIAL_SCENARIOS.stream()
            .collect(LinkedHashMap::new,
                    (map, scenario) -> map.put(scenario.scenarioKey(), scenario),
                    LinkedHashMap::putAll);

    private SandboxPromptReplayScenarioCatalog() {
    }

    public static List<SandboxPromptReplayScenario> defaultScenarios() {
        return coreScenarioSet();
    }

    public static List<SandboxPromptReplayScenario> coreScenarioSet() {
        return List.of(
                ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE,
                ADMIN_SENSITIVE_BASELINE_THEN_UNSEEN_SENSITIVE_FANOUT,
                ADMIN_SENSITIVE_BASELINE_THEN_DEVICE_SHIFT_SAME_IP,
                ADMIN_NORMAL_SENSITIVE_BASELINE_THEN_SEQUENCE_REVERSAL);
    }

    public static List<SandboxPromptReplayScenario> extendedScenarioSet() {
        return ALL_SCENARIOS;
    }

    public static List<SandboxPromptReplayScenario> ambiguityScenarioSet() {
        return DECISION_AMBIGUITY_SCENARIOS;
    }

    public static List<SandboxPromptReplayScenario> decisionOfficialScenarioSet() {
        return DECISION_OFFICIAL_SCENARIOS;
    }

    public static List<SandboxPromptReplayScenario> resolve(String selector) {
        if (selector == null || selector.isBlank()) {
            return defaultScenarios();
        }
        String normalized = selector.trim().toUpperCase(Locale.ROOT);
        if ("DEFAULT".equals(normalized)) {
            return defaultScenarios();
        }
        if ("CORE".equals(normalized)) {
            return coreScenarioSet();
        }
        if ("EXTENDED".equals(normalized) || "ALL".equals(normalized)) {
            return extendedScenarioSet();
        }
        if ("AMBIGUITY".equals(normalized) || "DECISION_AMBIGUITY".equals(normalized)) {
            return ambiguityScenarioSet();
        }
        if ("DECISION".equals(normalized) || "DECISION_OFFICIAL".equals(normalized)) {
            return decisionOfficialScenarioSet();
        }

        LinkedHashMap<String, SandboxPromptReplayScenario> resolved = new LinkedHashMap<>();
        for (String token : selector.split(",")) {
            String key = token == null ? "" : token.trim().toUpperCase(Locale.ROOT);
            if (key.isBlank()) {
                continue;
            }
            SandboxPromptReplayScenario scenario = BY_KEY.get(key);
            if (scenario == null) {
                throw new IllegalArgumentException("Unknown sandbox replay scenario: " + token);
            }
            resolved.put(scenario.scenarioKey(), scenario);
        }
        if (resolved.isEmpty()) {
            throw new IllegalArgumentException("No sandbox replay scenarios resolved from selector: " + selector);
        }
        return List.copyOf(resolved.values());
    }

    public static SandboxPromptReplayScenario resizeScenario(SandboxPromptReplayScenario scenario, int roundCount) {
        if (scenario == null) {
            throw new IllegalArgumentException("scenario must not be null");
        }
        if (roundCount < 3) {
            throw new IllegalArgumentException("roundCount must be at least 3");
        }
        if (scenario.roundCount() == roundCount) {
            return scenario;
        }
        if (roundCount < scenario.roundCount()) {
            return new SandboxPromptReplayScenario(
                    scenario.scenarioKey(),
                    scenario.experimentGroup(),
                    scenario.scenarioHeader(),
                    scenario.expectedActionHeader(),
                    scenario.userProfileKey(),
                    scenario.scenarioFamily(),
                    scenario.roundPlans().subList(0, roundCount));
        }

        ArrayList<SandboxPromptRoundPlan> expanded = new ArrayList<>(scenario.roundPlans());
        int templateIndex = 0;
        int weekOffset = 4;
        while (expanded.size() < roundCount) {
            SandboxPromptRoundPlan template = scenario.roundPlans().get(templateIndex % scenario.roundCount());
            OffsetDateTime observedAt = template.observedAt().plusWeeks(weekOffset);
            expanded.add(new SandboxPromptRoundPlan(
                    String.format(Locale.ROOT, "R%02d", expanded.size() + 1),
                    template.requestPath(),
                    template.clientIp(),
                    template.browserUserAgent(),
                    template.simulatedUserAgentLabel(),
                    template.deviceAlias(),
                    observedAt,
                    template.sessionMode(),
                    template.cooldownBeforeRoundMs(),
                    template.behaviorPhase(),
                    template.anomalySignal(),
                    template.expectationNote(),
                    template.semanticMarkers()));
            templateIndex++;
            if (templateIndex % scenario.roundCount() == 0) {
                weekOffset += 4;
            }
        }

        return new SandboxPromptReplayScenario(
                scenario.scenarioKey(),
                scenario.experimentGroup(),
                scenario.scenarioHeader(),
                scenario.expectedActionHeader(),
                scenario.userProfileKey(),
                scenario.scenarioFamily(),
                List.copyOf(expanded));
    }

    private static SandboxPromptReplayScenario scenario(
            String scenarioKey,
            String scenarioFamily,
            String expectedActionHeader,
            String userProfileKey,
            List<SandboxPromptRoundPlan> roundPlans) {
        return new SandboxPromptReplayScenario(
                scenarioKey,
                DEFAULT_EXPERIMENT_GROUP,
                DEFAULT_SCENARIO_HEADER,
                expectedActionHeader,
                userProfileKey,
                scenarioFamily,
                roundPlans);
    }

    private static List<SandboxPromptReplayScenario> concat(
            List<SandboxPromptReplayScenario> left,
            List<SandboxPromptReplayScenario> right) {
        ArrayList<SandboxPromptReplayScenario> merged = new ArrayList<>(left.size() + right.size());
        merged.addAll(left);
        merged.addAll(right);
        return List.copyOf(merged);
    }
}
