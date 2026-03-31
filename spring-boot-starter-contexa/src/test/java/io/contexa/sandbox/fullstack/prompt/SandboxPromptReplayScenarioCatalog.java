package io.contexa.sandbox.fullstack.prompt;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Official sandbox replay scenario catalog.
 *
 * The benchmark "when" must model long-running real user behavior, not a static path loop.
 * Each scenario below keeps the same authenticated account but changes selected context dimensions
 * across rounds to build a personal baseline and then inject subtle or abrupt deviations.
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

    private static final String CORP_LAN_IP = "192.168.1.100";
    private static final String CORP_WIFI_IP = "192.168.1.118";
    private static final String VPN_IP = "10.10.8.44";
    private static final String BRANCH_IP = "172.16.20.52";

    private static final String CHROME_RAW = SandboxFullStackPromptReplayHarness.DEFAULT_BROWSER_USER_AGENT;
    private static final String CHROME_LABEL = "Chrome 120 / Windows 11";
    private static final String EDGE_RAW =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " +
                    "Edg/120.0.0.0 Safari/537.36";
    private static final String EDGE_LABEL = "Edge 120 / Windows 11";
    private static final String CHROME_VDI_RAW =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; VDI) AppleWebKit/537.36 (KHTML, like Gecko) " +
                    "Chrome/120.0.0.0 Safari/537.36";
    private static final String CHROME_VDI_LABEL = "Chrome 120 / Windows 11 VDI";

    private static final long STEADY_GAP = 6_200L;
    private static final long SLOW_GAP = 8_800L;
    private static final long BURST_GAP = 5_200L;

    public static final SandboxPromptReplayScenario ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE =
            scenario(
                    "ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE",
                    FAMILY_RESOURCE_SURGE,
                    "Prompt should preserve a stable sensitive baseline before a same-user critical surge",
                    "ADMIN_SENSITIVE_RESOURCE_SURGE",
                    rounds(
                            baseline("R1", "/admin/api/security-test/sensitive/resource-001", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "stable-start"),
                            baseline("R2", "/admin/api/security-test/sensitive/resource-002", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "adjacent sensitive variation"),
                            baseline("R3", "/admin/api/security-test/sensitive/resource-001", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", SLOW_GAP, "repeat trusted sensitive asset"),
                            baseline("R4", "/admin/api/security-test/sensitive/resource-003", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "neighbor sensitive asset"),
                            baseline("R5", "/admin/api/security-test/sensitive/resource-002", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "stable sensitive baseline"),
                            anomaly("R6", "/admin/api/security-test/critical/resource-901", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "RESOURCE_SENSITIVITY_SURGE", "same user, same device, same IP but sudden critical scope jump"),
                            anomaly("R7", "/admin/api/security-test/critical/resource-902", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", BURST_GAP, "SUSTAINED_CRITICAL_SURGE", "critical access repeats before the newly formed trace settles"),
                            recovery("R8", "/admin/api/security-test/sensitive/resource-003", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "returns to known sensitive pattern after surge")));

    public static final SandboxPromptReplayScenario ADMIN_SENSITIVE_BASELINE_THEN_UNSEEN_SENSITIVE_FANOUT =
            scenario(
                    "ADMIN_SENSITIVE_BASELINE_THEN_UNSEEN_SENSITIVE_FANOUT",
                    FAMILY_RESOURCE_FANOUT,
                    "Prompt should retain the baseline and surface unusual fan-out into many unseen sensitive resources",
                    "ADMIN_SENSITIVE_RESOURCE_FANOUT",
                    rounds(
                            baseline("R1", "/admin/api/security-test/sensitive/resource-021", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "stable sensitive asset"),
                            baseline("R2", "/admin/api/security-test/sensitive/resource-022", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "repeat sensitive working set"),
                            baseline("R3", "/admin/api/security-test/sensitive/resource-021", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", SLOW_GAP, "return to trusted sensitive asset"),
                            baseline("R4", "/admin/api/security-test/sensitive/resource-023", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "third resource within known set"),
                            anomaly("R5", "/admin/api/security-test/sensitive/resource-071", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", BURST_GAP, "UNSEEN_RESOURCE_FANOUT", "same sensitivity and same device but new resource fan-out begins"),
                            anomaly("R6", "/admin/api/security-test/sensitive/resource-072", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", BURST_GAP, "UNSEEN_RESOURCE_FANOUT", "another unseen sensitive resource appears immediately"),
                            anomaly("R7", "/admin/api/security-test/sensitive/resource-073", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", BURST_GAP, "UNSEEN_RESOURCE_FANOUT", "fan-out persists without changing obvious coarse signals"),
                            recovery("R8", "/admin/api/security-test/sensitive/resource-022", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "returns to the long-running working set")));

    public static final SandboxPromptReplayScenario ADMIN_SENSITIVE_BASELINE_THEN_DEVICE_SHIFT_SAME_IP =
            scenario(
                    "ADMIN_SENSITIVE_BASELINE_THEN_DEVICE_SHIFT_SAME_IP",
                    FAMILY_DEVICE_SHIFT,
                    "Prompt should preserve same-user baseline and surface a device/fingerprint shift even when the IP stays constant",
                    "ADMIN_DEVICE_SHIFT_SAME_IP",
                    rounds(
                            baseline("R1", "/admin/api/security-test/sensitive/resource-031", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "baseline device A"),
                            baseline("R2", "/admin/api/security-test/sensitive/resource-032", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "baseline device A repeat"),
                            baseline("R3", "/admin/api/security-test/sensitive/resource-031", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", SLOW_GAP, "baseline device A revisit"),
                            baseline("R4", "/admin/api/security-test/sensitive/resource-033", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "baseline device A adjacent resource"),
                            anomaly("R5", "/admin/api/security-test/sensitive/resource-033", CORP_LAN_IP, EDGE_RAW, EDGE_LABEL, "corp-laptop-b", STEADY_GAP, "DEVICE_FINGERPRINT_SHIFT", "same user and same IP, but browser/device fingerprint changes"),
                            anomaly("R6", "/admin/api/security-test/sensitive/resource-031", CORP_LAN_IP, EDGE_RAW, EDGE_LABEL, "corp-laptop-b", BURST_GAP, "DEVICE_FINGERPRINT_SHIFT", "shifted device immediately accesses an old sensitive asset"),
                            recovery("R7", "/admin/api/security-test/sensitive/resource-032", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "returns to original device"),
                            recovery("R8", "/admin/api/security-test/sensitive/resource-031", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "baseline device restored")));

    public static final SandboxPromptReplayScenario ADMIN_SENSITIVE_BASELINE_THEN_VPN_PIVOT_SAME_DEVICE =
            scenario(
                    "ADMIN_SENSITIVE_BASELINE_THEN_VPN_PIVOT_SAME_DEVICE",
                    FAMILY_NETWORK_PIVOT,
                    "Prompt should surface a network pivot while keeping the same account, device and work scope",
                    "ADMIN_NETWORK_PIVOT",
                    rounds(
                            baseline("R1", "/admin/api/security-test/sensitive/resource-041", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "corp LAN baseline"),
                            baseline("R2", "/admin/api/security-test/sensitive/resource-042", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "corp LAN working set"),
                            baseline("R3", "/admin/api/security-test/sensitive/resource-041", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", SLOW_GAP, "corp LAN revisit"),
                            baseline("R4", "/admin/api/security-test/sensitive/resource-043", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "corp LAN adjacent resource"),
                            anomaly("R5", "/admin/api/security-test/sensitive/resource-043", VPN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "NETWORK_PIVOT", "same user and same device pivot to VPN source"),
                            anomaly("R6", "/admin/api/security-test/sensitive/resource-041", BRANCH_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", BURST_GAP, "NETWORK_PIVOT", "same device moves again while work scope stays similar"),
                            recovery("R7", "/admin/api/security-test/sensitive/resource-042", CORP_WIFI_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "returns to an internal network but not the original IP"),
                            recovery("R8", "/admin/api/security-test/sensitive/resource-041", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "returns to original corp LAN baseline")));

    public static final SandboxPromptReplayScenario ADMIN_SENSITIVE_BASELINE_THEN_CADENCE_BURST =
            scenario(
                    "ADMIN_SENSITIVE_BASELINE_THEN_CADENCE_BURST",
                    FAMILY_CADENCE_BURST,
                    "Prompt should surface an abnormal request burst even when user, device, IP and resource family stay almost unchanged",
                    "ADMIN_CADENCE_BURST",
                    rounds(
                            baseline("R1", "/admin/api/security-test/sensitive/resource-051", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", SLOW_GAP, "slow steady baseline"),
                            baseline("R2", "/admin/api/security-test/sensitive/resource-052", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", SLOW_GAP, "slow steady baseline"),
                            baseline("R3", "/admin/api/security-test/sensitive/resource-051", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", SLOW_GAP, "slow revisit"),
                            baseline("R4", "/admin/api/security-test/sensitive/resource-052", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", SLOW_GAP, "slow revisit"),
                            anomaly("R5", "/admin/api/security-test/sensitive/resource-051", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", BURST_GAP, "CADENCE_BURST", "same asset starts repeating at the fastest allowed replay cadence"),
                            anomaly("R6", "/admin/api/security-test/sensitive/resource-052", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", BURST_GAP, "CADENCE_BURST", "paired resource repeats without the usual dwell"),
                            anomaly("R7", "/admin/api/security-test/sensitive/resource-051", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", BURST_GAP, "CADENCE_BURST", "burst persists while other coarse signals remain stable"),
                            recovery("R8", "/admin/api/security-test/sensitive/resource-052", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", SLOW_GAP, "returns to normal dwell pattern")));

    public static final SandboxPromptReplayScenario ADMIN_NORMAL_SENSITIVE_BASELINE_THEN_SEQUENCE_REVERSAL =
            scenario(
                    "ADMIN_NORMAL_SENSITIVE_BASELINE_THEN_SEQUENCE_REVERSAL",
                    FAMILY_SEQUENCE_REVERSAL,
                    "Prompt should preserve the learned task order and surface a reversed sequence for the same user",
                    "ADMIN_SEQUENCE_REVERSAL",
                    rounds(
                            baseline("R1", "/admin/api/security-test/normal/resource-061", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "normal pre-check"),
                            baseline("R2", "/admin/api/security-test/sensitive/resource-061", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "sensitive follow-up"),
                            baseline("R3", "/admin/api/security-test/normal/resource-062", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "second normal pre-check"),
                            baseline("R4", "/admin/api/security-test/sensitive/resource-062", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "second sensitive follow-up"),
                            baseline("R5", "/admin/api/security-test/sensitive/resource-061", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", SLOW_GAP, "stable mixed baseline"),
                            anomaly("R6", "/admin/api/security-test/critical/resource-061", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "SEQUENCE_REVERSAL", "critical step appears before the usual normal/sensitive preparation order"),
                            anomaly("R7", "/admin/api/security-test/normal/resource-061", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", BURST_GAP, "SEQUENCE_REVERSAL", "sequence snaps back to normal immediately after the critical jump"),
                            recovery("R8", "/admin/api/security-test/sensitive/resource-062", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "returns to the learned order")));

    public static final SandboxPromptReplayScenario ADMIN_MIXED_SCOPE_BASELINE_THEN_LATE_CRITICAL_APPROVAL =
            scenario(
                    "ADMIN_MIXED_SCOPE_BASELINE_THEN_LATE_CRITICAL_APPROVAL",
                    FAMILY_LATE_ESCALATION,
                    "Prompt should accumulate a broad baseline before a late critical approval event on the same account",
                    "ADMIN_LATE_CRITICAL_APPROVAL",
                    rounds(
                            baseline("R1", "/admin/api/security-test/normal/resource-071", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "mixed baseline normal start"),
                            baseline("R2", "/admin/api/security-test/sensitive/resource-071", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "mixed baseline sensitive follow-up"),
                            baseline("R3", "/admin/api/security-test/normal/resource-072", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", SLOW_GAP, "mixed baseline secondary normal"),
                            baseline("R4", "/admin/api/security-test/sensitive/resource-072", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "mixed baseline secondary sensitive"),
                            baseline("R5", "/admin/api/security-test/sensitive/resource-073", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "stable sensitive expansion"),
                            baseline("R6", "/admin/api/security-test/normal/resource-071", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", SLOW_GAP, "returns to normal checkpoint"),
                            anomaly("R7", "/admin/api/security-test/critical/resource-771", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "LATE_CRITICAL_APPROVAL", "critical approval lands only after a rich multi-resource baseline exists"),
                            recovery("R8", "/admin/api/security-test/sensitive/resource-073", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a", STEADY_GAP, "falls back to established sensitive work")));

    public static final SandboxPromptReplayScenario ADMIN_CRITICAL_BASELINE_THEN_NORMALIZED_RECOVERY =
            scenario(
                    "ADMIN_CRITICAL_BASELINE_THEN_NORMALIZED_RECOVERY",
                    FAMILY_RECOVERY,
                    "Prompt should learn a critical-heavy baseline and still preserve a temporary normalization detour",
                    "ADMIN_CRITICAL_BASELINE_RECOVERY",
                    rounds(
                            baseline("R1", "/admin/api/security-test/critical/resource-081", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "managed-vdi", STEADY_GAP, "critical-heavy baseline start"),
                            baseline("R2", "/admin/api/security-test/critical/resource-082", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "managed-vdi", STEADY_GAP, "critical-heavy baseline second asset"),
                            baseline("R3", "/admin/api/security-test/sensitive/resource-081", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "managed-vdi", SLOW_GAP, "sensitive subtask inside critical profile"),
                            baseline("R4", "/admin/api/security-test/critical/resource-083", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "managed-vdi", STEADY_GAP, "critical profile continues"),
                            baseline("R5", "/admin/api/security-test/critical/resource-082", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "managed-vdi", STEADY_GAP, "critical revisit"),
                            anomaly("R6", "/admin/api/security-test/normal/resource-081", CORP_LAN_IP, CHROME_VDI_RAW, CHROME_VDI_LABEL, "managed-vdi", STEADY_GAP, "TEMPORARY_NORMALIZATION", "same user temporarily detours to a low-sensitivity scope unusual for this profile"),
                            anomaly("R7", "/admin/api/security-test/normal/resource-082", CORP_LAN_IP, CHROME_VDI_RAW, CHROME_VDI_LABEL, "managed-vdi", BURST_GAP, "TEMPORARY_NORMALIZATION", "normal detour persists long enough to require explanation in prompt"),
                            recovery("R8", "/admin/api/security-test/critical/resource-081", CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "managed-vdi", STEADY_GAP, "critical baseline restored")));

    private static final List<SandboxPromptReplayScenario> ALL_SCENARIOS = List.of(
            ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE,
            ADMIN_SENSITIVE_BASELINE_THEN_UNSEEN_SENSITIVE_FANOUT,
            ADMIN_SENSITIVE_BASELINE_THEN_DEVICE_SHIFT_SAME_IP,
            ADMIN_SENSITIVE_BASELINE_THEN_VPN_PIVOT_SAME_DEVICE,
            ADMIN_SENSITIVE_BASELINE_THEN_CADENCE_BURST,
            ADMIN_NORMAL_SENSITIVE_BASELINE_THEN_SEQUENCE_REVERSAL,
            ADMIN_MIXED_SCOPE_BASELINE_THEN_LATE_CRITICAL_APPROVAL,
            ADMIN_CRITICAL_BASELINE_THEN_NORMALIZED_RECOVERY);

    private static final Map<String, SandboxPromptReplayScenario> BY_KEY = ALL_SCENARIOS.stream()
            .collect(LinkedHashMap::new,
                    (map, scenario) -> map.put(scenario.scenarioKey(), scenario),
                    LinkedHashMap::putAll);

    private SandboxPromptReplayScenarioCatalog() {
    }

    public static List<SandboxPromptReplayScenario> defaultScenarios() {
        return List.of(ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE);
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

    private static List<SandboxPromptRoundPlan> rounds(SandboxPromptRoundPlan... roundPlans) {
        return List.of(roundPlans);
    }

    private static SandboxPromptRoundPlan baseline(
            String roundKey,
            String requestPath,
            String clientIp,
            String browserUserAgent,
            String simulatedUserAgentLabel,
            String deviceAlias,
            long cooldownBeforeRoundMs,
            String expectationNote) {
        return round(
                roundKey,
                requestPath,
                clientIp,
                browserUserAgent,
                simulatedUserAgentLabel,
                deviceAlias,
                cooldownBeforeRoundMs,
                "BASELINE",
                "NONE",
                expectationNote,
                List.of("EXPECT_HISTORY_BUILDUP", "EXPECT_RAG_ACCUMULATION"));
    }

    private static SandboxPromptRoundPlan anomaly(
            String roundKey,
            String requestPath,
            String clientIp,
            String browserUserAgent,
            String simulatedUserAgentLabel,
            String deviceAlias,
            long cooldownBeforeRoundMs,
            String anomalySignal,
            String expectationNote) {
        return round(
                roundKey,
                requestPath,
                clientIp,
                browserUserAgent,
                simulatedUserAgentLabel,
                deviceAlias,
                cooldownBeforeRoundMs,
                "ANOMALY",
                anomalySignal,
                expectationNote,
                List.of("EXPECT_HISTORY_CONTRAST", "EXPECT_PREVIOUS_PATH", "EXPECT_OBSERVED_WORK_PATTERN"));
    }

    private static SandboxPromptRoundPlan recovery(
            String roundKey,
            String requestPath,
            String clientIp,
            String browserUserAgent,
            String simulatedUserAgentLabel,
            String deviceAlias,
            long cooldownBeforeRoundMs,
            String expectationNote) {
        return round(
                roundKey,
                requestPath,
                clientIp,
                browserUserAgent,
                simulatedUserAgentLabel,
                deviceAlias,
                cooldownBeforeRoundMs,
                "RECOVERY",
                "NONE",
                expectationNote,
                List.of("EXPECT_HISTORY_PRESERVATION", "EXPECT_RAG_ACCUMULATION"));
    }

    private static SandboxPromptRoundPlan round(
            String roundKey,
            String requestPath,
            String clientIp,
            String browserUserAgent,
            String simulatedUserAgentLabel,
            String deviceAlias,
            long cooldownBeforeRoundMs,
            String behaviorPhase,
            String anomalySignal,
            String expectationNote,
            List<String> semanticMarkers) {
        return new SandboxPromptRoundPlan(
                roundKey,
                requestPath,
                clientIp,
                browserUserAgent,
                simulatedUserAgentLabel,
                deviceAlias,
                cooldownBeforeRoundMs,
                behaviorPhase,
                anomalySignal,
                expectationNote,
                semanticMarkers);
    }
}
