package io.contexa.sandbox.fullstack.prompt;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class SandboxPromptLongHorizonScenarioFactory {

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

    private static final long STEADY_GAP = 800L;
    private static final long SLOW_GAP = 1_000L;
    private static final long BURST_GAP = 250L;

    private static final LocalDate BASE_MONDAY = LocalDate.of(2026, 1, 5);
    private static final ZoneOffset SEOUL_OFFSET = ZoneOffset.ofHours(9);

    private SandboxPromptLongHorizonScenarioFactory() {
    }

    static List<SandboxPromptRoundPlan> buildResourceSurgeRounds() {
        ArrayList<SandboxPromptRoundPlan> rounds = new ArrayList<>();
        addBaselineSession(rounds, 0, DayOfWeek.MONDAY, 9, 5, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-001",
                "/admin/api/security-test/sensitive/resource-002",
                "stable sensitive working pair");
        addBaselineSession(rounds, 0, DayOfWeek.WEDNESDAY, 10, 12, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-003",
                "/admin/api/security-test/sensitive/resource-001",
                "mid-week sensitive review");
        addBaselineSession(rounds, 0, DayOfWeek.FRIDAY, 14, 8, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-002",
                "/admin/api/security-test/sensitive/resource-003",
                "end-of-week sensitive checkpoint");

        addBaselineSession(rounds, 1, DayOfWeek.MONDAY, 9, 3, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-001",
                "/admin/api/security-test/sensitive/resource-003",
                "same time window with adjacent sensitive asset");
        addBaselineSession(rounds, 1, DayOfWeek.WEDNESDAY, 10, 15, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-002",
                "/admin/api/security-test/sensitive/resource-001",
                "mid-week repetition");
        addBaselineSession(rounds, 1, DayOfWeek.FRIDAY, 14, 11, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-003",
                "/admin/api/security-test/sensitive/resource-002",
                "stable sensitive closure");

        addBaselineSession(rounds, 2, DayOfWeek.MONDAY, 9, 6, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-001",
                "/admin/api/security-test/sensitive/resource-002",
                "baseline now spans multiple weeks");
        addBaselineSession(rounds, 2, DayOfWeek.WEDNESDAY, 10, 10, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-003",
                "/admin/api/security-test/sensitive/resource-001",
                "mid-week rhythm remains steady");
        addBaselineSession(rounds, 2, DayOfWeek.FRIDAY, 14, 6, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-002",
                "/admin/api/security-test/sensitive/resource-003",
                "three-week sensitive baseline established");

        addAnomalySession(rounds, 3, DayOfWeek.MONDAY, 9, 4, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-001",
                "/admin/api/security-test/critical/resource-901",
                "RESOURCE_SENSITIVITY_SURGE",
                "same user, same time, same device and same IP but critical scope suddenly appears");
        addAnomalySession(rounds, 3, DayOfWeek.WEDNESDAY, 10, 14, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-002",
                "/admin/api/security-test/critical/resource-902",
                "RESOURCE_SENSITIVITY_SURGE",
                "critical access repeats before the user re-establishes a new pattern");
        addRecoverySession(rounds, 3, DayOfWeek.FRIDAY, 14, 9, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-003",
                "/admin/api/security-test/sensitive/resource-001",
                "returns to known sensitive working set after surge");
        return List.copyOf(rounds);
    }

    static List<SandboxPromptRoundPlan> buildResourceFanoutRounds() {
        ArrayList<SandboxPromptRoundPlan> rounds = new ArrayList<>();
        for (int week = 0; week < 3; week++) {
            addBaselineSession(rounds, week, DayOfWeek.MONDAY, 9, 10 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-021",
                    "/admin/api/security-test/sensitive/resource-022",
                    "stable sensitive working pair");
            addBaselineSession(rounds, week, DayOfWeek.WEDNESDAY, 10, 18 - week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-023",
                    "/admin/api/security-test/sensitive/resource-021",
                    "known three-resource working set");
            addBaselineSession(rounds, week, DayOfWeek.FRIDAY, 14, 14 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-022",
                    "/admin/api/security-test/sensitive/resource-023",
                    "end-of-week sensitive cycle");
        }
        addAnomalySession(rounds, 3, DayOfWeek.MONDAY, 9, 12, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-021",
                "/admin/api/security-test/sensitive/resource-071",
                "UNSEEN_RESOURCE_FANOUT",
                "same sensitivity and same coarse signals but a new sensitive cluster begins");
        addAnomalySession(rounds, 3, DayOfWeek.WEDNESDAY, 10, 16, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-022",
                "/admin/api/security-test/sensitive/resource-072",
                "UNSEEN_RESOURCE_FANOUT",
                "unseen resource fan-out persists without changing device or IP");
        addRecoverySession(rounds, 3, DayOfWeek.FRIDAY, 14, 12, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-023",
                "/admin/api/security-test/sensitive/resource-022",
                "falls back to long-running resource set after fan-out");
        return List.copyOf(rounds);
    }

    static List<SandboxPromptRoundPlan> buildDeviceShiftRounds() {
        ArrayList<SandboxPromptRoundPlan> rounds = new ArrayList<>();
        for (int week = 0; week < 3; week++) {
            addBaselineSession(rounds, week, DayOfWeek.MONDAY, 9, 8 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-031",
                    "/admin/api/security-test/sensitive/resource-032",
                    "baseline device A steady pattern");
            addBaselineSession(rounds, week, DayOfWeek.WEDNESDAY, 10, 20 - week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-033",
                    "/admin/api/security-test/sensitive/resource-031",
                    "baseline device A revisit");
            addBaselineSession(rounds, week, DayOfWeek.FRIDAY, 14, 10 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-032",
                    "/admin/api/security-test/sensitive/resource-033",
                    "stable device A closure");
        }
        addAnomalySession(rounds, 3, DayOfWeek.MONDAY, 9, 9, CORP_LAN_IP, EDGE_RAW, EDGE_LABEL, "corp-laptop-b",
                "/admin/api/security-test/sensitive/resource-031",
                "/admin/api/security-test/sensitive/resource-032",
                "DEVICE_FINGERPRINT_SHIFT",
                "same account, same IP and same work scope but browser/device fingerprint shifts");
        addAnomalySession(rounds, 3, DayOfWeek.WEDNESDAY, 10, 19, CORP_LAN_IP, EDGE_RAW, EDGE_LABEL, "corp-laptop-b",
                "/admin/api/security-test/sensitive/resource-033",
                "/admin/api/security-test/sensitive/resource-031",
                "DEVICE_FINGERPRINT_SHIFT",
                "shifted device revisits old assets before the system can normalize it");
        addRecoverySession(rounds, 3, DayOfWeek.FRIDAY, 14, 11, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-032",
                "/admin/api/security-test/sensitive/resource-033",
                "original device returns and should remain distinguishable from the detour");
        return List.copyOf(rounds);
    }

    static List<SandboxPromptRoundPlan> buildNetworkPivotRounds() {
        ArrayList<SandboxPromptRoundPlan> rounds = new ArrayList<>();
        for (int week = 0; week < 3; week++) {
            addBaselineSession(rounds, week, DayOfWeek.MONDAY, 9, 7 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-041",
                    "/admin/api/security-test/sensitive/resource-042",
                    "corp LAN baseline");
            addBaselineSession(rounds, week, DayOfWeek.WEDNESDAY, 10, 21 - week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-043",
                    "/admin/api/security-test/sensitive/resource-041",
                    "same device and same office network");
            addBaselineSession(rounds, week, DayOfWeek.FRIDAY, 14, 13 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-042",
                    "/admin/api/security-test/sensitive/resource-043",
                    "end-of-week corp LAN pattern");
        }
        addAnomalySession(rounds, 3, DayOfWeek.MONDAY, 9, 8, VPN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-041",
                "/admin/api/security-test/sensitive/resource-042",
                "NETWORK_PIVOT",
                "same user and same device pivot to VPN while work scope stays the same");
        addAnomalySession(rounds, 3, DayOfWeek.WEDNESDAY, 10, 20, BRANCH_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-043",
                "/admin/api/security-test/sensitive/resource-041",
                "NETWORK_PIVOT",
                "same scope repeats from a different branch network");
        addRecoverySession(rounds, 3, DayOfWeek.FRIDAY, 14, 14, CORP_WIFI_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-042",
                "/admin/api/security-test/sensitive/resource-043",
                "returns to internal network without fully matching the original IP");
        return List.copyOf(rounds);
    }

    static List<SandboxPromptRoundPlan> buildCadenceBurstRounds() {
        ArrayList<SandboxPromptRoundPlan> rounds = new ArrayList<>();
        for (int week = 0; week < 3; week++) {
            addBaselineSession(rounds, week, DayOfWeek.MONDAY, 9, week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-051",
                    "/admin/api/security-test/sensitive/resource-052",
                    "slow steady baseline");
            addBaselineSession(rounds, week, DayOfWeek.WEDNESDAY, 10, 25 - week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-051",
                    "/admin/api/security-test/sensitive/resource-052",
                    "same pair with normal dwell");
            addBaselineSession(rounds, week, DayOfWeek.FRIDAY, 14, 18 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-051",
                    "/admin/api/security-test/sensitive/resource-052",
                    "end-of-week steady cadence");
        }
        addAnomalySession(rounds, 3, DayOfWeek.MONDAY, 9, 1, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-051",
                "/admin/api/security-test/sensitive/resource-052",
                "CADENCE_BURST",
                "same asset pair repeats at an unusually compressed cadence");
        tweakLastRound(rounds, at(3, DayOfWeek.MONDAY, 9, 2), BURST_GAP);
        addAnomalySession(rounds, 3, DayOfWeek.WEDNESDAY, 10, 1, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-051",
                "/admin/api/security-test/sensitive/resource-052",
                "CADENCE_BURST",
                "cadence burst recurs on another day without changing the coarse context");
        tweakLastRound(rounds, at(3, DayOfWeek.WEDNESDAY, 10, 2), BURST_GAP);
        addRecoverySession(rounds, 3, DayOfWeek.FRIDAY, 14, 19, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-051",
                "/admin/api/security-test/sensitive/resource-052",
                "returns to normal dwell after burst");
        return List.copyOf(rounds);
    }

    static List<SandboxPromptRoundPlan> buildSequenceReversalRounds() {
        ArrayList<SandboxPromptRoundPlan> rounds = new ArrayList<>();
        for (int week = 0; week < 3; week++) {
            addBaselineSession(rounds, week, DayOfWeek.MONDAY, 9, 9 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/normal/resource-061",
                    "/admin/api/security-test/sensitive/resource-061",
                    "normal pre-check then sensitive follow-up");
            addBaselineSession(rounds, week, DayOfWeek.WEDNESDAY, 10, 17 - week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/normal/resource-062",
                    "/admin/api/security-test/sensitive/resource-062",
                    "second resource pair with the same order");
            addBaselineSession(rounds, week, DayOfWeek.FRIDAY, 14, 15 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/normal/resource-063",
                    "/admin/api/security-test/sensitive/resource-063",
                    "order remains stable across weeks");
        }
        addAnomalySession(rounds, 3, DayOfWeek.MONDAY, 9, 10, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/critical/resource-061",
                "/admin/api/security-test/normal/resource-061",
                "SEQUENCE_REVERSAL",
                "critical step appears before the usual preparation order");
        addAnomalySession(rounds, 3, DayOfWeek.WEDNESDAY, 10, 18, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/critical/resource-062",
                "/admin/api/security-test/normal/resource-062",
                "SEQUENCE_REVERSAL",
                "sequence reversal persists on a second resource pair");
        addRecoverySession(rounds, 3, DayOfWeek.FRIDAY, 14, 16, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/normal/resource-063",
                "/admin/api/security-test/sensitive/resource-063",
                "returns to learned order after reversal");
        return List.copyOf(rounds);
    }

    static List<SandboxPromptRoundPlan> buildLateEscalationRounds() {
        ArrayList<SandboxPromptRoundPlan> rounds = new ArrayList<>();
        for (int week = 0; week < 3; week++) {
            addBaselineSession(rounds, week, DayOfWeek.MONDAY, 9, 4 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/normal/resource-071",
                    "/admin/api/security-test/sensitive/resource-071",
                    "mixed baseline normal to sensitive");
            addBaselineSession(rounds, week, DayOfWeek.WEDNESDAY, 10, 13 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/normal/resource-072",
                    "/admin/api/security-test/sensitive/resource-072",
                    "mixed baseline secondary pair");
            addBaselineSession(rounds, week, DayOfWeek.FRIDAY, 14, 7 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-073",
                    "/admin/api/security-test/normal/resource-071",
                    "broad baseline before late escalation");
        }
        addAnomalySession(rounds, 3, DayOfWeek.MONDAY, 9, 5, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-073",
                "/admin/api/security-test/critical/resource-771",
                "LATE_CRITICAL_APPROVAL",
                "critical approval occurs only after a broad baseline exists");
        addAnomalySession(rounds, 3, DayOfWeek.WEDNESDAY, 10, 14, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/normal/resource-072",
                "/admin/api/security-test/critical/resource-772",
                "LATE_CRITICAL_APPROVAL",
                "late escalation persists on a second workflow branch");
        addRecoverySession(rounds, 3, DayOfWeek.FRIDAY, 14, 8, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-073",
                "/admin/api/security-test/normal/resource-071",
                "falls back to broad mixed baseline");
        return List.copyOf(rounds);
    }

    static List<SandboxPromptRoundPlan> buildRecoveryRounds() {
        ArrayList<SandboxPromptRoundPlan> rounds = new ArrayList<>();
        for (int week = 0; week < 3; week++) {
            addBaselineSession(rounds, week, DayOfWeek.MONDAY, 9, 6 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "managed-vdi",
                    "/admin/api/security-test/critical/resource-081",
                    "/admin/api/security-test/critical/resource-082",
                    "critical-heavy baseline");
            addBaselineSession(rounds, week, DayOfWeek.WEDNESDAY, 10, 22 - week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "managed-vdi",
                    "/admin/api/security-test/sensitive/resource-081",
                    "/admin/api/security-test/critical/resource-083",
                    "critical profile with sensitive subtask");
            addBaselineSession(rounds, week, DayOfWeek.FRIDAY, 14, 9 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "managed-vdi",
                    "/admin/api/security-test/critical/resource-082",
                    "/admin/api/security-test/critical/resource-081",
                    "critical revisit");
        }
        addAnomalySession(rounds, 3, DayOfWeek.MONDAY, 9, 7, CORP_LAN_IP, CHROME_VDI_RAW, CHROME_VDI_LABEL, "managed-vdi",
                "/admin/api/security-test/normal/resource-081",
                "/admin/api/security-test/normal/resource-082",
                "TEMPORARY_NORMALIZATION",
                "same user temporarily detours into a low-sensitivity scope unusual for this profile");
        addAnomalySession(rounds, 3, DayOfWeek.WEDNESDAY, 10, 21, CORP_LAN_IP, CHROME_VDI_RAW, CHROME_VDI_LABEL, "managed-vdi",
                "/admin/api/security-test/normal/resource-081",
                "/admin/api/security-test/sensitive/resource-081",
                "TEMPORARY_NORMALIZATION",
                "normalization detour persists long enough to require contextual explanation");
        addRecoverySession(rounds, 3, DayOfWeek.FRIDAY, 14, 10, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "managed-vdi",
                "/admin/api/security-test/critical/resource-081",
                "/admin/api/security-test/critical/resource-082",
                "critical-heavy baseline restored");
        return List.copyOf(rounds);
    }

    static List<SandboxPromptRoundPlan> buildSparseEvidenceRounds() {
        ArrayList<SandboxPromptRoundPlan> rounds = new ArrayList<>();
        for (int week = 0; week < 3; week++) {
            addBaselineSession(rounds, week, DayOfWeek.MONDAY, 9, 11 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/normal/resource-" + (111 + week),
                    "/admin/api/security-test/sensitive/resource-" + (121 + week),
                    "resource set keeps moving so baseline evidence stays sparse");
            addBaselineSession(rounds, week, DayOfWeek.THURSDAY, 15, 6 + week, CORP_WIFI_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/normal/resource-" + (131 + week),
                    "/admin/api/security-test/sensitive/resource-" + (141 + week),
                    "same user revisits new assets without forming a dense history cluster");
        }
        addAnomalySession(rounds, 3, DayOfWeek.MONDAY, 9, 13, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-151",
                "/admin/api/security-test/critical/resource-951",
                "SPARSE_EVIDENCE",
                "same account reaches high-value scope before enough comparable history exists");
        addRecoverySession(rounds, 3, DayOfWeek.THURSDAY, 15, 9, CORP_WIFI_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/normal/resource-133",
                "/admin/api/security-test/sensitive/resource-143",
                "returns to rotating sparse workflow after ambiguity");
        return List.copyOf(rounds);
    }

    static List<SandboxPromptRoundPlan> buildConflictingContextRounds() {
        ArrayList<SandboxPromptRoundPlan> rounds = new ArrayList<>();
        for (int week = 0; week < 3; week++) {
            addBaselineSession(rounds, week, DayOfWeek.MONDAY, 9, 14 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-161",
                    "/admin/api/security-test/sensitive/resource-162",
                    "same device and same network build a stable sensitive baseline");
            addBaselineSession(rounds, week, DayOfWeek.WEDNESDAY, 10, 9 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-163",
                    "/admin/api/security-test/sensitive/resource-161",
                    "mid-week baseline remains steady");
            addBaselineSession(rounds, week, DayOfWeek.FRIDAY, 14, 7 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-162",
                    "/admin/api/security-test/sensitive/resource-163",
                    "baseline closes on the same office profile");
        }
        addAnomalySession(rounds, 3, DayOfWeek.MONDAY, 9, 15, VPN_IP, EDGE_RAW, EDGE_LABEL, "corp-laptop-b",
                "/admin/api/security-test/sensitive/resource-161",
                "/admin/api/security-test/sensitive/resource-162",
                "CONFLICTING_CONTEXT",
                "same user keeps the same resource scope while device and network signals pivot together");
        addAnomalySession(rounds, 3, DayOfWeek.WEDNESDAY, 10, 10, BRANCH_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-163",
                "/admin/api/security-test/critical/resource-963",
                "CONFLICTING_CONTEXT",
                "network reverts toward normal while scope escalates, leaving mixed evidence");
        addRecoverySession(rounds, 3, DayOfWeek.FRIDAY, 14, 8, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-162",
                "/admin/api/security-test/sensitive/resource-163",
                "conflicting context clears and baseline path returns");
        return List.copyOf(rounds);
    }

    static List<SandboxPromptRoundPlan> buildPartialMemoryRounds() {
        ArrayList<SandboxPromptRoundPlan> rounds = new ArrayList<>();
        for (int week = 0; week < 3; week++) {
            addBaselineSession(rounds, week, DayOfWeek.MONDAY, 9, 2 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-" + (171 + week),
                    "/admin/api/security-test/sensitive/resource-" + (181 + week),
                    "memory disperses across adjacent assets");
            addBaselineSession(rounds, week, DayOfWeek.WEDNESDAY, 10, 4 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-" + (191 + week),
                    "/admin/api/security-test/sensitive/resource-" + (201 + week),
                    "wide fan-out keeps direct memory for each path partial");
            addBaselineSession(rounds, week, DayOfWeek.FRIDAY, 14, 5 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-" + (211 + week),
                    "/admin/api/security-test/sensitive/resource-" + (221 + week),
                    "history grows, but path-specific recall stays fragmented");
        }
        addAnomalySession(rounds, 3, DayOfWeek.MONDAY, 9, 3, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-171",
                "/admin/api/security-test/critical/resource-971",
                "PARTIAL_MEMORY",
                "the user revisits an older thread where only partial memory is available");
        addAnomalySession(rounds, 3, DayOfWeek.WEDNESDAY, 10, 5, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-201",
                "/admin/api/security-test/critical/resource-972",
                "PARTIAL_MEMORY",
                "critical follow-up appears while comparable memory remains thin and dispersed");
        addRecoverySession(rounds, 3, DayOfWeek.FRIDAY, 14, 6, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-223",
                "/admin/api/security-test/sensitive/resource-211",
                "falls back into the dispersed but familiar path family");
        return List.copyOf(rounds);
    }

    static List<SandboxPromptRoundPlan> buildApprovalAmbiguityRounds() {
        ArrayList<SandboxPromptRoundPlan> rounds = new ArrayList<>();
        for (int week = 0; week < 3; week++) {
            addBaselineSession(rounds, week, DayOfWeek.MONDAY, 8, 58 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/normal/resource-231",
                    "/admin/api/security-test/sensitive/resource-231",
                    "broad baseline builds normal-to-sensitive progression");
            addBaselineSession(rounds, week, DayOfWeek.WEDNESDAY, 10, 2 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/normal/resource-232",
                    "/admin/api/security-test/sensitive/resource-232",
                    "mixed scope remains read-dominant");
            addBaselineSession(rounds, week, DayOfWeek.FRIDAY, 14, 3 + week, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                    "/admin/api/security-test/sensitive/resource-233",
                    "/admin/api/security-test/normal/resource-231",
                    "scope summary stays broad but approval lineage remains thin");
        }
        addAnomalySession(rounds, 3, DayOfWeek.MONDAY, 9, 1, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-233",
                "/admin/api/security-test/critical/resource-981",
                "APPROVAL_AMBIGUITY",
                "critical access appears while scope evidence is present but approval lineage is still ambiguous");
        addAnomalySession(rounds, 3, DayOfWeek.WEDNESDAY, 10, 6, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/normal/resource-232",
                "/admin/api/security-test/critical/resource-982",
                "APPROVAL_AMBIGUITY",
                "critical action persists on a branch where approval evidence stays thin");
        addRecoverySession(rounds, 3, DayOfWeek.FRIDAY, 14, 5, CORP_LAN_IP, CHROME_RAW, CHROME_LABEL, "corp-laptop-a",
                "/admin/api/security-test/sensitive/resource-233",
                "/admin/api/security-test/normal/resource-231",
                "returns to broad mixed-scope baseline after approval ambiguity");
        return List.copyOf(rounds);
    }

    private static void addBaselineSession(
            List<SandboxPromptRoundPlan> rounds,
            int week,
            DayOfWeek dayOfWeek,
            int hour,
            int minute,
            String clientIp,
            String browserUserAgent,
            String simulatedUserAgentLabel,
            String deviceAlias,
            String firstPath,
            String secondPath,
            String note) {
        OffsetDateTime start = at(week, dayOfWeek, hour, minute);
        rounds.add(round(rounds.size() + 1, firstPath, clientIp, browserUserAgent, simulatedUserAgentLabel, deviceAlias,
                start, SandboxPromptSessionMode.NEW_SESSION, STEADY_GAP, "BASELINE", "NONE", note,
                List.of("EXPECT_HISTORY_BUILDUP", "EXPECT_RAG_ACCUMULATION", "EXPECT_MULTI_SESSION_PROFILE")));
        rounds.add(round(rounds.size() + 1, secondPath, clientIp, browserUserAgent, simulatedUserAgentLabel, deviceAlias,
                start.plusMinutes(12), SandboxPromptSessionMode.REUSE_SESSION, SLOW_GAP, "BASELINE", "NONE", note,
                List.of("EXPECT_HISTORY_BUILDUP", "EXPECT_PREVIOUS_PATH", "EXPECT_MULTI_SESSION_PROFILE")));
    }

    private static void addAnomalySession(
            List<SandboxPromptRoundPlan> rounds,
            int week,
            DayOfWeek dayOfWeek,
            int hour,
            int minute,
            String clientIp,
            String browserUserAgent,
            String simulatedUserAgentLabel,
            String deviceAlias,
            String firstPath,
            String secondPath,
            String anomalySignal,
            String note) {
        OffsetDateTime start = at(week, dayOfWeek, hour, minute);
        rounds.add(round(rounds.size() + 1, firstPath, clientIp, browserUserAgent, simulatedUserAgentLabel, deviceAlias,
                start, SandboxPromptSessionMode.NEW_SESSION, STEADY_GAP, "ANOMALY", anomalySignal, note,
                List.of("EXPECT_HISTORY_CONTRAST", "EXPECT_MULTI_SESSION_BASELINE", "EXPECT_OBSERVED_WORK_PATTERN")));
        rounds.add(round(rounds.size() + 1, secondPath, clientIp, browserUserAgent, simulatedUserAgentLabel, deviceAlias,
                start.plusMinutes(12), SandboxPromptSessionMode.REUSE_SESSION, BURST_GAP, "ANOMALY", anomalySignal, note,
                List.of("EXPECT_HISTORY_CONTRAST", "EXPECT_PREVIOUS_PATH", "EXPECT_USER_SPECIFIC_NOVELTY")));
    }

    private static void addRecoverySession(
            List<SandboxPromptRoundPlan> rounds,
            int week,
            DayOfWeek dayOfWeek,
            int hour,
            int minute,
            String clientIp,
            String browserUserAgent,
            String simulatedUserAgentLabel,
            String deviceAlias,
            String firstPath,
            String secondPath,
            String note) {
        OffsetDateTime start = at(week, dayOfWeek, hour, minute);
        rounds.add(round(rounds.size() + 1, firstPath, clientIp, browserUserAgent, simulatedUserAgentLabel, deviceAlias,
                start, SandboxPromptSessionMode.NEW_SESSION, STEADY_GAP, "RECOVERY", "NONE", note,
                List.of("EXPECT_HISTORY_PRESERVATION", "EXPECT_RECOVERY_AFTER_ANOMALY", "EXPECT_RAG_ACCUMULATION")));
        rounds.add(round(rounds.size() + 1, secondPath, clientIp, browserUserAgent, simulatedUserAgentLabel, deviceAlias,
                start.plusMinutes(12), SandboxPromptSessionMode.REUSE_SESSION, STEADY_GAP, "RECOVERY", "NONE", note,
                List.of("EXPECT_HISTORY_PRESERVATION", "EXPECT_PREVIOUS_PATH", "EXPECT_RAG_ACCUMULATION")));
    }

    private static SandboxPromptRoundPlan round(
            int roundNumber,
            String requestPath,
            String clientIp,
            String browserUserAgent,
            String simulatedUserAgentLabel,
            String deviceAlias,
            OffsetDateTime observedAt,
            SandboxPromptSessionMode sessionMode,
            long cooldownBeforeRoundMs,
            String behaviorPhase,
            String anomalySignal,
            String expectationNote,
            List<String> semanticMarkers) {
        return new SandboxPromptRoundPlan(
                String.format(Locale.ROOT, "R%02d", roundNumber),
                requestPath,
                clientIp,
                browserUserAgent,
                simulatedUserAgentLabel,
                deviceAlias,
                observedAt,
                sessionMode,
                cooldownBeforeRoundMs,
                behaviorPhase,
                anomalySignal,
                expectationNote,
                semanticMarkers);
    }

    private static void tweakLastRound(List<SandboxPromptRoundPlan> rounds, OffsetDateTime observedAt, long cooldownBeforeRoundMs) {
        SandboxPromptRoundPlan previous = rounds.get(rounds.size() - 1);
        rounds.set(rounds.size() - 1, new SandboxPromptRoundPlan(
                previous.roundKey(),
                previous.requestPath(),
                previous.clientIp(),
                previous.browserUserAgent(),
                previous.simulatedUserAgentLabel(),
                previous.deviceAlias(),
                observedAt,
                previous.sessionMode(),
                cooldownBeforeRoundMs,
                previous.behaviorPhase(),
                previous.anomalySignal(),
                previous.expectationNote(),
                previous.semanticMarkers()));
    }

    private static OffsetDateTime at(int weekOffset, DayOfWeek dayOfWeek, int hour, int minute) {
        int dayOffset = dayOfWeek.getValue() - DayOfWeek.MONDAY.getValue();
        return BASE_MONDAY.plusWeeks(weekOffset)
                .plusDays(dayOffset)
                .atTime(0, 0)
                .plusHours(hour)
                .plusMinutes(minute)
                .atOffset(SEOUL_OFFSET);
    }
}
