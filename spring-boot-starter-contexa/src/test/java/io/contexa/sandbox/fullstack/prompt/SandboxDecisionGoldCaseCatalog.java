package io.contexa.sandbox.fullstack.prompt;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class SandboxDecisionGoldCaseCatalog {

    private static final List<String> ALL_ACTIONS = List.of("ALLOW", "CHALLENGE", "ESCALATE", "BLOCK");

    private SandboxDecisionGoldCaseCatalog() {
    }

    public static SandboxDecisionGoldCase resolve(
            SandboxPromptReplayScenario scenario,
            SandboxPromptReplayRound round) {
        SandboxPromptRoundPlan roundPlan = round.roundPlan();
        String family = canonicalFamily(roundPlan.anomalySignal().equalsIgnoreCase("NONE")
                ? scenario.scenarioFamily()
                : roundPlan.anomalySignal());
        String phase = normalize(roundPlan.behaviorPhase());

        List<String> safeActions;
        SandboxDecisionConfidenceBand confidenceBand;
        boolean uncertaintyRequired;
        List<String> requiredEvidenceTokens;
        List<String> forbiddenReasoningTokens = List.of("guaranteed", "certain", "definitively safe");

        if (round.roundNumber() == 1 || phase.contains("BASELINE")) {
            safeActions = List.of("ALLOW", "CHALLENGE", "ESCALATE");
            confidenceBand = new SandboxDecisionConfidenceBand(0.35d, 0.75d);
            uncertaintyRequired = true;
            requiredEvidenceTokens = List.of("baseline", "sensitivity");
        } else if (phase.contains("RECOVERY") || family.contains("RECOVERY")) {
            safeActions = List.of("ALLOW", "CHALLENGE");
            confidenceBand = new SandboxDecisionConfidenceBand(0.45d, 0.80d);
            uncertaintyRequired = false;
            requiredEvidenceTokens = List.of("previous path", "session", "history");
        } else if (family.contains("TEMPORARY_NORMALIZATION") || family.contains("NORMALIZATION")) {
            safeActions = List.of("ALLOW", "CHALLENGE", "ESCALATE");
            confidenceBand = new SandboxDecisionConfidenceBand(0.35d, 0.80d);
            uncertaintyRequired = true;
            requiredEvidenceTokens = List.of("previous path", "session", "baseline", "history");
        } else if (family.contains("SPARSE_EVIDENCE")
                || family.contains("PARTIAL_MEMORY")) {
            safeActions = List.of("CHALLENGE", "ESCALATE");
            confidenceBand = new SandboxDecisionConfidenceBand(0.35d, 0.72d);
            uncertaintyRequired = true;
            requiredEvidenceTokens = List.of("baseline", "history", "session");
        } else if (family.contains("CONFLICTING_CONTEXT")) {
            safeActions = List.of("ALLOW", "CHALLENGE", "ESCALATE");
            confidenceBand = new SandboxDecisionConfidenceBand(0.30d, 0.70d);
            uncertaintyRequired = true;
            requiredEvidenceTokens = List.of("previous path", "session", "baseline");
        } else if (family.contains("APPROVAL_AMBIGUITY")) {
            safeActions = List.of("CHALLENGE", "ESCALATE");
            confidenceBand = new SandboxDecisionConfidenceBand(0.35d, 0.74d);
            uncertaintyRequired = true;
            requiredEvidenceTokens = List.of("scope", "baseline", "history");
        } else if (family.contains("RESOURCE_SURGE")
                || family.contains("RESOURCE_FANOUT")
                || family.contains("LATE_ESCALATION")) {
            safeActions = List.of("CHALLENGE", "ESCALATE");
            confidenceBand = new SandboxDecisionConfidenceBand(0.50d, 0.90d);
            uncertaintyRequired = true;
            requiredEvidenceTokens = List.of("high sensitivity", "scope", "baseline", "history");
        } else if (family.contains("DEVICE_SHIFT")
                || family.contains("NETWORK_PIVOT")
                || family.contains("CADENCE_BURST")
                || family.contains("SEQUENCE_REVERSAL")) {
            safeActions = List.of("ALLOW", "CHALLENGE", "ESCALATE");
            confidenceBand = new SandboxDecisionConfidenceBand(0.35d, 0.80d);
            uncertaintyRequired = true;
            requiredEvidenceTokens = List.of("previous path", "session", "baseline");
        } else {
            safeActions = List.of("ALLOW");
            confidenceBand = new SandboxDecisionConfidenceBand(0.55d, 0.90d);
            uncertaintyRequired = false;
            requiredEvidenceTokens = List.of("baseline", "history");
        }

        return new SandboxDecisionGoldCase(
                scenario.scenarioKey(),
                roundPlan.roundKey(),
                scenario.scenarioFamily(),
                roundPlan.behaviorPhase(),
                roundPlan.anomalySignal(),
                safeActions,
                unsafeActions(safeActions),
                confidenceBand,
                uncertaintyRequired,
                requiredEvidenceTokens,
                forbiddenReasoningTokens,
                SandboxDecisionBenchmarkSettings.goldVersion());
    }

    private static List<String> unsafeActions(List<String> safeActions) {
        Set<String> allowed = new LinkedHashSet<>();
        for (String safeAction : safeActions) {
            allowed.add(normalize(safeAction));
        }
        return ALL_ACTIONS.stream()
                .map(SandboxDecisionGoldCaseCatalog::normalize)
                .filter(candidate -> !allowed.contains(candidate))
                .toList();
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private static String canonicalFamily(String rawFamily) {
        String family = normalize(rawFamily);
        if (family.contains("RESOURCE") && family.contains("FANOUT")) {
            return "RESOURCE_FANOUT";
        }
        if (family.contains("RESOURCE") || family.contains("CRITICAL")) {
            return "RESOURCE_SURGE";
        }
        if (family.contains("DEVICE")) {
            return "DEVICE_SHIFT";
        }
        if (family.contains("NETWORK") || family.contains("VPN")) {
            return "NETWORK_PIVOT";
        }
        if (family.contains("CADENCE")) {
            return "CADENCE_BURST";
        }
        if (family.contains("SEQUENCE")) {
            return "SEQUENCE_REVERSAL";
        }
        if (family.contains("SPARSE")) {
            return "SPARSE_EVIDENCE";
        }
        if (family.contains("CONFLICT")) {
            return "CONFLICTING_CONTEXT";
        }
        if (family.contains("PARTIAL") || family.contains("MEMORY")) {
            return "PARTIAL_MEMORY";
        }
        if (family.contains("APPROVAL_AMBIGUITY")) {
            return "APPROVAL_AMBIGUITY";
        }
        if (family.contains("LATE") || family.contains("ESCALATION") || family.contains("APPROVAL")) {
            return "LATE_ESCALATION";
        }
        if (family.contains("NORMALIZATION") || family.contains("RECOVERY")) {
            return "RECOVERY";
        }
        return family;
    }
}
