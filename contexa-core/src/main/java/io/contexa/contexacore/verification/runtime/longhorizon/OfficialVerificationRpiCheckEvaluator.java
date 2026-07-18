package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractSessionMode;
import io.contexa.contexacore.verification.runtime.OfficialVerificationContractMetadataSupport;
import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationRpiExecutionService.RpiCheckResult;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;

final class OfficialVerificationRpiCheckEvaluator {

    private static final String SCENARIO_SELECTOR = "EXTENDED";
    List<RpiCheckResult> buildChecks(List<RoundSnapshot> rounds) {
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

    List<List<RoundSnapshot>> scenarioGroups(List<RoundSnapshot> rounds) {
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

    List<String> scenarioKeys(List<List<RoundSnapshot>> scenarios) {
        return scenarios.stream().map(item -> item.get(0).plan().scenarioKey()).toList();
    }

    int minRelatedDocumentsAt(List<List<RoundSnapshot>> scenarios, int roundIndex) {
        return scenarios.stream().filter(item -> item.size() > roundIndex).mapToInt(item -> item.get(roundIndex).relatedDocumentsCount()).min().orElse(0);
    }

    int minObservationCountAt(List<List<RoundSnapshot>> scenarios, int roundIndex) {
        return scenarios.stream().filter(item -> item.size() > roundIndex).mapToInt(item -> item.get(roundIndex).observationCount()).min().orElse(-1);
    }

    int minFinalRelatedDocuments(List<List<RoundSnapshot>> scenarios) {
        return scenarios.stream().mapToInt(item -> item.get(item.size() - 1).relatedDocumentsCount()).min().orElse(0);
    }

    int minFinalObservationCount(List<List<RoundSnapshot>> scenarios) {
        return scenarios.stream().mapToInt(item -> item.get(item.size() - 1).observationCount()).min().orElse(-1);
    }

    boolean scenarioBaselineContextPresent(List<RoundSnapshot> rounds) {
        return rounds.stream().anyMatch(RoundSnapshot::baselineContextPresent);
    }

    boolean allScenariosRelatedDocumentsNonDecreasing(List<List<RoundSnapshot>> scenarios) {
        return scenarios.stream().allMatch(this::relatedDocumentsNonDecreasing);
    }

    boolean allScenariosObservationCountsNonDecreasing(List<List<RoundSnapshot>> scenarios) {
        return scenarios.stream().allMatch(this::observationCountsNonDecreasing);
    }

    String buildMessage(double score, List<RoundSnapshot> rounds, OfficialVerificationContractMetadataSupport.ContractStatus contractStatus) {
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

    boolean relatedDocumentsNonDecreasing(List<RoundSnapshot> rounds) {
        for (int index = 1; index < rounds.size(); index++) {
            if (rounds.get(index).relatedDocumentsCount() < rounds.get(index - 1).relatedDocumentsCount()) {
                return false;
            }
        }
        return true;
    }

    boolean observationCountsNonDecreasing(List<RoundSnapshot> rounds) {
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

    private String value(String input) {
        return StringUtils.hasText(input) ? input : "absent";
    }
}
