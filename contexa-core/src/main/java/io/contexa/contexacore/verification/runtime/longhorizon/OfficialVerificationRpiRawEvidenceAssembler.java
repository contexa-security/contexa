package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.runtime.OfficialVerificationContractMetadataSupport;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRuntimeEvidenceSupport;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class OfficialVerificationRpiRawEvidenceAssembler {

    static final String SCENARIO_SELECTOR = "EXTENDED";

    private final OfficialVerificationRpiCheckEvaluator checkEvaluator;

    OfficialVerificationRpiRawEvidenceAssembler(OfficialVerificationRpiCheckEvaluator checkEvaluator) {
        this.checkEvaluator = checkEvaluator;
    }

    Map<String, Object> build(
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
        List<List<RoundSnapshot>> scenarios = checkEvaluator.scenarioGroups(rounds);
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
        summary.put("relatedDocumentsNonDecreasing",
                checkEvaluator.allScenariosRelatedDocumentsNonDecreasing(scenarios));
        summary.put("observationCountNonDecreasing",
                checkEvaluator.allScenariosObservationCountsNonDecreasing(scenarios));
        summary.put("baselineContextScenarioCount",
                scenarios.stream().filter(checkEvaluator::scenarioBaselineContextPresent).count());
        summary.put("requestParityAligned", rounds.stream().allMatch(RoundSnapshot::requestParityAligned));
        summary.put("finalRelatedDocumentsMin", checkEvaluator.minFinalRelatedDocuments(scenarios));
        summary.put("finalObservationMin", checkEvaluator.minFinalObservationCount(scenarios));
        summary.put("scenarioKeys", checkEvaluator.scenarioKeys(scenarios));

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
        evidence.put("relatedDocumentsNonDecreasing", checkEvaluator.relatedDocumentsNonDecreasing(scenarioRounds));
        evidence.put("observationCountNonDecreasing", checkEvaluator.observationCountsNonDecreasing(scenarioRounds));
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
                round.decisionOutbox(), round.decisionPayload()));
        evidence.put("promptAuditOutbox", OfficialVerificationRuntimeEvidenceSupport.promptAuditOutboxSnapshot(
                round.promptOutbox(), round.promptPayload()));
        return evidence;
    }

    static String text(Map<String, Object> source, String... keys) {
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

    static String value(String input) {
        return StringUtils.hasText(input) ? input : "n/a";
    }
}
