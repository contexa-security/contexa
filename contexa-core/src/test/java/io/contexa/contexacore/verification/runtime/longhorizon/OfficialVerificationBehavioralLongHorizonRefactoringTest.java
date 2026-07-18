package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractSessionMode;
import io.contexa.contexacore.verification.runtime.OfficialVerificationPromptContractReplaySupport;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OfficialVerificationBehavioralLongHorizonRefactoringTest {

    @Test
    void preservesBsrBehavioralSurpriseAndRecoveryChecks() {
        List<OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan> plans = plans(
                List.of("BASELINE", "ANOMALY", "RECOVERY"),
                List.of("NONE", "RESOURCE_SEQUENCE", "CRITICAL_SEQUENCE")
        );
        List<OfficialVerificationBsrExecutionService.RoundSnapshot> rounds = bsrRounds(plans);

        assertThat(new OfficialVerificationBsrCheckEvaluator().buildChecks(rounds))
                .isNotEmpty()
                .allMatch(OfficialVerificationBsrExecutionService.BsrCheckResult::pass);
    }

    @Test
    void preservesUsnsNoveltyAndAnomalyChecks() {
        List<OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan> plans = plans(
                List.of("BASELINE", "ANOMALY", "ANOMALY"),
                List.of("NONE", "RESOURCE_SEQUENCE", "CRITICAL_SEQUENCE")
        );
        List<OfficialVerificationUsnsExecutionService.RoundSnapshot> rounds = usnsRounds(plans);

        assertThat(new OfficialVerificationUsnsCheckEvaluator().buildChecks(rounds))
                .isNotEmpty()
                .allMatch(OfficialVerificationUsnsExecutionService.UsnsCheckResult::pass);
    }

    @Test
    void preservesBmaBaselineMaturityChecks() {
        List<OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan> plans = plans(
                List.of("BASELINE", "MATURITY", "MATURITY"),
                List.of("NONE", "OBSERVATION_GROWTH", "OBSERVATION_GROWTH")
        );
        List<OfficialVerificationBmaExecutionService.RoundSnapshot> rounds = bmaRounds(plans);

        assertThat(new OfficialVerificationBmaCheckEvaluator().buildChecks(rounds))
                .isNotEmpty()
                .allMatch(OfficialVerificationBmaExecutionService.BmaCheckResult::pass);
    }
    private List<OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan> plans(
            List<String> phases,
            List<String> signals
    ) {
        List<String> endpointKeys = List.of("normal", "sensitive", "critical");
        List<OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan> plans = new ArrayList<>();
        for (int index = 0; index < phases.size(); index++) {
            String key = endpointKeys.get(index);
            plans.add(new OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan(
                    "BEHAVIORAL-SCENARIO", "BEHAVIORAL", "behavioral", "ALLOW", "R" + (index + 1),
                    "benchmark-1", "verification-user", "session-1", 1, index + 1,
                    new OfficialVerificationPromptContractReplaySupport.EndpointDefinition(
                            key, key, "/verification/runtime/probe/" + key + "/resource-1", "resource-1"
                    ),
                    "198.51.100.24", "Chrome/120", "Chrome on Windows", "device", "device-1",
                    Instant.parse("2026-07-16T00:0" + index + ":00Z"),
                    index == 0 ? OfficialVerificationPromptContractSessionMode.NEW_SESSION
                            : OfficialVerificationPromptContractSessionMode.REUSE_SESSION,
                    0L, phases.get(index), signals.get(index), "round " + (index + 1), List.of()
            ));
        }
        return List.copyOf(plans);
    }

    private List<OfficialVerificationBmaExecutionService.RoundSnapshot> bmaRounds(
            List<OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan> plans
    ) {
        List<OfficialVerificationBmaExecutionService.RoundSnapshot> rounds = new ArrayList<>();
        for (OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan plan : plans) {
            boolean firstRound = plan.roundNumber() == 1;
            int evidenceCount = firstRound ? 0 : plan.roundNumber();
            String summary = firstRound ? "Evidence State Provisional"
                    : "Evidence State Established Observations " + evidenceCount;
            rounds.add(new OfficialVerificationBmaExecutionService.RoundSnapshot(
                    plan, plan.roundNumber(), requestId(plan), Map.of("requestPath", plan.endpoint().path()), List.of(),
                    null, null, Map.of("workProfileSummary", summary), Map.of(), Map.of(), Map.of(), Map.of(),
                    evidenceCount, evidenceCount, !firstRound, true, summary
            ));
        }
        return List.copyOf(rounds);
    }
    private List<OfficialVerificationBsrExecutionService.RoundSnapshot> bsrRounds(
            List<OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan> plans
    ) {
        List<OfficialVerificationBsrExecutionService.RoundSnapshot> rounds = new ArrayList<>();
        Map<String, String> previousPaths = new HashMap<>();
        for (OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan plan : plans) {
            Map<String, Object> metadata = metadata(plan, previousPaths);
            int evidenceCount = Math.max(1, plan.roundNumber() - 1);
            rounds.add(new OfficialVerificationBsrExecutionService.RoundSnapshot(
                    plan, plan.roundNumber(), requestId(plan), Map.of("requestPath", plan.endpoint().path()), List.of(),
                    null, null, Map.of("workProfileSummary", "Observations " + evidenceCount), Map.of(),
                    metadata, Map.of(), Map.of(), evidenceCount, evidenceCount, true, true,
                    "Observations " + evidenceCount
            ));
            previousPaths.put(plan.scenarioKey(), plan.endpoint().path());
        }
        return List.copyOf(rounds);
    }

    private List<OfficialVerificationUsnsExecutionService.RoundSnapshot> usnsRounds(
            List<OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan> plans
    ) {
        List<OfficialVerificationUsnsExecutionService.RoundSnapshot> rounds = new ArrayList<>();
        Map<String, String> previousPaths = new HashMap<>();
        for (OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan plan : plans) {
            Map<String, Object> metadata = metadata(plan, previousPaths);
            int evidenceCount = Math.max(1, plan.roundNumber() - 1);
            rounds.add(new OfficialVerificationUsnsExecutionService.RoundSnapshot(
                    plan, plan.roundNumber(), requestId(plan), Map.of("requestPath", plan.endpoint().path()), List.of(),
                    null, null, Map.of("workProfileSummary", "Observations " + evidenceCount), Map.of(),
                    metadata, Map.of(), Map.of(), evidenceCount, evidenceCount, true, true,
                    "Observations " + evidenceCount
            ));
            previousPaths.put(plan.scenarioKey(), plan.endpoint().path());
        }
        return List.copyOf(rounds);
    }

    private Map<String, Object> metadata(
            OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan plan,
            Map<String, String> previousPaths
    ) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("behaviorPhase", plan.behaviorPhase());
        metadata.put("anomalySignal", plan.anomalySignal());
        metadata.put("requestPath", plan.endpoint().path());
        metadata.put("previousPath", previousPaths.getOrDefault(plan.scenarioKey(), plan.endpoint().path()));
        metadata.put("userAgent", plan.browserUserAgent());
        metadata.put("simulatedUserAgentLabel", plan.simulatedUserAgentLabel());
        metadata.put("clientIp", plan.clientIp());
        metadata.put("geoCountry", "KR");
        metadata.put("lastRequestIntervalMs", 0L);
        metadata.put("resourceSensitivity", "HIGH");
        return Map.copyOf(metadata);
    }

    private String requestId(OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan plan) {
        return "request-" + plan.scenarioIndex() + "-" + plan.roundNumber();
    }
}