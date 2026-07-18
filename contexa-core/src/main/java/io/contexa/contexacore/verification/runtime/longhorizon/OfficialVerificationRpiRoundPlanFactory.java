package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractRoundPlan;
import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractScenario;
import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractScenarioCatalog;
import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractSessionMode;
import io.contexa.contexacore.verification.runtime.OfficialVerificationContractMetadataSupport;
import io.contexa.contexacore.verification.runtime.OfficialVerificationReplayPathSupport;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRuntimeIsolationSupport;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

final class OfficialVerificationRpiRoundPlanFactory {

    private static final int MIN_PROGRESSION_ROUNDS = 3;
    private static final String SCENARIO_SELECTOR = "EXTENDED";
    private static final List<String> ALLOWED_ENDPOINT_KEYS = List.of("normal", "sensitive", "critical");

    int minimumRounds() {
        return MIN_PROGRESSION_ROUNDS;
    }

    OfficialVerificationContractMetadataSupport.ContractStatus contractStatus(int horizonRounds) {
        return OfficialVerificationContractMetadataSupport.rpiStructureAligned(
                SCENARIO_SELECTOR, contracts(horizonRounds)
        );
    }

    List<ProgressionRoundPlan> buildRoundPlans(String operatorUserId, int horizonRounds) {
        return buildAlignedRoundPlans(contracts(horizonRounds), operatorUserId);
    }

    RequestedTarget resolveRequestedTarget(String endpointKey, String resourceId, String requestPath) {
        String normalizedPath = OfficialVerificationReplayPathSupport.normalizeReplayPath(requestPath);
        String normalizedResourceId = normalizeResourceId(resourceId);
        if (StringUtils.hasText(normalizedPath) || StringUtils.hasText(endpointKey) || StringUtils.hasText(normalizedResourceId)) {
            OfficialVerificationReplayPathSupport.ReplayTarget target = OfficialVerificationReplayPathSupport.resolveProbeTarget(
                    endpointKey, normalizedResourceId, requestPath, ALLOWED_ENDPOINT_KEYS
            );
            return new RequestedTarget(target.endpointKey(), target.resourceId(), target.requestPath());
        }
        return new RequestedTarget("n/a", normalizedResourceId, normalizedPath);
    }

    private List<OfficialVerificationPromptContractScenario> contracts(int horizonRounds) {
        return OfficialVerificationPromptContractScenarioCatalog.resolve(SCENARIO_SELECTOR)
                .stream()
                .map(scenario -> OfficialVerificationPromptContractScenarioCatalog.resizeScenario(
                        scenario, Math.max(MIN_PROGRESSION_ROUNDS, horizonRounds)
                ))
                .toList();
    }

    private List<ProgressionRoundPlan> buildAlignedRoundPlans(
            List<OfficialVerificationPromptContractScenario> contracts,
            String operatorUserId
    ) {
        List<ProgressionRoundPlan> plans = new ArrayList<>();
        for (int scenarioIndex = 0; scenarioIndex < contracts.size(); scenarioIndex++) {
            addScenarioPlans(plans, contracts.get(scenarioIndex), operatorUserId, scenarioIndex);
        }
        return List.copyOf(plans);
    }

    private void addScenarioPlans(
            List<ProgressionRoundPlan> plans,
            OfficialVerificationPromptContractScenario contract,
            String operatorUserId,
            int scenarioIndex
    ) {
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
                currentSessionId = OfficialVerificationRuntimeIsolationSupport.verificationSessionId(
                        benchmarkRunId + ":" + contract.scenarioKey() + ":session-" + (++sessionSequence)
                );
            }
            String deviceId = deviceIdsByAlias.computeIfAbsent(
                    round.deviceAlias(), alias -> buildDeviceId(contract, alias)
            );
            plans.add(toRoundPlan(
                    contract, round, scenarioIndex, roundIndex, benchmarkRunId,
                    verificationUserId, currentSessionId, deviceId
            ));
        }
    }

    private ProgressionRoundPlan toRoundPlan(
            OfficialVerificationPromptContractScenario contract,
            OfficialVerificationPromptContractRoundPlan round,
            int scenarioIndex,
            int roundIndex,
            String benchmarkRunId,
            String verificationUserId,
            String sessionId,
            String deviceId
    ) {
        EndpointDefinition endpoint = resolveContractEndpoint(round.requestPath());
        return new ProgressionRoundPlan(
                contract.scenarioKey(), contract.scenarioFamily(), contract.scenarioHeader(),
                contract.expectedActionHeader(), round.roundKey(), benchmarkRunId, verificationUserId, sessionId,
                scenarioIndex + 1, roundIndex + 1, endpoint.key(), endpoint.label(), endpoint.resourceId(), endpoint.path(),
                round.clientIp(), round.browserUserAgent(), round.simulatedUserAgentLabel(), round.deviceAlias(), deviceId,
                round.observedAt().toInstant(), round.sessionMode(), round.cooldownBeforeRoundMs(), round.behaviorPhase(),
                round.anomalySignal(), round.expectationNote(), round.semanticMarkers()
        );
    }

    private String buildDeviceId(OfficialVerificationPromptContractScenario contract, String deviceAlias) {
        String normalizedAlias = StringUtils.hasText(deviceAlias) ? deviceAlias.trim() : "device";
        normalizedAlias = normalizedAlias.replaceAll("[^A-Za-z0-9._:-]", "-");
        return "official-verification-rpi-" + contract.scenarioKey().toLowerCase(Locale.ROOT)
                + "-" + normalizedAlias.toLowerCase(Locale.ROOT);
    }

    private EndpointDefinition resolveContractEndpoint(String requestPath) {
        OfficialVerificationReplayPathSupport.ReplayTarget target =
                OfficialVerificationReplayPathSupport.parseProbeTarget(requestPath, ALLOWED_ENDPOINT_KEYS);
        return new EndpointDefinition(target.endpointKey(), switch (target.endpointKey()) {
            case "sensitive" -> "Sensitive Resource";
            case "critical" -> "Critical Resource";
            default -> "Normal Resource";
        }, target.requestPath(), target.resourceId());
    }

    private String normalizeResourceId(String resourceId) {
        String normalized = StringUtils.hasText(resourceId) ? resourceId.trim() : "resource-001";
        normalized = normalized.replaceAll("[^A-Za-z0-9._-]", "-");
        return normalized.isBlank() ? "resource-001" : normalized;
    }

    private record EndpointDefinition(String key, String label, String path, String resourceId) {
    }
}
