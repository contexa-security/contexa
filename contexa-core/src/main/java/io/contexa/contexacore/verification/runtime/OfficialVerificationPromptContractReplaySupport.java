package io.contexa.contexacore.verification.runtime;

import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractRoundPlan;
import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractScenario;
import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractScenarioCatalog;
import io.contexa.contexacore.verification.contract.prompt.OfficialVerificationPromptContractSessionMode;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

public final class OfficialVerificationPromptContractReplaySupport {

    public static final String EXTENDED_SCENARIO_SELECTOR = "EXTENDED";
    public static final List<String> STANDARD_ENDPOINT_KEYS = List.of("normal", "sensitive", "critical");

    private OfficialVerificationPromptContractReplaySupport() {
    }

    public static List<OfficialVerificationPromptContractScenario> resolveScenarios(String selector, int roundCountPerScenario) {
        return OfficialVerificationPromptContractScenarioCatalog.resolve(selector)
                .stream()
                .map(scenario -> OfficialVerificationPromptContractScenarioCatalog.resizeScenario(scenario, roundCountPerScenario))
                .toList();
    }

    public static List<PromptContractRoundPlan> buildAlignedRoundPlans(
            List<OfficialVerificationPromptContractScenario> contracts,
            String operatorUserId,
            String runTag,
            List<String> allowedEndpointKeys
    ) {
        ArrayList<PromptContractRoundPlan> plans = new ArrayList<>();
        for (int scenarioIndex = 0; scenarioIndex < contracts.size(); scenarioIndex++) {
            OfficialVerificationPromptContractScenario contract = contracts.get(scenarioIndex);
            String benchmarkRunId = contract.scenarioKey().toLowerCase(Locale.ROOT) + "-" + runTag + "-benchmark-run-1";
            String verificationUserId = OfficialVerificationRuntimeIsolationSupport.verificationSubjectId(
                    operatorUserId,
                    runTag + "-" + UUID.randomUUID() + "-" + contract.scenarioKey().toLowerCase(Locale.ROOT)
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
                        alias -> buildDeviceId(runTag, contract, alias)
                );
                EndpointDefinition endpoint = resolveContractEndpoint(round.requestPath(), allowedEndpointKeys);
                plans.add(new PromptContractRoundPlan(
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
                        endpoint,
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

    private static String buildDeviceId(String runTag, OfficialVerificationPromptContractScenario contract, String deviceAlias) {
        String normalizedAlias = StringUtils.hasText(deviceAlias) ? deviceAlias.trim() : "device";
        normalizedAlias = normalizedAlias.replaceAll("[^A-Za-z0-9._:-]", "-");
        return "official-verification-"
                + runTag.toLowerCase(Locale.ROOT)
                + "-"
                + contract.scenarioKey().toLowerCase(Locale.ROOT)
                + "-"
                + normalizedAlias.toLowerCase(Locale.ROOT);
    }

    public static EndpointDefinition resolveContractEndpoint(String requestPath, List<String> allowedEndpointKeys) {
        OfficialVerificationReplayPathSupport.ReplayTarget replayTarget =
                OfficialVerificationReplayPathSupport.parseProbeTarget(normalizeContractRuntimePath(requestPath), allowedEndpointKeys);
        return new EndpointDefinition(
                replayTarget.endpointKey(),
                switch (replayTarget.endpointKey()) {
                    case "sensitive" -> "Sensitive Resource";
                    case "critical" -> "Critical Resource";
                    default -> "Normal Resource";
                },
                replayTarget.requestPath(),
                replayTarget.resourceId()
        );
    }

    private static String normalizeContractRuntimePath(String requestPath) {
        String normalized = OfficialVerificationReplayPathSupport.normalizeReplayPath(requestPath);
        if (!StringUtils.hasText(normalized)) {
            return normalized;
        }
        String enterpriseProbePrefix = "/admin/api/enterprise/verification/runtime/probe/";
        if (normalized.startsWith(enterpriseProbePrefix)) {
            return "/contexa" + normalized;
        }
        return normalized;
    }

    public record EndpointDefinition(String key, String label, String path, String resourceId) {
    }

    public record PromptContractRoundPlan(
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
            EndpointDefinition endpoint,
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
            String expectationNote,
            List<String> semanticMarkers
    ) {
        public PromptContractRoundPlan {
            semanticMarkers = semanticMarkers == null ? List.of() : List.copyOf(semanticMarkers);
        }
    }
}
