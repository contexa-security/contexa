package io.contexa.sandbox.fullstack.prompt;

import java.util.Map;

/**
 * One protected-resource replay result from the real web path.
 */
public record SandboxPromptReplayRound(
        String phase,
        int roundNumber,
        SandboxPromptRoundPlan roundPlan,
        String requestId,
        String requestPath,
        String clientIp,
        String userAgentLabel,
        String deviceId,
        Map<String, Object> responseBody,
        SandboxPromptTraceSnapshot snapshot) {
}
