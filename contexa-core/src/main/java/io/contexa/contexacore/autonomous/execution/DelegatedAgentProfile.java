package io.contexa.contexacore.autonomous.execution;

import java.util.List;

public record DelegatedAgentProfile(
        String agentId,
        String agentRuntimeId,
        String delegationId,
        String parentExecutionId,
        String agentClass,
        String attestationState,
        String runtimePostureState,
        List<String> allowedToolChain) {

    public DelegatedAgentProfile {
        allowedToolChain = allowedToolChain == null ? List.of() : List.copyOf(allowedToolChain);
    }
}