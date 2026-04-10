package io.contexa.contexacore.autonomous.execution;

import java.util.LinkedHashMap;
import java.util.Map;

public record AttestationEnvelope(
        String attestationState,
        String runtimePostureState,
        String trustTier,
        Map<String, Object> attributes) {

    public AttestationEnvelope {
        attributes = attributes == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(attributes));
    }
}