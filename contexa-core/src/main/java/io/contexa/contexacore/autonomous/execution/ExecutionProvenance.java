package io.contexa.contexacore.autonomous.execution;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

public record ExecutionProvenance(
        String protocolType,
        String protocolVersion,
        String sourceSystem,
        String sourceReference,
        String chainId,
        Integer chainDepth,
        String lineageState,
        boolean serviceClientPrincipal,
        LocalDateTime observedAt,
        Map<String, Object> attributes) {

    public ExecutionProvenance {
        attributes = attributes == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(attributes));
    }
}