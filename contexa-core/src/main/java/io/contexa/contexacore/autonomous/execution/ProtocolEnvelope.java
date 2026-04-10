package io.contexa.contexacore.autonomous.execution;

import java.util.LinkedHashMap;
import java.util.Map;

public record ProtocolEnvelope(
        String protocolType,
        String protocolVersion,
        String tenantId,
        String clientId,
        String subjectId,
        boolean serviceClientPrincipal,
        Map<String, Object> attributes) {

    public ProtocolEnvelope {
        attributes = attributes == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(attributes));
    }
}