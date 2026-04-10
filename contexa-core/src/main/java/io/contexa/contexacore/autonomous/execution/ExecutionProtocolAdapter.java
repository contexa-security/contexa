package io.contexa.contexacore.autonomous.execution;

import java.util.List;

public interface ExecutionProtocolAdapter {

    String protocolType();

    default boolean supports(ProtocolEnvelope envelope) {
        return envelope != null && protocolType().equalsIgnoreCase(envelope.protocolType());
    }

    default List<String> supportedVersions() {
        return List.of("1");
    }

    default String negotiateVersion(ProtocolEnvelope envelope) {
        List<String> versions = supportedVersions();
        String fallback = versions.isEmpty() ? "1" : versions.get(0);
        if (envelope == null) {
            return fallback;
        }
        String requestedVersion = envelope.protocolVersion();
        if (requestedVersion == null || requestedVersion.isBlank()) {
            return fallback;
        }
        return versions.stream()
                .filter(version -> version.equalsIgnoreCase(requestedVersion))
                .findFirst()
                .orElseGet(() -> versions.isEmpty() ? requestedVersion.trim() : versions.get(0));
    }

    CanonicalExecutionBinding adapt(ProtocolEnvelope envelope);
}
