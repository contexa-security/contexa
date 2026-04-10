package io.contexa.contexacore.autonomous.execution;

import java.util.List;

public record ServiceClientSubjectProfile(
        String clientId,
        String workloadType,
        boolean serviceClientPrincipal,
        String clientType,
        List<String> approvedScopes) {

    public ServiceClientSubjectProfile {
        approvedScopes = approvedScopes == null ? List.of() : List.copyOf(approvedScopes);
    }
}