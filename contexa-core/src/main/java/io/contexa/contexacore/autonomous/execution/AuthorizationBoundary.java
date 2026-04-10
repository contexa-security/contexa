package io.contexa.contexacore.autonomous.execution;

import java.util.List;

public record AuthorizationBoundary(
        List<String> requestedScopes,
        List<String> approvedScopes,
        List<String> allowedOperations,
        List<String> allowedResourceFamilies,
        List<String> allowedToolChain,
        boolean containmentOnly,
        boolean privilegedExportAllowed) {

    public AuthorizationBoundary {
        requestedScopes = requestedScopes == null ? List.of() : List.copyOf(requestedScopes);
        approvedScopes = approvedScopes == null ? List.of() : List.copyOf(approvedScopes);
        allowedOperations = allowedOperations == null ? List.of() : List.copyOf(allowedOperations);
        allowedResourceFamilies = allowedResourceFamilies == null ? List.of() : List.copyOf(allowedResourceFamilies);
        allowedToolChain = allowedToolChain == null ? List.of() : List.copyOf(allowedToolChain);
    }
}