package io.contexa.demo.workspace.configuration;

import java.net.URI;
import java.util.Set;
import java.util.UUID;

public record WorkspaceSlotDefinition(String id, UUID generation, URI baseline, URI contexa) {

    public WorkspaceSlotDefinition {
        if (id == null || !id.matches("[a-z0-9][a-z0-9-]{0,39}") || generation == null) {
            throw new IllegalArgumentException("Invalid workspace slot definition");
        }
        for (URI endpoint : new URI[]{baseline, contexa}) {
            if (endpoint == null || !Set.of("http", "https").contains(endpoint.getScheme())
                    || endpoint.getHost() == null || endpoint.getUserInfo() != null || endpoint.getQuery() != null
                    || endpoint.getFragment() != null || !Set.of("", "/").contains(endpoint.getPath())) {
                throw new IllegalArgumentException("Invalid workspace worker origin");
            }
        }
    }
}
