package io.contexa.contexacore.autonomous.context;

import java.util.Optional;

public interface ResourceContextRegistry {

    Optional<ResourceContextDescriptor> findByResourceId(String resourceId);

    default Optional<ResourceContextDescriptor> findByEvent(CanonicalSecurityContext canonicalContext) {
        if (canonicalContext == null || canonicalContext.getResource() == null) {
            return Optional.empty();
        }
        return findByResourceId(canonicalContext.getResource().getResourceId());
    }
}
