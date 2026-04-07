package io.contexa.contexacore.autonomous.context.registry;

import java.util.Optional;
import io.contexa.contexacore.autonomous.context.model.ResourceContextDescriptor;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;

public interface ResourceContextRegistry {

    Optional<ResourceContextDescriptor> findByResourceId(String resourceId);

    default Optional<ResourceContextDescriptor> findByEvent(CanonicalSecurityContext canonicalContext) {
        if (canonicalContext == null || canonicalContext.getResource() == null) {
            return Optional.empty();
        }
        return findByResourceId(canonicalContext.getResource().getResourceId());
    }
}
