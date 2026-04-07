package io.contexa.contexacore.autonomous.context.registry;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import io.contexa.contexacore.autonomous.context.model.ResourceContextDescriptor;
import io.contexa.contexacore.autonomous.context.registry.ResourceContextRegistry;

public class InMemoryResourceContextRegistry implements ResourceContextRegistry {

    private final Map<String, ResourceContextDescriptor> resources = new ConcurrentHashMap<>();

    public void register(ResourceContextDescriptor descriptor) {
        if (descriptor == null || descriptor.resourceId() == null || descriptor.resourceId().isBlank()) {
            return;
        }
        resources.put(descriptor.resourceId(), descriptor);
    }

    @Override
    public Optional<ResourceContextDescriptor> findByResourceId(String resourceId) {
        if (resourceId == null || resourceId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(resources.get(resourceId));
    }
}
