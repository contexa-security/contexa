package io.contexa.contexaiam.resource.util;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;

// Canonical key format shared between a ManagedResource and a PolicyTarget.
// Centralising the "<TYPE>:<identifier>" convention avoids silent drift between
// the resource discovery side and the policy evaluation side.
public final class ResourceTargetKey {

    private ResourceTargetKey() {
    }

    public static String of(ManagedResource.ResourceType resourceType, String identifier) {
        return resourceType.name() + ":" + identifier;
    }

    public static String of(String targetType, String targetIdentifier) {
        return targetType + ":" + targetIdentifier;
    }

    public static String ofResource(ManagedResource resource) {
        return of(resource.getResourceType(), resource.getResourceIdentifier());
    }

    public static String ofPolicyTarget(PolicyTarget target) {
        return of(target.getTargetType(), target.getTargetIdentifier());
    }
}
