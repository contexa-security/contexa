package io.contexa.contexaiam.resource.util;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ResourceTargetKey utility")
class ResourceTargetKeyTest {

    @Test
    @DisplayName("ofResource produces TYPE:identifier")
    void ofResource_produceCanonicalKey() {
        ManagedResource resource = new ManagedResource();
        resource.setResourceType(ManagedResource.ResourceType.URL);
        resource.setResourceIdentifier("/api/x");

        assertThat(ResourceTargetKey.ofResource(resource)).isEqualTo("URL:/api/x");
    }

    @Test
    @DisplayName("ofPolicyTarget produces TYPE:identifier")
    void ofPolicyTarget_produceCanonicalKey() {
        PolicyTarget target = new PolicyTarget();
        target.setTargetType("URL");
        target.setTargetIdentifier("/api/x");

        assertThat(ResourceTargetKey.ofPolicyTarget(target)).isEqualTo("URL:/api/x");
    }

    @Test
    @DisplayName("Same logical target from both sides yields the same key")
    void sameLogicalTarget_yieldsIdenticalKey() {
        ManagedResource resource = new ManagedResource();
        resource.setResourceType(ManagedResource.ResourceType.METHOD);
        resource.setResourceIdentifier("io.contexa.Foo#bar");

        PolicyTarget target = new PolicyTarget();
        target.setTargetType("METHOD");
        target.setTargetIdentifier("io.contexa.Foo#bar");

        assertThat(ResourceTargetKey.ofResource(resource))
                .isEqualTo(ResourceTargetKey.ofPolicyTarget(target));
    }
}
