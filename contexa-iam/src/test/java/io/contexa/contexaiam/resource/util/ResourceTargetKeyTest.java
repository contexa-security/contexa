/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
