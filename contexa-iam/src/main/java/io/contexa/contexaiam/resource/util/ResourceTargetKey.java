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
