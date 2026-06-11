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
