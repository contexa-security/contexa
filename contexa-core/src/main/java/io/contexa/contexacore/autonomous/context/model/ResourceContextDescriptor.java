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
package io.contexa.contexacore.autonomous.context.model;

import java.util.List;

/**
 * What the host declares about a protected resource: its type, business label and category, sensitivity, the roles
 * and actions it allows, and whether it is privileged or exports sensitive data. A null value declares nothing.
 *
 * @param resourceCategory the business category (W2-11); never a sensitivity grade
 * @param privileged       whether the resource is privileged; null when the host did not state it
 * @param exportSensitive  whether the resource exports sensitive data; null when the host did not state it
 */
public record ResourceContextDescriptor(
        String resourceId,
        String resourceType,
        String businessLabel,
        String resourceCategory,
        String sensitivity,
        List<String> allowedRoleFamilies,
        List<String> allowedActionFamilies,
        Boolean privileged,
        Boolean exportSensitive) {

    public ResourceContextDescriptor {
        allowedRoleFamilies = allowedRoleFamilies == null ? List.of() : List.copyOf(allowedRoleFamilies);
        allowedActionFamilies = allowedActionFamilies == null ? List.of() : List.copyOf(allowedActionFamilies);
    }

    /** A descriptor that states both flags and no category, as registries built it before W2-11. */
    public ResourceContextDescriptor(
            String resourceId,
            String resourceType,
            String businessLabel,
            String sensitivity,
            List<String> allowedRoleFamilies,
            List<String> allowedActionFamilies,
            boolean privileged,
            boolean exportSensitive) {
        this(resourceId, resourceType, businessLabel, null, sensitivity, allowedRoleFamilies, allowedActionFamilies,
                privileged, exportSensitive);
    }
}
