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
package io.contexa.contexacore.autonomous.context.resolver;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;

import java.util.Map;
import java.util.Optional;

/**
 * Interface for resolving a specific profile type from metadata and canonical context.
 * Each profile type (SessionNarrative, WorkProfile, RoleScope, etc.) has its own resolver.
 *
 * @param <T> the profile type this resolver produces
 */
public interface ProfileResolver<T> {

    /**
     * Resolve a profile from metadata and existing canonical context.
     * Returns empty if the profile has no meaningful data.
     */
    Optional<T> resolve(Map<String, Object> metadata, CanonicalSecurityContext context);

    /**
     * Check if the profile contains meaningful data.
     */
    boolean hasData(T profile);

    /**
     * Build a human-readable summary for the profile.
     */
    String buildSummary(T profile, CanonicalSecurityContext context);

    /**
     * Apply the resolved profile to the canonical context.
     */
    void apply(T profile, CanonicalSecurityContext context);
}
