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
package io.contexa.contexacommon.security.bridge.stamp;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public record AuthorizationStamp(
        String subjectId,
        String resourceId,
        String action,
        AuthorizationEffect effect,
        Boolean privileged,
        List<String> scopeTags,
        String policyId,
        String policyVersion,
        String decisionSource,
        Instant decisionTime,
        List<String> effectiveRoles,
        List<String> effectiveAuthorities,
        Map<String, Object> attributes
) {

    public AuthorizationStamp {
        effect = effect == null ? AuthorizationEffect.UNKNOWN : effect;
        scopeTags = scopeTags == null ? List.of() : List.copyOf(new LinkedHashSet<>(scopeTags));
        effectiveRoles = effectiveRoles == null ? List.of() : List.copyOf(new LinkedHashSet<>(effectiveRoles));
        effectiveAuthorities = effectiveAuthorities == null ? List.of() : List.copyOf(new LinkedHashSet<>(effectiveAuthorities));
        attributes = attributes == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(attributes));
    }
}
