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
package io.contexa.contexacommon.security.bridge;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public record BridgedUser(
        String username,
        String displayName,
        Set<String> roles,
        Map<String, Object> attributes
) {

    public BridgedUser {
        roles = roles == null ? Set.of() : Set.copyOf(new LinkedHashSet<>(roles));
        attributes = attributes == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(attributes));
    }

    public BridgedUser(String username) {
        this(username, username, Set.of(), Map.of());
    }

    public BridgedUser(String username, Set<String> roles) {
        this(username, username, roles, Map.of());
    }
}
