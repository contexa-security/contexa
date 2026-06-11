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

import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class HeaderAuthBridge implements AuthBridge {

    private final BridgeProperties.Headers properties;

    public HeaderAuthBridge(BridgeProperties.Headers properties) {
        this.properties = properties != null ? properties : new BridgeProperties.Headers();
    }

    @Override
    public BridgedUser extractUser(HttpServletRequest request) {
        if (!properties.isEnabled()) {
            return null;
        }
        String authenticated = request.getHeader(properties.getAuthenticated());
        if (authenticated != null && !authenticated.isBlank() && !Boolean.parseBoolean(authenticated)) {
            return null;
        }
        String principalId = request.getHeader(properties.getPrincipalId());
        if (principalId == null || principalId.isBlank()) {
            return null;
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("bridgeAuthenticationSource", "HEADER");
        putIfPresent(attributes, "tenantId", request.getHeader(properties.getTenantId()));
        putIfPresent(attributes, "organizationId", request.getHeader(properties.getOrganizationId()));
        putIfPresent(attributes, "orgId", request.getHeader(properties.getOrgId()));
        putIfPresent(attributes, "authenticationType", request.getHeader(properties.getAuthenticationType()));
        putIfPresent(attributes, "authenticationAssurance", request.getHeader(properties.getAuthenticationAssurance()));
        putIfPresent(attributes, "mfaCompleted", request.getHeader(properties.getMfaCompleted()));
        putIfPresent(attributes, "authenticationTime", request.getHeader(properties.getAuthenticationTime()));
        return new BridgedUser(
                principalId,
                textOrFallback(request.getHeader(properties.getDisplayName()), principalId),
                splitValues(request.getHeader(properties.getAuthorities())),
                attributes
        );
    }

    private void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    private String textOrFallback(String value, String fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return value;
    }

    private Set<String> splitValues(String raw) {
        if (raw == null || raw.isBlank()) {
            return Set.of();
        }
        return Set.of(raw.split("\\s*,\\s*"));
    }
}
