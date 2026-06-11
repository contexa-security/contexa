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
package io.contexa.contexacommon.security.bridge.resolver;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;

public class HeaderAuthorizationStampResolver implements AuthorizationStampResolver {

    @Override
    public Optional<AuthorizationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        BridgeProperties.Headers config = properties.getAuthorization().getHeaders();
        if (!config.isEnabled()) {
            return Optional.empty();
        }
        String effect = request.getHeader(config.getAuthorizationEffect());
        String roles = request.getHeader(config.getEffectiveRoles());
        String authorities = request.getHeader(config.getEffectiveAuthorities());
        String privileged = request.getHeader(config.getPrivileged());
        String scopeTags = request.getHeader(config.getScopeTags());
        String policyVersion = request.getHeader(config.getPolicyVersion());
        if (effect == null && roles == null && authorities == null && privileged == null && scopeTags == null && policyVersion == null) {
            return Optional.empty();
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("authorizationResolver", "HEADER");
        return Optional.of(new AuthorizationStamp(
                SecurityContextStampSupport.resolveSubjectIdFromHeaders(request, properties),
                requestContext.requestUri(),
                requestContext.method(),
                AuthorizationEffect.from(effect),
                privileged != null ? Boolean.parseBoolean(privileged) : null,
                split(scopeTags),
                request.getHeader(config.getPolicyId()),
                policyVersion,
                "HEADER",
                Instant.now(),
                split(roles),
                split(authorities),
                attributes
        ));
    }

    private List<String> split(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        return List.of(raw.split("\\s*,\\s*"));
    }
}
