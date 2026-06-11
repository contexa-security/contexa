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

public class RequestAttributeAuthorizationStampResolver implements AuthorizationStampResolver {

    @Override
    public Optional<AuthorizationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        BridgeProperties.RequestAttributes config = properties.getAuthorization().getRequestAttributes();
        if (!config.isEnabled()) {
            return Optional.empty();
        }
        Object effect = request.getAttribute(config.getAuthorizationEffect());
        Object roles = request.getAttribute(config.getEffectiveRoles());
        Object authorities = request.getAttribute(config.getEffectiveAuthorities());
        Object privileged = request.getAttribute(config.getPrivileged());
        Object scopeTags = request.getAttribute(config.getScopeTags());
        Object policyVersion = request.getAttribute(config.getPolicyVersion());
        if (effect == null && roles == null && authorities == null && privileged == null && scopeTags == null && policyVersion == null) {
            return Optional.empty();
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("authorizationResolver", "REQUEST_ATTRIBUTE");
        return Optional.of(new AuthorizationStamp(
                SecurityContextStampSupport.resolveSubjectIdFromRequestAttributes(request, properties),
                requestContext.requestUri(),
                requestContext.method(),
                AuthorizationEffect.from(effect),
                privileged instanceof Boolean booleanValue ? booleanValue : null,
                split(scopeTags),
                text(request.getAttribute(config.getPolicyId())),
                text(policyVersion),
                "REQUEST_ATTRIBUTE",
                Instant.now(),
                split(roles),
                split(authorities),
                attributes
        ));
    }

    private List<String> split(Object raw) {
        if (raw == null) {
            return List.of();
        }
        String text = raw.toString();
        if (text.isBlank()) {
            return List.of();
        }
        return List.of(text.split("\\s*,\\s*"));
    }

    private String text(Object raw) {
        return SecurityContextStampSupport.text(raw);
    }
}
