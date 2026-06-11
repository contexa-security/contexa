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
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;

public class RequestAttributeDelegationStampResolver implements DelegationStampResolver {

    @Override
    public Optional<DelegationStamp> resolve(HttpServletRequest request, RequestContextSnapshot requestContext, BridgeProperties properties) {
        BridgeProperties.RequestAttributes config = properties.getDelegation().getRequestAttributes();
        if (!config.isEnabled()) {
            return Optional.empty();
        }
        Object delegated = request.getAttribute(config.getDelegated());
        Object agentId = request.getAttribute(config.getAgentId());
        Object objectiveId = request.getAttribute(config.getObjectiveId());
        Object objectiveFamily = request.getAttribute(config.getObjectiveFamily());
        Object expiresAt = request.getAttribute(config.getExpiresAt());
        if (delegated == null && agentId == null && objectiveId == null && objectiveFamily == null && expiresAt == null) {
            return Optional.empty();
        }
        LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("delegationResolver", "REQUEST_ATTRIBUTE");
        return Optional.of(new DelegationStamp(
                SecurityContextStampSupport.resolveSubjectIdFromRequestAttributes(request, properties),
                text(agentId),
                delegated instanceof Boolean booleanValue ? booleanValue : Boolean.parseBoolean(text(delegated)),
                text(objectiveId),
                text(objectiveFamily),
                text(request.getAttribute(config.getObjectiveSummary())),
                split(request.getAttribute(config.getAllowedOperations())),
                split(request.getAttribute(config.getAllowedResources())),
                parseBoolean(request.getAttribute(config.getApprovalRequired())),
                parseBoolean(request.getAttribute(config.getPrivilegedExportAllowed())),
                parseBoolean(request.getAttribute(config.getContainmentOnly())),
                parseInstant(expiresAt),
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

    private Boolean parseBoolean(Object raw) {
        if (raw instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (raw instanceof String text && !text.isBlank()) {
            return Boolean.parseBoolean(text);
        }
        return null;
    }

    private Instant parseInstant(Object raw) {
        if (raw instanceof Instant instant) {
            return instant;
        }
        if (raw instanceof Number number) {
            return Instant.ofEpochMilli(number.longValue());
        }
        if (raw instanceof String text && !text.isBlank()) {
            try {
                return Instant.parse(text.trim());
            }
            catch (DateTimeParseException ignored) {
                return null;
            }
        }
        return null;
    }

    private String text(Object raw) {
        return SecurityContextStampSupport.text(raw);
    }
}
