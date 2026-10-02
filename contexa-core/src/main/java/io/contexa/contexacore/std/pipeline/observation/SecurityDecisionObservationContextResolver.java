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
package io.contexa.contexacore.std.pipeline.observation;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.std.llm.observation.LlmObservationContext;

import java.util.Map;

/** Copies explicit source identifiers without inferring missing relationships. */
public final class SecurityDecisionObservationContextResolver {

    private SecurityDecisionObservationContextResolver() {
    }

    public static LlmObservationContext resolve(AIRequest<? extends DomainContext> request) {
        if (request == null || !(request.getContext() instanceof SecurityDecisionContext context)) {
            return null;
        }
        SecurityEvent event = context.getSecurityEvent();
        if (event == null) {
            return null;
        }
        Map<String, Object> metadata = event.getMetadata();
        return new LlmObservationContext(request.getRequestId(),
                text(metadata == null ? null : metadata.get("requestId")),
                event.getEventId(),
                text(metadata == null ? null : metadata.get("eventProcessingOwnerToken")));
    }

    private static String text(Object value) {
        return value instanceof String text && !text.isBlank() ? text : null;
    }
}
