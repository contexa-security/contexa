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
package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.saas.SaasDecisionOutboxService;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class SaasForwardingHandler implements SecurityEventHandler {

    private final SaasDecisionOutboxService outboxService;
    private final SaasForwardingProperties properties;

    @Override
    public boolean canHandle(SecurityEventContext context) {
        if (context == null || !properties.isEnabled()) {
            return false;
        }
        Object resultObject = context.getMetadata().get("processingResult");
        if (!(resultObject instanceof ProcessingResult result) || !result.isSuccess()) {
            return false;
        }
        return isForwardableAction(result.getAction());
    }

    private boolean isForwardableAction(String action) {
        if (action == null || action.isBlank()) {
            return false;
        }
        return !("PENDING_ANALYSIS".equalsIgnoreCase(action) || "ALLOW".equalsIgnoreCase(action));
    }

    @Override
    public boolean handle(SecurityEventContext context) {
        try {
            outboxService.capture(context);
            return true;
        }
        catch (Exception e) {
            log.error("[SaasForwardingHandler] Failed to capture SaaS forwarding payload: eventId={}",
                    context.getSecurityEvent() != null ? context.getSecurityEvent().getEventId() : "unknown", e);
            return true;
        }
    }

    @Override
    public String getName() {
        return "SaasForwardingHandler";
    }

    @Override
    public int getOrder() {
        return 65;
    }
}

