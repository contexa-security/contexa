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
package io.contexa.contexacore.autonomous.agent;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Refuses the agents' requests not confirmed in time and records it (docs/agent A5-2), also when nobody looks at the
 * confirmation again: every {@code contexa.security.zerotrust.agent.confirmation-sweep-interval} (one minute).
 */
@Slf4j
public class AgentConfirmationExpiry {

    private final AgentConfirmationService confirmations;

    public AgentConfirmationExpiry(AgentConfirmationService confirmations) {
        this.confirmations = confirmations;
    }

    @Scheduled(fixedDelayString = "${contexa.security.zerotrust.agent.confirmation-sweep-interval:PT1M}",
            initialDelayString = "${contexa.security.zerotrust.agent.confirmation-sweep-interval:PT1M}")
    public void expireOverdue() {
        try {
            int expired = confirmations.expireOverdue();
            if (expired > 0) {
                log.info("Agent confirmations expired: {}", expired);
            }
        } catch (RuntimeException e) {
            log.error("Agent confirmation expiry failed", e);
        }
    }
}
