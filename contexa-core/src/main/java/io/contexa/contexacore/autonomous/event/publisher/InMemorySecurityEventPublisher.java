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
package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.autonomous.event.SecurityEventCollector;
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.InMemorySecurityEventCollector;
import io.contexa.contexacore.autonomous.event.support.ZeroTrustSecurityEventConverter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * In-memory implementation of SecurityEventPublisher for standalone mode.
 * Dispatches events directly to InMemorySecurityEventCollector without Kafka.
 */
@Slf4j
@RequiredArgsConstructor
public class InMemorySecurityEventPublisher implements SecurityEventPublisher {

    private final SecurityEventCollector eventCollector;

    @Override
    public void publishGenericSecurityEvent(ZeroTrustSpringEvent event) {
        if (event == null) {
            return;
        }

        try {
            var securityEvent = ZeroTrustSecurityEventConverter.convert(event);
            if (eventCollector instanceof InMemorySecurityEventCollector inMemoryCollector) {
                inMemoryCollector.dispatchEvent(securityEvent);
            }
        } catch (Exception e) {
            log.error("Failed to publish in-memory security event: userId={}", event.getUserId(), e);
        }
    }
}
