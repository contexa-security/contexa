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
package io.contexa.contexacore.autonomous.event.support;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ZeroTrustSecurityEventConverterTest {

    private static ZeroTrustSpringEvent signIn(Map<String, Object> payload) {
        return ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS)
                .userId("alice")
                .payload(payload)
                .build();
    }

    /** PR-24: a sign-in has no request id of its own, so its rows had only the event id and a search by request found none. */
    @Test
    void anEventWithoutARequestIdIsFoundByItsEventId() {
        SecurityEvent event = ZeroTrustSecurityEventConverter.convert(signIn(new HashMap<>()));

        assertThat(event.getEventId()).isNotBlank();
        assertThat(event.getMetadata())
                .containsEntry("requestId", event.getEventId())
                .containsEntry("correlationId", event.getEventId());
    }

    @Test
    void aRequestIdTheEventCarriesStays() {
        Map<String, Object> payload = new HashMap<>();
        payload.put("eventId", "event-1");
        payload.put("requestId", "request-1");
        payload.put("correlationId", "correlation-1");

        SecurityEvent event = ZeroTrustSecurityEventConverter.convert(signIn(payload));

        assertThat(event.getMetadata())
                .containsEntry("requestId", "request-1")
                .containsEntry("correlationId", "correlation-1");
    }

    @Test
    void anEventThatCarriesOneOfTheTwoKeepsItAndTheOtherFollows() {
        Map<String, Object> payload = new HashMap<>();
        payload.put("correlationId", "correlation-1");

        SecurityEvent event = ZeroTrustSecurityEventConverter.convert(signIn(payload));

        assertThat(event.getMetadata())
                .containsEntry("requestId", "correlation-1")
                .containsEntry("correlationId", "correlation-1");
    }
}
