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

import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * One sign-in is one decision: a sign-in that two parts of a login report in one request (the filter's event and the
 * login's own success) goes to the engine once.
 */
class SignInPublishedOnceTest {

    private final List<Object> events = new ArrayList<>();
    private final ZeroTrustEventPublisher publisher =
            new ZeroTrustEventPublisher(events::add, new TieredStrategyProperties());
    private final Authentication alice = UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());

    @Test
    @DisplayName("a sign-in reported twice in one request is published once")
    void aSignInReportedTwiceIsPublishedOnce() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");

        publisher.publishAuthenticationSuccess(alice, request, Map.of("authenticationType", "SINGLE"));
        publisher.publishAuthenticationSuccess(alice, request, Map.of("authenticationType", "MFA"));

        assertThat(events).hasSize(1);
        assertThat(((ZeroTrustSpringEvent) events.get(0)).getPayload()).containsEntry("authenticationType", "SINGLE");
    }

    @Test
    @DisplayName("the sign-ins of two requests are two sign-ins")
    void twoRequestsAreTwoSignIns() {
        publisher.publishAuthenticationSuccess(alice, new MockHttpServletRequest("POST", "/login"), Map.of());
        publisher.publishAuthenticationSuccess(alice, new MockHttpServletRequest("POST", "/login"), Map.of());

        assertThat(events).hasSize(2);
    }

    @Test
    @DisplayName("without a request each report is published, as nothing ties them")
    void withoutARequestEachIsPublished() {
        publisher.publishAuthenticationSuccess(alice, null, Map.of());
        publisher.publishAuthenticationSuccess(alice, null, Map.of());

        assertThat(events).hasSize(2);
    }
}
