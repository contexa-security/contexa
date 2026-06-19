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
package io.contexa.contexacore.hcad.trigger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class HcadActorSessionKeyFactoryTest {

    @Test
    @DisplayName("actor session key should ignore method and path fan-out")
    void fromRequest_sameSessionDifferentPath_shouldReturnSameKey() {
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken("alice", "n/a", List.of());
        MockHttpServletRequest first = request("GET", "/api/dashboard", "session-1", "203.0.113.10", "JUnit");
        MockHttpServletRequest second = request("POST", "/api/menus?refresh=true", "session-1", "203.0.113.10", "JUnit");

        String firstKey = HcadActorSessionKeyFactory.fromRequest(first, auth);
        String secondKey = HcadActorSessionKeyFactory.fromRequest(second, auth);

        assertThat(firstKey).isNotBlank();
        assertThat(secondKey).isEqualTo(firstKey);
    }

    @Test
    @DisplayName("actor session key should change for different session, IP, user agent, or user")
    void fromRequest_contextChanges_shouldReturnDifferentKeys() {
        UsernamePasswordAuthenticationToken alice =
                new UsernamePasswordAuthenticationToken("alice", "n/a", List.of());
        String baseline = HcadActorSessionKeyFactory.fromRequest(
                request("GET", "/api/dashboard", "session-1", "203.0.113.10", "JUnit"),
                alice);

        assertThat(HcadActorSessionKeyFactory.fromRequest(
                request("GET", "/api/dashboard", "session-2", "203.0.113.10", "JUnit"),
                alice)).isNotEqualTo(baseline);
        assertThat(HcadActorSessionKeyFactory.fromRequest(
                request("GET", "/api/dashboard", "session-1", "203.0.113.11", "JUnit"),
                alice)).isNotEqualTo(baseline);
        assertThat(HcadActorSessionKeyFactory.fromRequest(
                request("GET", "/api/dashboard", "session-1", "203.0.113.10", "Different"),
                alice)).isNotEqualTo(baseline);
        assertThat(HcadActorSessionKeyFactory.fromRequest(
                request("GET", "/api/dashboard", "session-1", "203.0.113.10", "JUnit"),
                new UsernamePasswordAuthenticationToken("bob", "n/a", List.of()))).isNotEqualTo(baseline);
    }

    @Test
    @DisplayName("legacy base and trigger keys should not include method or path")
    void pendingAnomalyKeys_methodAndPath_shouldNotChangeBaseOrTriggerKeys() {
        String firstBase = PendingAnomalyKeyFactory.buildBaseKey("alice", "ctx-1", "GET", "/api/a");
        String secondBase = PendingAnomalyKeyFactory.buildBaseKey("alice", "ctx-1", "POST", "/api/b");
        String firstTrigger = PendingAnomalyKeyFactory.buildTriggerKey("alice", "ctx-1", "GET", "/api/a", "risk");
        String secondTrigger = PendingAnomalyKeyFactory.buildTriggerKey("alice", "ctx-1", "POST", "/api/b", "risk");

        assertThat(secondBase).isEqualTo(firstBase);
        assertThat(secondTrigger).isEqualTo(firstTrigger);
    }

    @Test
    @DisplayName("trusted signal signature should be anchored so corroborating fan-out does not create a new trigger")
    void trustedSignalSignature_anchorStableForCorroboratingFanOut() {
        String first = PendingAnomalyKeyFactory.buildTrustedSignalSignature(
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("REQUEST_BURST"));
        String second = PendingAnomalyKeyFactory.buildTrustedSignalSignature(
                List.of("IMPOSSIBLE_TRAVEL"),
                List.of("RAPID_SEQUENCE", "PREVIOUS_PATH_JUMP"));
        String third = PendingAnomalyKeyFactory.buildTrustedSignalSignature(
                List.of("FAILED_LOGIN_BURST"),
                List.of("REQUEST_BURST"));

        assertThat(second).isEqualTo(first);
        assertThat(third).isNotEqualTo(first);
    }

    private MockHttpServletRequest request(
            String method,
            String path,
            String sessionId,
            String remoteAddr,
            String userAgent) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setRequestedSessionId(sessionId);
        request.setRemoteAddr(remoteAddr);
        request.addHeader("User-Agent", userAgent);
        return request;
    }
}
