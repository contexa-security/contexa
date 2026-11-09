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
package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.BridgedUser;
import io.contexa.contexacommon.security.bridge.HeaderAuthBridge;
import io.contexa.contexacommon.security.bridge.authentication.HostPrincipalSnapshot;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The authorities of the header are a list the caller writes. A name it repeats or an element it leaves empty must not
 * stop the bridge from reading the request: the bridge once threw on both, and the request's whole bridge was lost.
 */
class HeaderAuthBridgeTest {

    private static final String PROXY = "10.0.0.1";

    private static HeaderAuthBridge bridge() {
        BridgeProperties properties = new BridgeProperties();
        properties.getAuthentication().getHeaders().setEnabled(true);
        properties.getNetwork().setTrustedProxies(List.of(PROXY));
        return new HeaderAuthBridge(properties);
    }

    /** A request from the trusted proxy whose header names the principal the host authenticated. */
    private static MockHttpServletRequest requestWithAuthorities(String authorities) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/profile");
        request.setRemoteAddr(PROXY);
        request.setAttribute(BridgeRequestAttributes.HOST_PRINCIPAL_SNAPSHOT,
                new HostPrincipalSnapshot("alice", Set.of("ROLE_USER"), Map.of()));
        request.addHeader("X-Contexa-Principal-Id", "alice");
        if (authorities != null) {
            request.addHeader("X-Contexa-Authorities", authorities);
        }
        return request;
    }

    @Test
    void readsTheAuthoritiesOfTheHeader() {
        BridgedUser user = bridge().extractUser(requestWithAuthorities("ROLE_USER,REPORT_EXPORT"));

        assertThat(user).isNotNull();
        assertThat(user.username()).isEqualTo("alice");
        assertThat(user.roles()).containsExactlyInAnyOrder("ROLE_USER", "REPORT_EXPORT");
    }

    @Test
    void readsANameTheHeaderRepeatsOnce() {
        BridgedUser user = bridge().extractUser(requestWithAuthorities("ROLE_USER, ROLE_USER,REPORT_EXPORT"));

        assertThat(user).isNotNull();
        assertThat(user.roles()).containsExactlyInAnyOrder("ROLE_USER", "REPORT_EXPORT");
    }

    @Test
    void takesNoEmptyElementForAnAuthority() {
        assertThat(bridge().extractUser(requestWithAuthorities("ROLE_USER,,,REPORT_EXPORT")).roles())
                .containsExactlyInAnyOrder("ROLE_USER", "REPORT_EXPORT");
        assertThat(bridge().extractUser(requestWithAuthorities(",ROLE_USER, ,")).roles())
                .containsExactly("ROLE_USER");
    }

    @Test
    void trimsTheSpacesAroundAName() {
        assertThat(bridge().extractUser(requestWithAuthorities("  ROLE_USER ,  REPORT_EXPORT  ")).roles())
                .containsExactlyInAnyOrder("ROLE_USER", "REPORT_EXPORT");
    }

    @Test
    void readsAHeaderWithoutAuthoritiesAsNone() {
        assertThat(bridge().extractUser(requestWithAuthorities(null)).roles()).isEmpty();
        assertThat(bridge().extractUser(requestWithAuthorities("  ")).roles()).isEmpty();
    }
}
