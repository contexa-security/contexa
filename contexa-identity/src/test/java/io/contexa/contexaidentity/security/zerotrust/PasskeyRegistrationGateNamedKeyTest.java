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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The registration of a passkey reads the decision of the signed-in user, whatever the user is called. */
class PasskeyRegistrationGateNamedKeyTest {

    private static final String NAME = "console::rcboss";

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final PasskeyRegistrationGate gate = new PasskeyRegistrationGate(actions, () -> true, () -> false);
    private final Authentication user = new TestingAuthenticationToken(NAME, "x", "ROLE_USER");
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/webauthn/register/options");

    @Test
    @DisplayName("a BLOCK of the console stops no user named as its key")
    void theConsolesBlockStopsNoUserOfThatName() {
        actions.saveAction(NAME, ZeroTrustAction.BLOCK, Map.of());

        assertThat(gate.verdict(request, user)).isEqualTo(PasskeyRegistrationGate.Verdict.OPEN);
    }

    @Test
    @DisplayName("the user's own BLOCK stops the registration")
    void theUsersOwnBlockStopsIt() {
        actions.saveAction(ZeroTrustUserKey.person(NAME), ZeroTrustAction.BLOCK, Map.of());

        assertThat(gate.verdict(request, user)).isEqualTo(PasskeyRegistrationGate.Verdict.REFUSED);
    }
}
