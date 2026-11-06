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
package io.contexa.contexacore.security.zerotrust;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** A sign-out and a dropped decision of a person named as an internal key reach the person's key, never that key. */
class ZeroTrustNamedKeyLogoutTest {

    private static final String NAME = "console::admin";
    private static final String ACTION_ATTRIBUTE = "contexa.zeroTrustAction";

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final InMemoryZeroTrustSecurityService service = new InMemoryZeroTrustSecurityService(
            mock(ThreatScoreUtil.class), new SecurityZeroTrustProperties(), actions,
            new InMemoryBlockingSignalBroadcaster());
    private final String own = ZeroTrustUserKey.person(NAME);

    @Test
    void theLogoutClearsThePersonsDecisionAndLeavesTheConsoles() {
        actions.saveAction(NAME, ZeroTrustAction.ALLOW, Map.of());
        actions.saveAction(own, ZeroTrustAction.ALLOW, Map.of());

        service.cleanupOnLogout(NAME, null);

        assertThat(actions.getCurrentAction(NAME)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(actions.getCurrentAction(own)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    void aDroppedDecisionIsThePersonsTheCacheKept() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        SecurityContext context = new SecurityContextImpl(new TestingAuthenticationToken(NAME, "n/a", "ROLE_USER"));
        context.getAuthentication().setAuthenticated(true);
        actions.saveAction(own, ZeroTrustAction.ALLOW, Map.of());
        service.applyZeroTrustToContext(context, NAME, null, request);
        assertThat(request.getAttribute(ACTION_ATTRIBUTE)).isEqualTo(ZeroTrustAction.ALLOW);

        actions.saveAction(own, ZeroTrustAction.BLOCK, Map.of());
        service.invalidateDecisionCache(NAME);
        service.applyZeroTrustToContext(context, NAME, null, request);

        assertThat(request.getAttribute(ACTION_ATTRIBUTE)).isEqualTo(ZeroTrustAction.BLOCK);
    }
}
