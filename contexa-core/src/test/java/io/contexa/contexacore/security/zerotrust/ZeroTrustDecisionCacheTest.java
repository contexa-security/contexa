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
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * The few seconds a session's decision is remembered. Only an ALLOW is: a request right after a decision landed read the
 * PENDING of the request before it, and a method policy on the decision refused it (measured I5: 403 with an ALLOW in
 * force); a user who just answered a CHALLENGE would be held to it the same way.
 */
class ZeroTrustDecisionCacheTest {

    private static final String USER = "full-i5a";
    private static final String ACTION_ATTRIBUTE = "contexa.zeroTrustAction";

    private final InMemoryZeroTrustActionRepository store = new InMemoryZeroTrustActionRepository();
    private final ZeroTrustActionRepository actions = spy(store);
    private final InMemoryZeroTrustSecurityService service = new InMemoryZeroTrustSecurityService(
            mock(ThreatScoreUtil.class), new SecurityZeroTrustProperties(), actions, new InMemoryBlockingSignalBroadcaster());
    private final Authentication authentication = new TestingAuthenticationToken(USER, null, "ROLE_USER");

    private MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/rc/unverified/1");
        request.setRequestedSessionId("session-1");
        request.setRemoteAddr("198.51.100.1");
        return request;
    }

    private String context() {
        return SessionFingerprintUtil.generateContextBindingHash(request(), authentication);
    }

    private ZeroTrustAction readOnANewRequest() {
        MockHttpServletRequest request = request();
        SecurityContext context = new SecurityContextImpl(authentication);
        service.applyZeroTrustToContext(context, USER, "session-1", request);
        return (ZeroTrustAction) request.getAttribute(ACTION_ATTRIBUTE);
    }

    @Test
    @DisplayName("the next request reads a decision that landed, not the PENDING of the request before it")
    void aDecisionThatLandedIsRead() {
        assertThat(readOnANewRequest()).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);

        store.saveAction(USER, ZeroTrustAction.ALLOW, Map.of("contextBindingHash", context()));

        assertThat(readOnANewRequest()).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("a CHALLENGE answered holds nobody back")
    void anAnsweredChallengeIsRead() {
        store.saveAction(USER, ZeroTrustAction.CHALLENGE, Map.of());
        assertThat(readOnANewRequest()).isEqualTo(ZeroTrustAction.CHALLENGE);

        store.saveActionWithPrevious(USER, ZeroTrustAction.ALLOW, context());

        assertThat(readOnANewRequest()).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("an ALLOW is remembered for the moment: the requests of a page read the store once")
    void anAllowIsRemembered() {
        store.saveAction(USER, ZeroTrustAction.ALLOW, Map.of("contextBindingHash", context()));

        assertThat(readOnANewRequest()).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(readOnANewRequest()).isEqualTo(ZeroTrustAction.ALLOW);

        verify(actions, times(1)).getCurrentAction(anyString(), anyString());
    }
}
