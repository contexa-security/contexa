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
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.resolver.SessionDelegationStampResolver;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.agent.AgentConfirmationService;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * What an application keeps in the session for its own pages is no delegation: a person under a CHALLENGE stays under
 * it whatever the session holds, and only the attribute the application names as its delegation moves a request to an
 * agent's decision.
 */
class SessionValuesAreNoDelegationTest {

    /** A bean of a domain with agents that an application keeps in the session; it names an agent, it is no delegation. */
    public static class PolicyForm {
        public String getAgentId() {
            return "sales-agent-7";
        }
    }

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final AgentConfirmationService confirmations = mock(AgentConfirmationService.class);
    private final BridgeProperties properties = new BridgeProperties();
    private ZeroTrustChallengeFilter filter;
    private MockHttpSession session;

    @BeforeEach
    void setUp() {
        filter = new ZeroTrustChallengeFilter(mock(ChallengeMfaInitializer.class), mock(AuthResponseWriter.class),
                mock(AuthUrlProvider.class), mock(MfaSessionRepository.class), mock(MfaStateMachineIntegrator.class),
                mock(DistributedLockService.class), null, actions);
        HostOwnedStepUp stepUp = mock(HostOwnedStepUp.class);
        when(stepUp.stepUpUrl(any())).thenReturn("/contexa/step-up");
        filter.setHostOwnedStepUp(stepUp);
        when(confirmations.request(any())).thenReturn(Optional.empty());
        filter.setAgentConfirmationGate(new AgentConfirmationGate(confirmations, actions, mock(AuthResponseWriter.class),
                1024, null, null));
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("alice", null, "ROLE_USER"));
        session = new MockHttpSession();
        actions.saveAction("alice", ZeroTrustAction.CHALLENGE, Map.of());
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private Optional<DelegationStamp> stamp() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setSession(session);
        return new SessionDelegationStampResolver().resolve(request, null, properties);
    }

    private boolean reachesTheApplication() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setSession(session);
        new SessionDelegationStampResolver().resolve(request, null, properties)
                .ifPresent(stamp -> request.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, stamp));
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        return chain.getRequest() != null;
    }

    @Test
    @DisplayName("a person under a CHALLENGE is stopped")
    void aPersonUnderAChallengeIsStopped() throws Exception {
        assertThat(reachesTheApplication()).isFalse();
    }

    @Test
    @DisplayName("a map of request values kept in the session does not move the person off the CHALLENGE")
    void aMapOfRequestValues() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("q", "laptop");
        params.put("agentId", "x");
        params.put("delegated", "true");
        session.setAttribute("lastSearch", params);

        assertThat(stamp()).isEmpty();
        assertThat(reachesTheApplication()).isFalse();
    }

    @Test
    @DisplayName("the parameter map of a servlet request kept in the session is no delegation")
    void theParameterMapOfAServletRequest() throws Exception {
        Map<String, String[]> params = new HashMap<>();
        params.put("agentId", new String[]{"x"});
        params.put("delegated", new String[]{"true"});
        session.setAttribute("lastSearch", params);

        assertThat(stamp()).isEmpty();
        assertThat(reachesTheApplication()).isFalse();
    }

    @Test
    @DisplayName("a new agent ID in the session does not leave the agent key's CHALLENGE behind")
    void aNewAgentIdInTheSession() throws Exception {
        session.setAttribute("wizard", new HashMap<>(Map.of("agentId", "x", "delegated", true)));
        assertThat(reachesTheApplication()).isFalse();

        session.setAttribute("wizard", new HashMap<>(Map.of("agentId", "y", "delegated", true)));

        assertThat(stamp()).isEmpty();
        assertThat(reachesTheApplication()).isFalse();
    }

    @Test
    @DisplayName("a bean with an agent ID only sends the person to the step-up, never to an agent's confirmation")
    void aBeanWithAnAgentIdOnly() throws Exception {
        session.setAttribute("policyForm", new PolicyForm());

        assertThat(stamp()).isEmpty();
        assertThat(reachesTheApplication()).isFalse();
        verify(confirmations, never()).request(any());
    }

    @Test
    @DisplayName("the attribute the application names as its delegation moves the request to the agent's decision")
    void theNamedAttribute() {
        properties.getDelegation().getSession().setAttribute("agentDelegation");
        session.setAttribute("agentDelegation", new HashMap<>(Map.of("agentId", "x", "delegated", true)));
        session.setAttribute("lastSearch", new HashMap<>(Map.of("agentId", "y", "delegated", true)));

        DelegationStamp stamp = stamp().orElseThrow();

        assertThat(stamp.agentId()).isEqualTo("x");
        assertThat(stamp.delegated()).isTrue();
        assertThat(ZeroTrustSubject.of("alice", stamp).storageKey()).isEqualTo("alice::agent::x");
    }
}
