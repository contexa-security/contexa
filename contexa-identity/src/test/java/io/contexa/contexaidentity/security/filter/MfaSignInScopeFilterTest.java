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
package io.contexa.contexaidentity.security.filter;

import io.contexa.contexacommon.security.bridge.AuthenticationMethodReferences;
import io.contexa.contexaidentity.security.handler.login.LoginFactsDetails;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The scope of an MFA flow takes only the logins that meet it (D-B1): a password login of a form flow in the same state
 * was a login on the paths of the MFA flow too.
 */
class MfaSignInScopeFilterTest {

    private static final String FLOW = "mfa_secure";

    private final AuthUrlProvider flowUrls = mock(AuthUrlProvider.class);

    @BeforeEach
    void flowAddresses() {
        when(flowUrls.getMfaInProgressUrls()).thenReturn(Set.of("/secure/mfa/login", "/secure/login/mfa-ott"));
    }

    @AfterEach
    void signOut() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void aPasswordLoginOfAnotherFlowIsNoLoginOnTheFlowsPaths() throws Exception {
        Authentication seen = pass(new MfaSignInScopeFilter(FLOW, 1, flowUrls), "/secure/reports",
                login(null, AuthenticationMethodReferences.PASSWORD));

        assertThat(seen).isInstanceOf(AnonymousAuthenticationToken.class);
    }

    /** Nothing is saved: the login stays for the other flows once the request is over. */
    @Test
    void theLoginItselfIsLeftAsItWas() throws Exception {
        Authentication login = login(null, AuthenticationMethodReferences.PASSWORD);
        MfaSignInScopeFilter filter = new MfaSignInScopeFilter(FLOW, 1, flowUrls);

        pass(filter, "/secure/reports", login);

        assertThat(login.isAuthenticated()).isTrue();
        assertThat(login.getDetails()).isInstanceOf(LoginFactsDetails.class);
    }

    /** Its policy asked for no factor: the flow itself completed the login with the password. */
    @Test
    void aLoginTheFlowCompletedCountsWhateverItsFactors() throws Exception {
        Authentication login = login(FLOW, AuthenticationMethodReferences.PASSWORD);

        assertThat(pass(new MfaSignInScopeFilter(FLOW, 1, flowUrls), "/secure/reports", login)).isSameAs(login);
    }

    @Test
    void aLoginWithAsManyFactorsCountsFromAnyFlow() throws Exception {
        Authentication login = login("mfa_other", AuthenticationMethodReferences.PASSWORD,
                AuthenticationMethodReferences.ONE_TIME_CODE);

        assertThat(pass(new MfaSignInScopeFilter(FLOW, 1, flowUrls), "/secure/reports", login)).isSameAs(login);
    }

    @Test
    void aLoginWithFewerFactorsThanTheFlowAsksForIsNoLogin() throws Exception {
        Authentication login = login("mfa_other", AuthenticationMethodReferences.PASSWORD,
                AuthenticationMethodReferences.ONE_TIME_CODE);

        assertThat(pass(new MfaSignInScopeFilter(FLOW, 2, flowUrls), "/secure/reports", login))
                .isInstanceOf(AnonymousAuthenticationToken.class);
    }

    @Test
    void aZeroTrustChallengePassedIsTheOneFactorMore() throws Exception {
        LoginFactsDetails password = facts(null, AuthenticationMethodReferences.PASSWORD);
        Authentication login = token(LoginFactsDetails.challengeVerified(null, null, password, Instant.now()));

        assertThat(pass(new MfaSignInScopeFilter(FLOW, 1, flowUrls), "/secure/reports", login)).isSameAs(login);
        assertThat(pass(new MfaSignInScopeFilter(FLOW, 2, flowUrls), "/secure/reports", login))
                .isInstanceOf(AnonymousAuthenticationToken.class);
    }

    /** The flow's own sign-in and steps stay reachable: a person signed in elsewhere starts the MFA there. */
    @Test
    void theFlowsSignInAndStepsTakeAnyLogin() throws Exception {
        Authentication login = login(null, AuthenticationMethodReferences.PASSWORD);

        assertThat(pass(new MfaSignInScopeFilter(FLOW, 1, flowUrls), "/secure/mfa/login", login)).isSameAs(login);
    }

    /** A login method the application added itself carries no facts of a Contexa flow and is left to it. */
    @Test
    void aLoginWithoutTheFactsOfAContexaFlowIsLeftAsItIs() throws Exception {
        Authentication login = UsernamePasswordAuthenticationToken.authenticated("alice", null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));

        assertThat(pass(new MfaSignInScopeFilter(FLOW, 1, flowUrls), "/secure/reports", login)).isSameAs(login);
    }

    private static Authentication pass(MfaSignInScopeFilter filter, String path, Authentication login) throws Exception {
        SecurityContextHolder.setContext(new SecurityContextImpl(login));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setServletPath(path);
        AtomicReference<Authentication> seen = new AtomicReference<>();
        filter.doFilter(request, new MockHttpServletResponse(),
                (req, res) -> seen.set(SecurityContextHolder.getContext().getAuthentication()));
        return seen.get();
    }

    private static Authentication login(String flow, String... methods) {
        return token(facts(flow, methods));
    }

    private static LoginFactsDetails facts(String flow, String... methods) {
        LoginFactsDetails facts = new LoginFactsDetails("127.0.0.1", "session-1", List.of(methods), Instant.now());
        return flow != null ? facts.ofFlow(flow) : facts;
    }

    private static Authentication token(LoginFactsDetails facts) {
        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.authenticated("alice", null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        token.setDetails(facts);
        return token;
    }
}
