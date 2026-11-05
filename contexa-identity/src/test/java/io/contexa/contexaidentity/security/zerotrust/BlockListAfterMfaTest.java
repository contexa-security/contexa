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

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.store.InMemoryBlockMfaStateStore;
import io.contexa.contexacore.autonomous.utils.InMemoryThreatScoreUtil;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.zerotrust.InMemoryZeroTrustSecurityService;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import java.time.Duration;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Under CONTEXA_OWNED the console and the application share one account, so the only administrator under a BLOCK
 * had nobody to lift it. An administrator who passed MFA in this session reaches the block list, and nothing else.
 */
class BlockListAfterMfaTest {

    private static final String SESSION = "session-of-the-administrator";
    private static final String ADDRESS = "203.0.113.7";
    private static final String BROWSER = "the administrator's browser";
    private static final String BLOCK_LIST = "/contexa/admin/blacklist";

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final InMemoryBlockMfaStateStore verifications = new InMemoryBlockMfaStateStore(actions);
    private final ZeroTrustAccessControlFilter filter = new ZeroTrustAccessControlFilter(actions,
            mock(AuthResponseWriter.class), mock(IBlockedUserRecorder.class), null, mock(AuthUrlProvider.class), null, 2);
    private final SecurityZeroTrustProperties settings = new SecurityZeroTrustProperties();
    private final InMemoryZeroTrustSecurityService zeroTrust = new InMemoryZeroTrustSecurityService(
            new InMemoryThreatScoreUtil(settings), settings, actions, new InMemoryBlockingSignalBroadcaster());
    private MockHttpServletRequest last;
    private boolean passed;
    private Authentication behindTheFilter;

    @BeforeEach
    void anAdministratorUnderABlock() {
        filter.setBlockMfaStateStore(verifications);
        signedIn("rcboss", "ROLE_ADMIN");
        blocked("rcboss");
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static void signedIn(String name, String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(name, "x", authorities));
    }

    private void blocked(String key) {
        actions.saveAction(key, ZeroTrustAction.BLOCK, Map.of());
        actions.setBlockedFlag(key);
    }

    private static String context() {
        return SessionFingerprintUtil.generateContextBindingHash(SESSION, ADDRESS, BROWSER);
    }

    private void passedMfa(String key) {
        verifications.setVerified(key, context());
    }

    private MockHttpServletResponse send(String method, String path, String session, String address, String browser)
            throws Exception {
        last = new MockHttpServletRequest(method, path);
        last.setRequestedSessionId(session);
        last.setRemoteAddr(address);
        last.addHeader("User-Agent", browser);
        MockHttpServletResponse response = new MockHttpServletResponse();
        passed = false;
        behindTheFilter = null;
        filter.doFilter(last, response, (request, sent) -> {
            passed = true;
            behindTheFilter = SecurityContextHolder.getContext().getAuthentication();
        });
        return response;
    }

    private MockHttpServletResponse get(String path) throws Exception {
        return send("GET", path, SESSION, ADDRESS, BROWSER);
    }

    @Test
    @DisplayName("without MFA the block list stays shut")
    void withoutMfaItStaysShut() throws Exception {
        MockHttpServletResponse response = get(BLOCK_LIST);

        assertThat(passed).isFalse();
        assertThat(response.getRedirectedUrl()).isEqualTo("/contexa/zero-trust/blocked");
        assertThat(ConsoleSession.onReleasePath(last)).isFalse();
    }

    @Test
    @DisplayName("session reuse: the verification of one session opens nothing in another of the same account")
    void anotherSessionOfTheAccount() throws Exception {
        passedMfa("rcboss");

        send("GET", BLOCK_LIST, "a-stolen-session", ADDRESS, BROWSER);
        assertThat(passed).as("another session").isFalse();

        send("GET", BLOCK_LIST, SESSION, "198.51.100.20", BROWSER);
        assertThat(passed).as("the session from another address").isFalse();

        send("GET", BLOCK_LIST, SESSION, ADDRESS, "curl/8.0");
        assertThat(passed).as("the session from another client").isFalse();

        send("GET", BLOCK_LIST, null, ADDRESS, BROWSER);
        assertThat(passed).as("no session at all").isFalse();
    }

    @Test
    @DisplayName("a verification kept without its context opens nothing")
    void aVerificationWithoutAContext() throws Exception {
        verifications.setVerified("rcboss");

        get(BLOCK_LIST);

        assertThat(passed).isFalse();
    }

    @Test
    @DisplayName("another account's verification opens nothing")
    void anotherAccount() throws Exception {
        passedMfa("someone-else");

        get(BLOCK_LIST);

        assertThat(passed).isFalse();
    }

    @Test
    @DisplayName("a user who is no administrator passes MFA and meets the block as before")
    void aUserWhoIsNoAdministrator() throws Exception {
        signedIn("plain", "ROLE_USER");
        blocked("plain");
        passedMfa("plain");

        MockHttpServletResponse response = get(BLOCK_LIST);

        assertThat(passed).isFalse();
        assertThat(response.getRedirectedUrl()).isEqualTo("/contexa/zero-trust/blocked");
    }

    @Test
    @DisplayName("an authority that only looks like the administrator's opens nothing")
    void aLookalikeAuthority() throws Exception {
        signedIn("rcboss", "ROLE_ADMINISTRATOR", "role_admin", "ADMIN");
        passedMfa("rcboss");

        get(BLOCK_LIST);

        assertThat(passed).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/contexa/admin", "/contexa/admin/users", "/contexa/admin/api/users", "/contexa/admin/blacklistX",
            "/contexa/admin/api/blacklistX", "/contexa/admin/blacklist/agents", "/contexa/admin/blacklist/agents/kill-switch",
            "/contexa/admin/blacklist/agents/release-agent", "/contexa/admin/blacklist/../users",
            "/contexa/admin/blacklist/..;/users", "/contexa/admin/blacklist;a=b/../users", "/contexa/admin/blacklist/%2e%2e/users",
            "/contexa/admin/blacklist%2f..%2fusers", "//contexa/admin/blacklist", "/orders"})
    @DisplayName("MFA opens the block list and nothing else of the console or the application")
    void nothingElseOpens(String path) throws Exception {
        passedMfa("rcboss");

        get(path);

        assertThat(passed).isFalse();
        assertThat(ConsoleSession.onReleasePath(last)).isFalse();
    }

    @Test
    @DisplayName("a verification that lapsed opens nothing")
    void aLapsedVerification() throws Exception {
        InMemoryBlockMfaStateStore shortLived = new InMemoryBlockMfaStateStore(actions, Duration.ofMillis(1));
        filter.setBlockMfaStateStore(shortLived);
        shortLived.setVerified("rcboss", context());
        Thread.sleep(20);

        get(BLOCK_LIST);

        assertThat(passed).isFalse();
    }

    @Test
    @DisplayName("session reuse: the verification of a BLOCK released earlier answers no new BLOCK")
    void aVerificationOfAnEarlierBlock() throws Exception {
        passedMfa("rcboss");
        actions.approveOverrideAtomically("rcboss", ZeroTrustAction.ALLOW);
        blocked("rcboss");

        get(BLOCK_LIST);

        assertThat(passed).isFalse();
    }

    @Test
    @DisplayName("where the application owns sign-in the application's chain opens nothing: the console has its own")
    void hostOwnedOpensNothingHere() throws Exception {
        filter.setHostOwnedStepUp(mock(HostOwnedStepUp.class));
        passedMfa("rcboss");

        get(BLOCK_LIST);

        assertThat(passed).isFalse();
    }

    @Test
    @DisplayName("without a store of verifications nothing opens")
    void noStore() throws Exception {
        passedMfa("rcboss");
        filter.setBlockMfaStateStore(null);

        get(BLOCK_LIST);

        assertThat(passed).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/contexa/admin/blacklist", "/contexa/admin/blacklist/7", "/contexa/admin/api/blacklist",
            "/contexa/admin/api/blacklist/7"})
    @DisplayName("the administrator who passed MFA in this session reads the block list")
    void theListOpens(String path) throws Exception {
        passedMfa("rcboss");

        get(path);

        assertThat(passed).isTrue();
        assertThat(ConsoleSession.onReleasePath(last)).as("what stands behind the filter is told").isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/contexa/admin/blacklist/7/resolve", "/contexa/admin/api/blacklist/7/resolve"})
    @DisplayName("and can post to it, which is the way out")
    void theReleaseOpens(String path) throws Exception {
        passedMfa("rcboss");

        send("POST", path, SESSION, ADDRESS, BROWSER);

        assertThat(passed).isTrue();
    }

    /**
     * The session of an account as a request reads it. Loading the context applies the decision in force, so under a BLOCK
     * the authentication has the authority of the BLOCK alone, and the object is the one the session holds.
     */
    private SecurityContext sessionOf(String name, String authority) {
        UnifiedCustomUserDetails account = new UnifiedCustomUserDetails(UserDto.builder().username(name).build(),
                Set.of(new SimpleGrantedAuthority(authority)));
        SecurityContext session = new SecurityContextImpl(
                UsernamePasswordAuthenticationToken.authenticated(account, "x", account.getAuthorities()));
        zeroTrust.applyZeroTrustToContext(session, name, null, new MockHttpServletRequest());
        SecurityContextHolder.setContext(session);
        return session;
    }

    private static Set<String> authoritiesOf(Authentication authentication) {
        return AuthorityUtils.authorityListToSet(authentication.getAuthorities());
    }

    @Test
    @DisplayName("the session of the administrator has the BLOCK's authority alone, and the block list opens all the same")
    void theListOpensToTheSessionABlockNarrowed() throws Exception {
        SecurityContext session = sessionOf("rcboss", "ROLE_ADMIN");
        assertThat(authoritiesOf(session.getAuthentication())).containsExactly("ROLE_BLOCKED");
        passedMfa("rcboss");

        get(BLOCK_LIST);

        assertThat(passed).isTrue();
    }

    @Test
    @DisplayName("what stands behind the filter asks for the administrator's authority, so the request has it")
    void theRequestHasTheAdministratorsAuthority() throws Exception {
        sessionOf("rcboss", "ROLE_ADMIN");
        passedMfa("rcboss");

        get(BLOCK_LIST);

        assertThat(authoritiesOf(behindTheFilter)).contains("ROLE_ADMIN").doesNotContain("ROLE_BLOCKED");
        assertThat(behindTheFilter.getName()).isEqualTo("rcboss");
    }

    @Test
    @DisplayName("the authority lasts for the request: the session keeps what the BLOCK left it")
    void theSessionStaysNarrowed() throws Exception {
        SecurityContext session = sessionOf("rcboss", "ROLE_ADMIN");
        Authentication narrowed = session.getAuthentication();
        passedMfa("rcboss");

        get(BLOCK_LIST);

        assertThat(session.getAuthentication()).isSameAs(narrowed);
        assertThat(SecurityContextHolder.getContext()).isSameAs(session);
    }

    @Test
    @DisplayName("the authority is gone from the context when the chain fails too")
    void aFailureBehindTheFilterEndsTheAuthorityToo() {
        SecurityContext session = sessionOf("rcboss", "ROLE_ADMIN");
        passedMfa("rcboss");
        last = new MockHttpServletRequest("GET", BLOCK_LIST);
        last.setRequestedSessionId(SESSION);
        last.setRemoteAddr(ADDRESS);
        last.addHeader("User-Agent", BROWSER);

        assertThatThrownBy(() -> filter.doFilter(last, new MockHttpServletResponse(), (request, sent) -> {
            throw new IllegalStateException("the page failed");
        })).isInstanceOf(IllegalStateException.class);

        assertThat(SecurityContextHolder.getContext()).isSameAs(session);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/contexa/admin", "/contexa/admin/users", "/contexa/admin/blacklist/agents/kill-switch", "/orders"})
    @DisplayName("past the block list a verified session stays what the BLOCK left it")
    void elsewhereTheSessionStaysNarrowed(String path) throws Exception {
        sessionOf("rcboss", "ROLE_ADMIN");
        passedMfa("rcboss");

        get(path);

        assertThat(passed).isFalse();
    }

    @Test
    @DisplayName("a narrowed session without MFA does not reach the block list")
    void aNarrowedSessionWithoutMfa() throws Exception {
        sessionOf("rcboss", "ROLE_ADMIN");

        get(BLOCK_LIST);

        assertThat(passed).isFalse();
    }

    @Test
    @DisplayName("a narrowed session of an account that is no administrator's does not reach it after MFA")
    void aNarrowedSessionOfAPlainAccount() throws Exception {
        blocked("plain");
        sessionOf("plain", "ROLE_USER");
        passedMfa("plain");

        get(BLOCK_LIST);

        assertThat(passed).isFalse();
    }

    @Test
    @DisplayName("a user who is not blocked goes on as ever and nothing marks the request")
    void nobodyBlocked() throws Exception {
        signedIn("calm", "ROLE_ADMIN");

        get(BLOCK_LIST);

        assertThat(passed).isTrue();
        assertThat(ConsoleSession.onReleasePath(last)).isFalse();
    }
}
