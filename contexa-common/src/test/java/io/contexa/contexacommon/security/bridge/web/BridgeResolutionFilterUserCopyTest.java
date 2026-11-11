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
package io.contexa.contexacommon.security.bridge.web;

import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.runtime.RequestPathDatabaseGuard;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The copy of the application's user is not waited for on the application's requests. Where the application owns the
 * sign-in the copy is synchronised once for the user's facts and then remembered; a user seen for the first time or with
 * changed facts is synchronised away from the request. Where Contexa owns the sign-in its own accounts need no copy, and
 * nothing is looked up for them.
 */
class BridgeResolutionFilterUserCopyTest {

    private final CountingCopies copies = new CountingCopies();
    private final RequestPathDatabaseGuard guard = new RequestPathDatabaseGuard(Duration.ofSeconds(1), 4);

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
        copies.release();
        guard.destroy();
    }

    // ----- HOST_OWNED -----

    @Test
    void theSameUserWithTheSameFactsIsNotSynchronisedAgain() throws Exception {
        BridgeResolutionFilter filter = filter(SecurityOwnershipMode.HOST_OWNED);
        Authentication alice = hostUser("alice", "ROLE_USER");

        signIn(alice);
        filter.resolveSignIn(request("/login", "203.0.113.5"), alice);
        assertThat(copies.calls("alice")).as("the sign-in waits for the copy").isEqualTo(1);

        for (int i = 0; i < 5; i++) {
            MockHttpServletRequest request = request("/orders/" + i, "203.0.113.5");
            filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
            assertThat(copyOf(request)).as("the copy remembered for the request").isNotNull();
            assertThat(copyOf(request).internalUserId()).isEqualTo(copies.idOf("alice"));
        }
        assertThat(copies.calls("alice")).as("synchronisations after the sign-in").isEqualTo(1);
    }

    @Test
    void changedFactsAreSynchronisedAgainAwayFromTheRequest() throws Exception {
        BridgeResolutionFilter filter = filter(SecurityOwnershipMode.HOST_OWNED);
        signedInAt(filter, hostUser("alice", "ROLE_USER"));

        Authentication promoted = hostUser("alice", "ROLE_USER", "ROLE_MANAGER");
        signIn(promoted);
        MockHttpServletRequest changed = request("/orders", "203.0.113.5");
        filter.doFilter(changed, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(copyOf(changed)).as("nothing remembered for the new facts yet").isNull();
        copies.awaitCalls("alice", 2);

        awaitCopy(filter, "/orders");
        assertThat(copies.calls("alice")).isEqualTo(2);

        MockHttpServletRequest otherAddress = request("/orders", "198.51.100.7");
        filter.doFilter(otherAddress, new MockHttpServletResponse(), new MockFilterChain());
        assertThat(copyOf(otherAddress)).as("the address is a fact of the copy").isNull();
        copies.awaitCalls("alice", 3);
    }

    @Test
    void oneUsersCopyIsNeverGivenToAnother() throws Exception {
        BridgeResolutionFilter filter = filter(SecurityOwnershipMode.HOST_OWNED);
        signedInAt(filter, hostUser("alice", "ROLE_USER"));

        signIn(hostUser("bob", "ROLE_USER"));
        MockHttpServletRequest bobs = request("/orders", "203.0.113.5");
        filter.doFilter(bobs, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(copyOf(bobs)).as("bob is not alice").isNull();
        copies.awaitCalls("bob", 1);
        MockHttpServletRequest bobsNext = awaitCopy(filter, "/orders");
        assertThat(copyOf(bobsNext).internalUserId()).isEqualTo(copies.idOf("bob")).isNotEqualTo(copies.idOf("alice"));
    }

    @Test
    void aUserSeenForTheFirstTimeDoesNotWaitForASlowDatabase() throws Exception {
        copies.slow();
        BridgeResolutionFilter filter = filter(SecurityOwnershipMode.HOST_OWNED);
        signIn(hostUser("carol", "ROLE_USER"));

        MockHttpServletRequest request = request("/orders", "203.0.113.5");
        long started = System.nanoTime();
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        assertThat(Duration.ofNanos(System.nanoTime() - started)).as("the request's time").isLessThan(Duration.ofMillis(200));
        assertThat(copyOf(request)).isNull();
        copies.awaitCalls("carol", 1);

        for (int i = 0; i < 3; i++) {
            long again = System.nanoTime();
            filter.doFilter(request("/orders", "203.0.113.5"), new MockHttpServletResponse(), new MockFilterChain());
            assertThat(Duration.ofNanos(System.nanoTime() - again)).as("the request's time").isLessThan(Duration.ofMillis(200));
        }
        assertThat(copies.calls("carol")).as("one synchronisation of the user at a time").isEqualTo(1);
    }

    // ----- CONTEXA_OWNED -----

    @Test
    void aSessionOfContexasOwnAccountIsLookedUpForNoCopy() throws Exception {
        BridgeResolutionFilter filter = filter(SecurityOwnershipMode.CONTEXA_OWNED);
        UnifiedCustomUserDetails admin = new UnifiedCustomUserDetails(UserDto.builder().id(1L).username("admin")
                .password("x").enabled(true).build(), Set.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        Authentication session = UsernamePasswordAuthenticationToken.authenticated(admin, null, admin.getAuthorities());

        signedInAt(filter, session);
        for (int i = 0; i < 3; i++) {
            filter.doFilter(request("/orders", "203.0.113.5"), new MockHttpServletResponse(), new MockFilterChain());
        }

        Thread.sleep(100);
        assertThat(copies.total()).as("lookups for an account of Contexa").isZero();
    }

    @Test
    void aTokenOfContexasOwnAccountIsLookedUpForNoCopy() throws Exception {
        BridgeResolutionFilter filter = filter(SecurityOwnershipMode.CONTEXA_OWNED);
        signIn(new JwtAuthenticationToken(jwt("admin", "default-client"), AuthorityUtils.createAuthorityList("ROLE_ADMIN")));

        for (int i = 0; i < 3; i++) {
            filter.doFilter(request("/orders", "203.0.113.5"), new MockHttpServletResponse(), new MockFilterChain());
        }

        Thread.sleep(100);
        assertThat(copies.total()).as("lookups for an account of Contexa").isZero();
    }

    /** A client's own token stands for no account: it keeps the copy it always had, synchronised once. */
    @Test
    void aClientsOwnTokenKeepsItsCopyWithoutALookupForEachRequest() throws Exception {
        BridgeResolutionFilter filter = filter(SecurityOwnershipMode.CONTEXA_OWNED);
        signIn(new JwtAuthenticationToken(jwt("svc-client", "svc-client"), AuthorityUtils.createAuthorityList("SCOPE_read")));

        filter.doFilter(request("/orders", "203.0.113.5"), new MockHttpServletResponse(), new MockFilterChain());
        copies.awaitCalls("svc-client", 1);
        MockHttpServletRequest next = awaitCopy(filter, "/orders");
        for (int i = 0; i < 3; i++) {
            filter.doFilter(request("/orders", "203.0.113.5"), new MockHttpServletResponse(), new MockFilterChain());
        }

        assertThat(copyOf(next).internalUserId()).isEqualTo(copies.idOf("svc-client"));
        assertThat(copies.calls("svc-client")).isEqualTo(1);
    }

    // ----- the filter -----

    private BridgeResolutionFilter filter(SecurityOwnershipMode ownership) {
        BridgeProperties properties = new BridgeProperties();
        properties.setOwnership(ownership);
        BooleanSupplier contexaAccountsSignIn = () -> true;
        return new BridgeResolutionFilter(properties, new RequestContextCollector(),
                List.of(new SecurityContextAuthenticationStampResolver()), List.of(), List.of(), new BridgeCoverageEvaluator(),
                copies, new BridgeRuntimeSupport(properties, copies, guard, contexaAccountsSignIn), null);
    }

    /** A request of the user once the copy is remembered for it; the synchronisation runs away from the requests. */
    private static MockHttpServletRequest awaitCopy(BridgeResolutionFilter filter, String path) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        MockHttpServletRequest request = request(path, "203.0.113.5");
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        while (copyOf(request) == null && System.nanoTime() < deadline) {
            Thread.sleep(10);
            request = request(path, "203.0.113.5");
            filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        }
        assertThat(copyOf(request)).as("the copy remembered once its synchronisation ended").isNotNull();
        return request;
    }

    /** The sign-in, with the authentication it put in the security context, as the application's sign-in hands it over. */
    private static void signedInAt(BridgeResolutionFilter filter, Authentication authentication) {
        signIn(authentication);
        filter.resolveSignIn(request("/login", "203.0.113.5"), authentication);
    }

    private static BridgeUserMirrorSyncResult copyOf(MockHttpServletRequest request) {
        return (BridgeUserMirrorSyncResult) request.getAttribute(BridgeRequestAttributes.USER_SYNC_RESULT);
    }

    private static MockHttpServletRequest request(String path, String address) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRemoteAddr(address);
        return request;
    }

    private static Authentication hostUser(String name, String... roles) {
        User user = new User(name, "n/a", AuthorityUtils.createAuthorityList(roles));
        return UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities());
    }

    private static void signIn(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private static Jwt jwt(String subject, String clientId) {
        return Jwt.withTokenValue("token-" + subject).header("alg", "none").subject(subject).claim("client_id", clientId)
                .issuedAt(Instant.parse("2026-11-11T00:00:00Z")).expiresAt(Instant.parse("2026-11-11T01:00:00Z")).build();
    }

    /** The synchronisation, counting what it is asked for each subject; slow when told to be. */
    private static final class CountingCopies implements BridgeUserMirrorSyncService {

        private final ConcurrentHashMap<String, AtomicInteger> calls = new ConcurrentHashMap<>();
        private final ConcurrentHashMap<String, Long> ids = new ConcurrentHashMap<>();
        private final AtomicInteger nextId = new AtomicInteger(100);
        private final CountDownLatch released = new CountDownLatch(1);
        private volatile boolean slow;

        void slow() {
            this.slow = true;
        }

        void release() {
            released.countDown();
        }

        @Override
        public BridgeUserMirrorSyncResult sync(AuthenticationStamp authentication, AuthorizationStamp authorization,
                                               RequestContextSnapshot request) {
            String subject = authentication.principalId();
            calls.computeIfAbsent(subject, key -> new AtomicInteger()).incrementAndGet();
            if (slow) {
                try {
                    released.await(400, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            long id = ids.computeIfAbsent(subject, key -> (long) nextId.incrementAndGet());
            return new BridgeUserMirrorSyncResult(id, "brg_" + subject, subject, "key-" + subject, true, true, false, false);
        }

        int calls(String subject) {
            AtomicInteger count = calls.get(subject);
            return count != null ? count.get() : 0;
        }

        int total() {
            return calls.values().stream().mapToInt(AtomicInteger::get).sum();
        }

        Long idOf(String subject) {
            return ids.get(subject);
        }

        void awaitCalls(String subject, int expected) throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (calls(subject) < expected && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
            assertThat(calls(subject)).as("synchronisations of " + subject).isEqualTo(expected);
        }
    }
}
