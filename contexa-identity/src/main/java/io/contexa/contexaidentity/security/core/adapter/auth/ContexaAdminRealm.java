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
package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacommon.security.ContexaConsolePaths;
import io.contexa.contexaidentity.security.zerotrust.SandboxUserPathGuard;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;

/**
 * The realm of Contexa's administrators where they sign in apart from the application's users (R-13 of
 * docs/agent/운영모드-정상화-구현계획.md): one MFA flow of Contexa's ({@link ContexaSignInRealm#ADMIN_FLOW_NAME}) under
 * {@link #URL_PREFIX}, which takes the console and what it needs before sign-in, signs Contexa's accounts in from Contexa's
 * store, and keeps everything it stores in the HTTP session under keys of its own, so that an administrator and an
 * application user in one browser do not overwrite each other and its sign-out does not end the application's session.
 */
public final class ContexaAdminRealm {

    /** The prefix of the flow's own addresses: its sign-in pages and steps lie under the console. */
    public static final String URL_PREFIX = "/contexa/admin";

    /** The order of the flow's chain, ahead of every other chain. */
    public static final int FLOW_ORDER = 10;

    /** The console's sign-out; the application's {@code /logout} stays the application's. */
    public static final String LOGOUT_URL = URL_PREFIX + "/logout";

    /**
     * The bean that holds the address throttle of the administrators' sign-in, an authentication provider asked ahead of the
     * password one; held, as Spring's global authentication manager counts every provider bean.
     */
    public static final String ADDRESS_GATE_BEAN = "contexaAdminSignInAddressGate";

    /** The bean that holds the publisher of the administrators' sign-in events to the sign-in policy (failed attempts, lock). */
    public static final String SIGN_IN_EVENTS_BEAN = "contexaAdminSignInEvents";

    public static final String CONTEXT_KEY = "CONTEXA_ADMIN_SECURITY_CONTEXT";

    /**
     * The request attribute that holds the security context repository of the administrators' chain, for what saves the
     * context after their sign-in outside the chain's own filters.
     */
    public static final String CONTEXT_REPOSITORY_ATTRIBUTE = ContexaAdminRealm.class.getName() + ".contextRepository";
    public static final String CSRF_KEY = "CONTEXA_ADMIN_CSRF_TOKEN";
    public static final String SAVED_REQUEST_KEY = "CONTEXA_ADMIN_SAVED_REQUEST";

    private ContexaAdminRealm() {
    }

    /**
     * The realm's requests: /contexa/admin and below, except the user's own paths there (the release of a block, the pending
     * analysis), which follow the application's users ({@link SandboxUserPathGuard}), and what the console needs before
     * sign-in.
     */
    public static RequestMatcher requests() {
        PathPatternRequestMatcher.Builder paths = PathPatternRequestMatcher.withDefaults();
        List<RequestMatcher> userPaths = SandboxUserPathGuard.ADMIN_SELF_SERVICE_PREFIXES.stream()
                .<RequestMatcher>map(prefix -> paths.matcher(prefix + "/**"))
                .toList();
        return new OrRequestMatcher(
                new AndRequestMatcher(
                        new OrRequestMatcher(paths.matcher(URL_PREFIX), paths.matcher(URL_PREFIX + "/**")),
                        new NegatedRequestMatcher(new OrRequestMatcher(userPaths))),
                beforeSignIn());
    }

    /** The look of the sign-in page and the password change an expired account is sent to, open before sign-in. */
    public static RequestMatcher beforeSignIn() {
        PathPatternRequestMatcher.Builder paths = PathPatternRequestMatcher.withDefaults();
        return new OrRequestMatcher(
                paths.matcher("/contexa/css/**"),
                paths.matcher("/contexa/js/**"),
                paths.matcher("/contexa/img/**"),
                paths.matcher(ContexaConsolePaths.PASSWORD_CHANGE));
    }

    /** The console's API, which answers 401 instead of a sign-in page and is never returned to after sign-in. */
    public static RequestMatcher api() {
        return PathPatternRequestMatcher.withDefaults().matcher(URL_PREFIX + "/api/**");
    }
}
