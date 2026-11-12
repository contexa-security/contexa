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
import io.contexa.contexaidentity.security.handler.login.LoginFactClaims;
import io.contexa.contexaidentity.security.handler.login.LoginFactsDetails;
import io.contexa.contexaidentity.security.handler.login.LoginFactsRecorder;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexacommon.security.bridge.BridgeObjectExtractor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Set;

/**
 * Holds an MFA flow's scope to the logins that meet it. Flows that keep their logins in the same state (two session
 * flows, two token flows) read the same login, so a login of a single flow (a password alone) or of an MFA flow with
 * fewer factors was a login on the paths of this flow too, and the factors it asks for were asked on its own sign-in
 * only. A login meets the flow when the flow itself completed it (also when its policy asked no factor), or when it was
 * completed with as many factors as the flow asks for. Any other login is, on this flow's requests, no login: the
 * request goes on as an anonymous one, so the flow's rules send it to the flow's own sign-in. The session or the token
 * keeps its login: nothing here is saved.
 *
 * <p>A login without the facts of a Contexa flow (a login method the application added itself) is left as it is.</p>
 */
@Slf4j
public class MfaSignInScopeFilter extends OncePerRequestFilter {

    private static final String ANONYMOUS_KEY = "contexa-mfa-sign-in-scope";

    private final String flowTypeName;
    private final int requiredFactors;
    private final AuthUrlProvider flowUrls;
    private final SecurityContextHolderStrategy contextHolder = SecurityContextHolder.getContextHolderStrategy();

    /**
     * @param flowTypeName    the type name of the MFA flow, such as {@code mfa_admin}
     * @param requiredFactors the factors the flow asks for after its primary step
     * @param flowUrls        the flow's addresses: its sign-in and MFA steps stay reachable with any login
     */
    public MfaSignInScopeFilter(String flowTypeName, int requiredFactors, AuthUrlProvider flowUrls) {
        this.flowTypeName = flowTypeName;
        this.requiredFactors = Math.max(1, requiredFactors);
        this.flowUrls = flowUrls;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication current = contextHolder.getContext().getAuthentication();
        if (current != null && current.isAuthenticated() && !(current instanceof AnonymousAuthenticationToken)
                && !isSignInStep(request) && !meetsTheFlow(current)) {
            log.warn("A login that does not meet MFA flow '{}' (it asks for {} factor(s)) is no login on its paths: {} {}",
                    flowTypeName, requiredFactors, request.getMethod(), request.getRequestURI());
            SecurityContext anonymous = contextHolder.createEmptyContext();
            anonymous.setAuthentication(new AnonymousAuthenticationToken(ANONYMOUS_KEY, "anonymousUser",
                    AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
            contextHolder.setContext(anonymous);
        }
        chain.doFilter(request, response);
    }

    /** Whether the login meets this flow. */
    boolean meetsTheFlow(Authentication login) {
        LoginFactsDetails facts = LoginFactsRecorder.loginOf(login, null, null);
        if (facts == null) {
            return true;
        }
        if (StringUtils.hasText(facts.getSignInFlow()) && flowTypeName.equalsIgnoreCase(facts.getSignInFlow())) {
            return true;
        }
        int methods = AuthenticationMethodReferences.methodsOf(facts.getAmr()).size();
        if (methods >= 1 + requiredFactors) {
            return true;
        }
        // A Zero Trust challenge passed by this login is one factor more than its sign-in had.
        return requiredFactors <= 1 && methods >= 1 && challengePassed(login, facts);
    }

    private static boolean challengePassed(Authentication login, LoginFactsDetails facts) {
        if (facts.getChallengeVerifiedAt() != null) {
            return true;
        }
        return StringUtils.hasText(BridgeObjectExtractor.extractString(login.getPrincipal(),
                List.of(LoginFactClaims.CHALLENGE_VERIFIED_AT)));
    }

    private boolean isSignInStep(HttpServletRequest request) {
        String path = pathOf(request);
        Set<String> steps = flowUrls.getMfaInProgressUrls();
        return path != null && steps.contains(path);
    }

    @Nullable
    private static String pathOf(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri == null) {
            return null;
        }
        String contextPath = request.getContextPath();
        return StringUtils.hasText(contextPath) && uri.startsWith(contextPath) ? uri.substring(contextPath.length()) : uri;
    }
}
