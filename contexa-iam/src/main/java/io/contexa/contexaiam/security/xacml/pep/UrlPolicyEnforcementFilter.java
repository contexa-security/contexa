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
package io.contexa.contexaiam.security.xacml.pep;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.security.ZeroTrustScreens;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.store.RequestPathScope;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * The URL policies on the application's requests (R-7 of docs/agent/운영모드-정상화-구현계획.md): those a chain of the
 * application takes, or no chain, which Contexa's main chain never sees. It runs as a servlet filter behind the Spring
 * Security filter chain, so the application's chain has run first and established who makes the request, and it asks the
 * URL policies' manager of Contexa's own chain.
 * <ul>
 *   <li>A request no policy decides keeps the decision of the chain that took it: the no-matching-policy decision is the
 *       default of Contexa's own chain, not of the application's.</li>
 *   <li>A request the manager has decided already, on a chain that asks it, is not decided again; a request one of
 *       Contexa's own chains takes ({@code applicationRequests} does not match it) is that chain's to decide.</li>
 *   <li>A refusal is 401 for a request without a signed-in user and 403 for one with: to an API or AJAX client as JSON
 *       at once, to a browser through the application's own error handling.</li>
 * </ul>
 * The decision is Contexa's work on the request's thread, so what it reads is bounded; the application's handler is not.
 * A decision that cannot be made, its policies failing to evaluate, is no decision: the request goes on as the
 * application's chain left it, as with Contexa's other filters on the application's requests.
 */
@Slf4j
public class UrlPolicyEnforcementFilter extends OncePerRequestFilter {

    /** The error code of a refusal answered as JSON. */
    public static final String DENIED = "URL_POLICY_DENIED";

    private static final AuthenticationTrustResolver TRUST_RESOLVER = new AuthenticationTrustResolverImpl();

    private final CustomDynamicAuthorizationManager authorizationManager;
    private final RequestMatcher applicationRequests;
    private final ObjectMapper objectMapper;
    private final String anonymousKey = UUID.randomUUID().toString();

    /**
     * @param authorizationManager the URL policies' manager of Contexa's own chain
     * @param applicationRequests  the requests that are the application's: those a chain of the application takes, or no
     *                             chain
     * @param objectMapper         writes the JSON answer of a refusal
     */
    public UrlPolicyEnforcementFilter(CustomDynamicAuthorizationManager authorizationManager,
                                      RequestMatcher applicationRequests, ObjectMapper objectMapper) {
        this.authorizationManager = Objects.requireNonNull(authorizationManager, "authorizationManager");
        this.applicationRequests = Objects.requireNonNull(applicationRequests, "applicationRequests");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (CustomDynamicAuthorizationManager.decided(request) || !applicationRequests.matches(request)) {
            chain.doFilter(request, response);
            return;
        }
        Authentication authentication = currentAuthentication(request);
        AuthorizationDecision decision;
        RequestPathScope.enter();
        try {
            decision = authorizationManager.checkNamedPolicies(() -> authentication, request);
        } catch (RuntimeException e) {
            log.error("[UrlPolicy] The URL policies could not be evaluated; the request keeps the application's decision: uri={}",
                    request.getRequestURI(), e);
            decision = null;
        } finally {
            RequestPathScope.leave();
        }
        if (decision == null || decision.isGranted()) {
            chain.doFilter(request, response);
            return;
        }
        refuse(request, response, authentication);
    }

    /**
     * Who makes the request: the user Contexa decides for (R-10), the application's chain's user, else the one the bridge
     * resolved for Contexa alone; a request nobody is known for is anonymous.
     */
    private Authentication currentAuthentication(HttpServletRequest request) {
        Authentication authentication = ContexaIdentity.of(request);
        return authentication != null
                ? authentication
                : new AnonymousAuthenticationToken(anonymousKey, "anonymousUser",
                        AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    }

    private void refuse(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        if (response.isCommitted()) {
            return;
        }
        int status = TRUST_RESOLVER.isAuthenticated(authentication)
                ? HttpServletResponse.SC_FORBIDDEN
                : HttpServletResponse.SC_UNAUTHORIZED;
        if (!ZeroTrustScreens.isApiOrAjaxRequest(request)) {
            response.sendError(status);
            return;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status);
        body.put("error", DENIED);
        body.put("message", "The URL policy refused the request");
        body.put("path", request.getRequestURI());
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        objectMapper.writeValue(response.getWriter(), body);
    }
}
