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
package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaAdminRealm;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaSignInRealm;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * The chain of Contexa's administrators ({@link ContexaAdminRealm}), on the flow of theirs only: it takes the realm's
 * requests, keeps its CSRF token and the page to return to under keys of its own, lets only administrators reach the
 * console, answers the console's API with 401, and signs out without ending the HTTP session the application may share.
 * It runs after the sign-in and state adapters, so that what it sets is what the chain keeps.
 */
public class AdminRealmConfigurer implements SecurityConfigurer {

    /** After the authentication adapters (300) and the state adapters (400). */
    private static final int ORDER = 450;

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (!ContexaSignInRealm.isAdminFlow(fc.flow())) {
            return;
        }
        HttpSecurity http = fc.http();
        HttpSessionCsrfTokenRepository csrfRepository = new HttpSessionCsrfTokenRepository();
        csrfRepository.setSessionAttributeName(ContexaAdminRealm.CSRF_KEY);
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setSessionAttrName(ContexaAdminRealm.SAVED_REQUEST_KEY);
        requestCache.setRequestMatcher(new NegatedRequestMatcher(ContexaAdminRealm.api()));

        http.securityMatcher(ContexaAdminRealm.requests())
                // The request is the console's (Q-17): its decisions are bound apart and its refusals answer on console pages
                .addFilterBefore(new ConsoleRequestMark(http.getSharedObject(SecurityContextRepository.class)), SecurityContextHolderFilter.class)
                .csrf(csrf -> csrf.csrfTokenRepository(csrfRepository))
                .requestCache(cache -> cache.requestCache(requestCache))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(ContexaAdminRealm.beforeSignIn()).permitAll()
                        .anyRequest().hasAuthority("ROLE_ADMIN"))
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED), ContexaAdminRealm.api()))
                .logout(logout -> logout
                        .logoutRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, ContexaAdminRealm.LOGOUT_URL))
                        .invalidateHttpSession(false));
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    /** Marks each request of the administrators' chain as the console's, and names the chain's context repository on it. */
    static final class ConsoleRequestMark extends OncePerRequestFilter {

        private final SecurityContextRepository repository;

        ConsoleRequestMark(SecurityContextRepository repository) {
            this.repository = repository;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            ConsoleSession.mark(request);
            if (repository != null) {
                request.setAttribute(ContexaAdminRealm.CONTEXT_REPOSITORY_ATTRIBUTE, repository);
            }
            chain.doFilter(request, response);
        }
    }
}
