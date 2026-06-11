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
package io.contexa.contexacore.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Zero Trust filter for OAuth2 Resource Server requests.
 * Registered after BearerTokenAuthenticationFilter in the OAuth2 filter chain
 * to apply Zero Trust verification to JWT-authenticated requests.
 *
 * <p>Execution flow:
 * <pre>
 * SecurityContextHolderFilter
 *   -> BearerTokenAuthenticationFilter (JWT verification -> SecurityContextHolder)
 *     -> AIOAuth2ZeroTrustFilter (Zero Trust -> authority adjustment)
 *       -> AuthorizationFilter (authorization with Zero Trust result)
 * </pre>
 *
 * @see AIOAuth2SecurityContextRepository
 */
public class AIOAuth2ZeroTrustFilter extends OncePerRequestFilter {

    private final AIOAuth2SecurityContextRepository oAuth2SecurityContextRepository;

    public AIOAuth2ZeroTrustFilter(AIOAuth2SecurityContextRepository oAuth2SecurityContextRepository) {
        this.oAuth2SecurityContextRepository = oAuth2SecurityContextRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {
        oAuth2SecurityContextRepository.applyZeroTrustToCurrentContext(request);
        filterChain.doFilter(request, response);
    }
}
