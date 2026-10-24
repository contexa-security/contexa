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
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.dsl.option.AuthenticationProcessingOptions;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import io.contexa.contexaidentity.security.core.mfa.options.PrimaryAuthenticationOptions;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The requests the chain of an OAuth2 flow takes with {@link OAuth2RequestScope#TOKEN_REQUESTS} (A1-10, AG-12a).
 */
final class TokenRequestScope {

    private TokenRequestScope() {
    }

    /**
     * The matcher of the token requests.
     *
     * @param tokenResolver                the resolver the chain reads access tokens with; {@code null} when the chain
     *                                     is no resource server
     * @param authorizationServerEndpoints the endpoints of the authorization server the chain hosts, or {@code null}
     * @param paths                        the authentication paths of the flow ({@link #flowPaths})
     * @param additional                   the requests the application adds
     */
    static RequestMatcher matcher(@Nullable BearerTokenResolver tokenResolver,
                                  @Nullable RequestMatcher authorizationServerEndpoints,
                                  Collection<String> paths, List<RequestMatcher> additional) {
        List<RequestMatcher> matchers = new ArrayList<>();
        if (tokenResolver != null) {
            matchers.add(new AccessTokenRequestMatcher(tokenResolver));
        }
        if (authorizationServerEndpoints != null) {
            matchers.add(authorizationServerEndpoints);
        }
        PathPatternRequestMatcher.Builder pathMatchers = PathPatternRequestMatcher.withDefaults();
        for (String path : paths) {
            matchers.add(pathMatchers.matcher(path));
        }
        matchers.addAll(additional);
        if (matchers.isEmpty()) {
            return request -> false;
        }
        return new OrRequestMatcher(matchers);
    }

    /**
     * The paths the flow authenticates on: the URL prefix, the URLs of its steps, the pages and endpoints of an MFA
     * flow, and the refresh URI. For a flow with a URL prefix only the paths under the prefix are the flow's. Query
     * strings are dropped and absolute URLs are left out.
     *
     * @param flow       the flow, or {@code null}
     * @param mfaUrls    the URLs of an MFA flow, or {@code null} for a single-factor flow
     * @param refreshUri the refresh URI this chain hosts, or {@code null}
     */
    static Set<String> flowPaths(@Nullable AuthenticationFlowConfig flow, @Nullable AuthUrlProvider mfaUrls,
                                 @Nullable String refreshUri) {
        Set<String> paths = new LinkedHashSet<>();
        addPath(paths, refreshUri);
        if (flow == null) {
            return paths;
        }
        // A flow with a URL prefix serves only the URLs under it (its MFA chain is matched to prefix/**). Its options
        // keep the unprefixed defaults, which are the URLs of the flows without a prefix, such as the people's sign-in
        // beside an agents' flow, so only the paths under the prefix are its own.
        String prefix = StringUtils.hasText(flow.getUrlPrefix()) ? flow.getUrlPrefix() : null;
        Set<String> flowPaths = new LinkedHashSet<>();
        if (prefix != null) {
            flowPaths.add(prefix + "/**");
        }
        PrimaryAuthenticationOptions primary = flow.getPrimaryAuthenticationOptions();
        if (primary != null) {
            addPath(flowPaths, primary.getLoginProcessingUrl());
            addPath(flowPaths, primary.getLoginPage());
        }
        for (AuthenticationStepConfig step : flow.getStepConfigs()) {
            addOptionPaths(flowPaths, step.getOption(AuthenticationStepConfig.OPTIONS_KEY));
        }
        for (AuthenticationProcessingOptions options : flow.getRegisteredFactorOptions().values()) {
            addOptionPaths(flowPaths, options);
        }
        if (mfaUrls != null) {
            mfaUrls.getAllMfaRelatedUrls().forEach(url -> addPath(flowPaths, url));
            mfaUrls.getMfaInProgressUrls().forEach(url -> addPath(flowPaths, url));
            mfaUrls.getPasskeyRegistrationUrls().forEach(url -> addPath(flowPaths, url));
        }
        flowPaths.stream().filter(path -> prefix == null || underPrefix(path, prefix)).forEach(paths::add);
        return paths;
    }

    private static boolean underPrefix(String path, String prefix) {
        return path.equals(prefix) || path.startsWith(prefix.endsWith("/") ? prefix : prefix + "/");
    }

    private static void addOptionPaths(Set<String> paths, @Nullable Object options) {
        if (options instanceof AuthenticationProcessingOptions processing) {
            addPath(paths, processing.getLoginProcessingUrl());
        }
        if (options instanceof FormOptions form) {
            addPath(paths, form.getLoginPage());
        }
        if (options instanceof OttOptions ott) {
            addPath(paths, ott.getTokenGeneratingUrl());
            addPath(paths, ott.getDefaultSubmitPageUrl());
        }
        if (options instanceof PasskeyOptions passkey) {
            addPath(paths, passkey.getAssertionOptionsEndpoint());
        }
    }

    private static void addPath(Set<String> paths, @Nullable String url) {
        if (!StringUtils.hasText(url)) {
            return;
        }
        int query = url.indexOf('?');
        String path = query >= 0 ? url.substring(0, query) : url;
        if (path.startsWith("/")) {
            paths.add(path);
        }
    }

    /**
     * A request carrying an access token as the chain's resolver reads it, or a CORS preflight announcing the
     * {@code Authorization} header. A malformed or duplicated token also matches, so the chain that reads tokens
     * answers it instead of a session chain ignoring it.
     */
    static final class AccessTokenRequestMatcher implements RequestMatcher {

        private final BearerTokenResolver tokenResolver;

        AccessTokenRequestMatcher(BearerTokenResolver tokenResolver) {
            this.tokenResolver = tokenResolver;
        }

        @Override
        public boolean matches(HttpServletRequest request) {
            if (isPreflightForAuthorization(request)) {
                return true;
            }
            try {
                return tokenResolver.resolve(request) != null;
            } catch (OAuth2AuthenticationException malformed) {
                return true;
            }
        }

        private static boolean isPreflightForAuthorization(HttpServletRequest request) {
            if (!HttpMethod.OPTIONS.matches(request.getMethod()) || request.getHeader(HttpHeaders.ORIGIN) == null) {
                return false;
            }
            String requested = request.getHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS);
            if (requested == null) {
                return false;
            }
            for (String header : requested.split(",")) {
                if (HttpHeaders.AUTHORIZATION.equalsIgnoreCase(header.trim())) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public String toString() {
            return "AccessTokenRequest";
        }
    }
}
