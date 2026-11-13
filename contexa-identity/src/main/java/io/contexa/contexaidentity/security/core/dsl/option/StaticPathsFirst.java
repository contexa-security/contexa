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
package io.contexa.contexaidentity.security.core.dsl.option;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;
import java.util.function.Supplier;

/**
 * Opens a flow's static paths in a chain whose authorization rules the application has closed with
 * {@code anyRequest()}. Spring Security takes no further rule after {@code anyRequest()}, so the paths cannot be added
 * as rules, and a flow with {@code authorizeStaticPermitAll(...)} next to such a global customizer did not start. The
 * manager built from the rules is wrapped: a request to a static path is granted, and every other request is decided by
 * the rules as they are.
 */
final class StaticPathsFirst implements ObjectPostProcessor<AuthorizationManager<HttpServletRequest>> {

    private final RequestMatcher staticPaths;

    StaticPathsFirst(ApplicationContext context, List<String> patterns) {
        this.staticPaths = new OrRequestMatcher(new PathMatchers(context).requestMatchers(patterns.toArray(String[]::new)));
    }

    @Override
    @SuppressWarnings("unchecked")
    public <O extends AuthorizationManager<HttpServletRequest>> O postProcess(O rules) {
        return (O) new StaticPathsThenRules(staticPaths, rules);
    }

    /** The matchers Spring Security makes of path patterns in {@code requestMatchers(String...)}, and no rule for them. */
    private static final class PathMatchers extends AbstractRequestMatcherRegistry<List<RequestMatcher>> {

        private PathMatchers(ApplicationContext context) {
            setApplicationContext(context);
        }

        @Override
        protected List<RequestMatcher> chainRequestMatchers(List<RequestMatcher> requestMatchers) {
            return requestMatchers;
        }
    }

    private record StaticPathsThenRules(RequestMatcher staticPaths, AuthorizationManager<HttpServletRequest> rules)
            implements AuthorizationManager<HttpServletRequest> {

        private static final AuthorizationDecision GRANTED = new AuthorizationDecision(true);

        @Override
        public AuthorizationResult authorize(Supplier<Authentication> authentication, HttpServletRequest request) {
            return staticPaths.matches(request) ? GRANTED : rules.authorize(authentication, request);
        }

        @Override
        @Deprecated
        public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest request) {
            return staticPaths.matches(request) ? GRANTED : rules.check(authentication, request);
        }
    }
}
