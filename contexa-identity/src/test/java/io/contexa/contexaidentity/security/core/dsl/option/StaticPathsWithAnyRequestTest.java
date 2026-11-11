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
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code authorizeStaticPermitAll(...)} of a flow next to the authorization rules the application writes in the global
 * customizer. The usual rules end with {@code anyRequest()}, after which Spring Security takes no further rule.
 */
class StaticPathsWithAnyRequestTest {

    private static final Authentication NOBODY = new AnonymousAuthenticationToken("key", "anonymous",
            AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    private static final Authentication USER = new TestingAuthenticationToken("user", "n/a", "ROLE_USER");

    private static final class Options extends AbstractOptions {

        private Options(Builder builder) {
            super(builder);
        }

        private static final class Builder extends AbstractOptions.Builder<Options, Builder> {

            @Override
            protected Builder self() {
                return this;
            }

            @Override
            public Options build() {
                return new Options(this);
            }
        }
    }

    private static HttpSecurity http() {
        GenericApplicationContext applicationContext = new GenericApplicationContext();
        applicationContext.refresh();
        return new HttpSecurity(ObjectPostProcessor.identity(),
                new AuthenticationManagerBuilder(ObjectPostProcessor.identity()),
                Map.of(ApplicationContext.class, applicationContext));
    }

    private static Options staticPaths(String... patterns) {
        return new Options.Builder().cors(AbstractHttpConfigurer::disable).authorizeStaticPermitAll(patterns).build();
    }

    private static AuthorizationManager<HttpServletRequest> rulesOf(HttpSecurity http) throws Exception {
        DefaultSecurityFilterChain chain = http.build();
        return chain.getFilters().stream()
                .filter(AuthorizationFilter.class::isInstance)
                .map(AuthorizationFilter.class::cast)
                .findFirst().orElseThrow()
                .getAuthorizationManager();
    }

    private static boolean granted(AuthorizationManager<HttpServletRequest> rules, Authentication who, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setServletPath(path);
        AuthorizationResult result = rules.authorize(() -> who, request);
        return result != null && result.isGranted();
    }

    @Test
    void rulesClosedWithAnyRequestStillTakeTheStaticPathsOfAFlow() throws Exception {
        HttpSecurity http = http();
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated());

        staticPaths("/assets/**", "/favicon.ico").applyCommonSecurityConfigs(http);

        AuthorizationManager<HttpServletRequest> rules = rulesOf(http);
        assertThat(granted(rules, NOBODY, "/assets/app.css")).isTrue();
        assertThat(granted(rules, NOBODY, "/favicon.ico")).isTrue();
        // every other request is decided by the application's rules as they are
        assertThat(granted(rules, NOBODY, "/orders")).isFalse();
        assertThat(granted(rules, USER, "/orders")).isTrue();
        assertThat(granted(rules, USER, "/admin/users")).isFalse();
    }

    @Test
    void rulesLeftOpenTakeTheStaticPathsAsRulesAfterTheApplicationsOwn() throws Exception {
        HttpSecurity http = http();
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/assets/private/**").denyAll()
                .requestMatchers("/orders/**").authenticated());

        staticPaths("/assets/**").applyCommonSecurityConfigs(http);

        AuthorizationManager<HttpServletRequest> rules = rulesOf(http);
        assertThat(granted(rules, NOBODY, "/assets/app.css")).isTrue();
        // the application's rule comes first, as it did: a static path does not open what an earlier rule closes
        assertThat(granted(rules, NOBODY, "/assets/private/key.pem")).isFalse();
        assertThat(granted(rules, NOBODY, "/orders/1")).isFalse();
    }

    @Test
    void aFlowWithoutRulesOfTheApplicationOpensItsStaticPaths() throws Exception {
        HttpSecurity http = http();

        staticPaths("/assets/**").applyCommonSecurityConfigs(http);

        AuthorizationManager<HttpServletRequest> rules = rulesOf(http);
        assertThat(granted(rules, NOBODY, "/assets/app.css")).isTrue();
        assertThat(granted(rules, NOBODY, "/orders")).isFalse();
    }
}
