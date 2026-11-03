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
package io.contexa.autoconfigure.ai;

import io.contexa.contexacore.security.UnifiedUserDetailsService;
import io.contexa.contexaidentity.security.core.context.OrderedSecurityFilterChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** Ownership findings F-1, F-2, F-8 (harness 2026-11-03): what Contexa reports at start. */
class OwnershipStartupDiagnosticsTest {

    private final RequestMatcher api = request -> request.getRequestURI().startsWith("/api/");

    @Test
    @DisplayName("F-1: the application's chains behind Contexa's chain for every request are named")
    void shadowedApplicationChainsAreNamed() {
        List<SecurityFilterChain> chains = List.of(
                new OrderedSecurityFilterChain(100, AnyRequestMatcher.INSTANCE, List.of()),
                new DefaultSecurityFilterChain(api, List.of()),
                new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, List.of()));

        assertThat(OwnershipStartupDiagnostics.shadowedApplicationChains(chains)).hasSize(2);
    }

    @Test
    @DisplayName("F-1: nothing is reported when Contexa's chain takes part of the requests only, or comes last")
    void nothingWhenContexaDoesNotShadow() {
        assertThat(OwnershipStartupDiagnostics.shadowedApplicationChains(List.of(
                new OrderedSecurityFilterChain(100, api, List.of()),
                new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, List.of())))).isEmpty();
        assertThat(OwnershipStartupDiagnostics.shadowedApplicationChains(List.of(
                new DefaultSecurityFilterChain(api, List.of()),
                new OrderedSecurityFilterChain(100, AnyRequestMatcher.INSTANCE, List.of())))).isEmpty();
    }

    @Test
    @DisplayName("F-8: an application user store that takes over Contexa's sign-in is named; Contexa's own is not")
    void applicationUserStoresAreNamed() {
        Map<String, UserDetailsService> stores = Map.of(
                "customerUsers", new InMemoryUserDetailsManager(),
                "unifiedUserDetailsService", mock(UnifiedUserDetailsService.class));

        assertThat(OwnershipStartupDiagnostics.applicationUserStores(stores)).containsExactly("customerUsers");
    }

    @Test
    @DisplayName("F-2: a one-time-code factor without a mail sender is reported")
    void oneTimeCodeWithoutMail() {
        assertThat(OwnershipStartupDiagnostics.oneTimeCodeUndeliverable(true, false)).isTrue();
        assertThat(OwnershipStartupDiagnostics.oneTimeCodeUndeliverable(true, true)).isFalse();
        assertThat(OwnershipStartupDiagnostics.oneTimeCodeUndeliverable(false, false)).isFalse();
    }
}
