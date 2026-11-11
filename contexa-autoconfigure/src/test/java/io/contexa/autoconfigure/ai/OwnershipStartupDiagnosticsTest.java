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

import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.web.reactive.function.server.RouterFunctions;
import jakarta.servlet.Filter;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.operating.ContexaOperatingProfileException;
import io.contexa.contexacommon.operating.ContexaOperatingProfile;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/** Ownership findings F-1, F-2, F-8 (harness 2026-11-03): what Contexa reports at start. */
class OwnershipStartupDiagnosticsTest {

    private final RequestMatcher api = request -> request.getRequestURI().startsWith("/api/");

    @Test
    void theStartSaysContexasSignInDoesNotReadTheApplicationsStores() {
        assertThat(OwnershipStartupDiagnostics.userStoresNotice(List.of("usersA")))
                .contains("usersA", "does not read", "Contexa's own user store")
                .doesNotContain("@Primary", "instead of Contexa's");
        assertThat(OwnershipStartupDiagnostics.userStoresNotice(List.of("usersA", "usersB")))
                .contains("usersA", "usersB", "does not read")
                .doesNotContain("@Primary", "unless");
    }

    @Test
    @DisplayName("Q-2: a chain of the application under CONTEXA_OWNED stops the start, and the refusal names it and says what to change")
    void anApplicationChainIsRefused() {
        SecurityFilterChain contexa = new OrderedSecurityFilterChain(100, AnyRequestMatcher.INSTANCE, List.of());
        SecurityFilterChain application = new DefaultSecurityFilterChain(api, List.of(mock(Filter.class)));

        assertThatThrownBy(() -> OwnershipStartupDiagnostics.refuseApplicationChains(List.of(contexa, application), null))
                .isInstanceOfSatisfying(ContexaOperatingProfileException.class, refused -> {
                    assertThat(refused.getMessage()).contains("would be open");
                    assertThat(refused.action()).contains("without mode = FULL");
                });
    }

    @Test
    @DisplayName("Q-2: a chain the application put in front of Contexa's is refused as well: it keeps a sign-in of its own")
    void aChainInFrontOfContexasIsRefusedToo() {
        SecurityFilterChain application = new DefaultSecurityFilterChain(api, List.of(mock(Filter.class)));
        SecurityFilterChain contexa = new OrderedSecurityFilterChain(100, AnyRequestMatcher.INSTANCE, List.of());

        assertThat(OwnershipStartupDiagnostics.applicationChains(List.of(application, contexa), null)).hasSize(1);
    }

    @Test
    @DisplayName("P-9: Contexa's chains and its placeholder are not the application's, so a new application starts")
    void contexasOwnChainsAreNotRefused() {
        SecurityFilterChain placeholder = new DefaultSecurityFilterChain(api, List.of(mock(Filter.class)));
        SecurityFilterChain contexa = new OrderedSecurityFilterChain(100, AnyRequestMatcher.INSTANCE, List.of());

        OwnershipStartupDiagnostics.refuseApplicationChains(List.of(contexa, placeholder), placeholder);

        assertThat(OwnershipStartupDiagnostics.applicationChains(List.of(contexa, placeholder), placeholder)).isEmpty();
    }

    @Test
    @DisplayName("Q-2: what web.ignoring() leaves is no chain of the application: without filters it signs nobody in")
    void anIgnoredPathIsNotAChain() {
        SecurityFilterChain ignored = new DefaultSecurityFilterChain(api, List.of());

        assertThat(OwnershipStartupDiagnostics.applicationChains(List.of(ignored), null)).isEmpty();
    }

    @Test
    @DisplayName("the start report says how the application runs Contexa")
    void theStartReportSaysHowContexaRuns() {
        assertThat(OwnershipStartupDiagnostics.report(new ContexaOperatingProfile(SecurityMode.SANDBOX, SecurityOwnershipMode.HOST_OWNED, false, false), "ENFORCE"))
                .isEqualTo("[Contexa] mode=SANDBOX ownership=HOST_OWNED data=application enforcement=ENFORCE");
        assertThat(OwnershipStartupDiagnostics.report(new ContexaOperatingProfile(SecurityMode.FULL, SecurityOwnershipMode.CONTEXA_OWNED, true, false), "SHADOW"))
                .isEqualTo("[Contexa] mode=FULL ownership=CONTEXA_OWNED data=contexa enforcement=SHADOW");
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

    /** Boot runs a WebFlux application on the servlet stack Contexa brings, and its functional routes then answer 404. */
    @Test
    void anApplicationWithWebFluxRoutesIsToldInsteadOfAnswering404() {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton("routes", RouterFunctions.route().GET("/orders", request -> ServerResponse.ok().build()).build());

        assertThatThrownBy(() -> OwnershipStartupDiagnostics.refuseReactiveRoutes(beans, getClass().getClassLoader()))
                .isInstanceOf(ContexaOperatingProfileException.class)
                .hasMessageContaining("routes");
    }

    @Test
    void anApplicationWithoutWebFluxRoutesStarts() {
        OwnershipStartupDiagnostics.refuseReactiveRoutes(new DefaultListableBeanFactory(), getClass().getClassLoader());
    }

    @Test
    void whatComesWithContexaIsNamedOnlyWhenItIsThere() {
        assertThat(OwnershipStartupDiagnostics.classPathImpact(getClass().getClassLoader())).contains("Reactor Netty");
        assertThat(OwnershipStartupDiagnostics.classPathImpact(new ClassLoader(null) {
        })).isNull();
    }
}
