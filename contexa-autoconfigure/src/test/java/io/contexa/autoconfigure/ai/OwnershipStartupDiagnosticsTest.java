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
import org.springframework.web.server.WebFilter;
import jakarta.servlet.Filter;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.operating.ContexaOperatingProfileException;
import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacore.security.UnifiedUserDetailsService;
import io.contexa.contexaidentity.security.core.context.OrderedSecurityFilterChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.Ordered;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
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

    /**
     * R-14 (F-2): with mode FULL Contexa's main chain takes every request it is left, and Spring Security runs no chain after
     * one that takes every request, so an application chain that takes every request as well cannot run beside it.
     */
    @Test
    @DisplayName("R-14: FULL에서 모든 요청을 받는 앱 체인은 기동을 멈추고, 거부는 그 체인을 이름하고 securityMatcher로 좁히거나 SANDBOX를 쓰라고 알린다")
    void anApplicationChainForEveryRequestIsRefused() {
        SecurityFilterChain contexa = new OrderedSecurityFilterChain(Ordered.LOWEST_PRECEDENCE, AnyRequestMatcher.INSTANCE, List.of());
        SecurityFilterChain application = new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, List.of(mock(Filter.class)));

        assertThatThrownBy(() -> OwnershipStartupDiagnostics.refuseApplicationChains(List.of(application, contexa), null))
                .isInstanceOfSatisfying(ContexaOperatingProfileException.class, refused -> {
                    assertThat(refused.getMessage()).contains(AnyRequestMatcher.INSTANCE.toString(), "would never run");
                    assertThat(refused.action()).contains("securityMatcher", "without mode = FULL");
                });
    }

    /** R-14: a chain of the application's narrowed to its own paths runs ahead of Contexa's main chain, which takes the rest. */
    @Test
    @DisplayName("R-14: FULL에서 securityMatcher로 좁힌 앱 체인은 거부하지 않는다: Contexa 주 체인 앞에서 자기 경로를 맡는다")
    void aNarrowedApplicationChainIsNotRefused() {
        SecurityFilterChain application = new DefaultSecurityFilterChain(api, List.of(mock(Filter.class)));
        SecurityFilterChain contexa = new OrderedSecurityFilterChain(Ordered.LOWEST_PRECEDENCE, AnyRequestMatcher.INSTANCE, List.of());

        assertThatCode(() -> OwnershipStartupDiagnostics.refuseApplicationChains(List.of(application, contexa), null))
                .doesNotThrowAnyException();
        assertThat(OwnershipStartupDiagnostics.applicationChains(List.of(application, contexa), null))
                .as("it is still the application's chain").hasSize(1);
    }

    /** Whether such a chain is refused is decided by the requests it takes (R-14), not by its being the application's. */
    @Test
    @DisplayName("Q-2: 앱이 Contexa 체인 앞에 둔 체인도 앱의 체인으로 센다")
    void aChainInFrontOfContexasIsTheApplications() {
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

    @Test
    @DisplayName("a stored PERMIT for URLs no policy names is reported where Contexa owns the sign-in, and only there")
    void aStoredPermitIsReportedUnderContexaOwnership() {
        ContexaOperatingProfile full = new ContexaOperatingProfile(SecurityMode.FULL, SecurityOwnershipMode.CONTEXA_OWNED, true, false);
        ContexaOperatingProfile sandbox = new ContexaOperatingProfile(SecurityMode.SANDBOX, SecurityOwnershipMode.HOST_OWNED, false, false);

        assertThat(OwnershipStartupDiagnostics.openUnnamedPathsNotice(full, "PERMIT"))
                .startsWith("[Contexa] FULL: the stored decision for URLs no policy names is PERMIT")
                .contains("an upgrade does not change it", "Decision when no URL policy applies");
        assertThat(OwnershipStartupDiagnostics.openUnnamedPathsNotice(full, " PERMIT ")).isNotNull();
        assertThat(OwnershipStartupDiagnostics.openUnnamedPathsNotice(sandbox, "PERMIT"))
                .as("the application's own chain decides there, so the decision is of no consequence").isNull();
    }

    @Test
    @DisplayName("nothing is reported for a decision that closes the paths, for none saved or for a value of no meaning")
    void nothingIsReportedForAnythingButPermit() {
        ContexaOperatingProfile full = new ContexaOperatingProfile(SecurityMode.FULL, SecurityOwnershipMode.CONTEXA_OWNED, true, false);

        for (String stored : new String[]{null, "", "AUTHENTICATED", "DENY", "permit"}) {
            assertThat(OwnershipStartupDiagnostics.openUnnamedPathsNotice(full, stored)).as("stored %s", stored).isNull();
        }
    }

    @Test
    @DisplayName("several senders and no spring.mail.host, Contexa is told it has none of its own to build, and how to give it one")
    void severalSendersAndNoHostAreExplainedWhereContexaSignsIn() {
        String message = OwnershipStartupDiagnostics.undeliverableCodeMessage(List.of("mailA", "mailB"), false);

        assertThat(message).contains("the application has several JavaMailSender beans [mailA, mailB]", "does not choose one of them",
                "spring.mail.host is not set", "Set spring.mail.host", "@Primary", "passkey").doesNotContain("no mail sender is configured");
    }

    @Test
    @DisplayName("no sender of the application and no spring.mail.host: the reason is that neither exists")
    void noSenderAndNoHostAreExplained() {
        assertThat(OwnershipStartupDiagnostics.undeliverableCodeMessage(List.of(), false))
                .contains("the application has no JavaMailSender and spring.mail.host is not set", "Set spring.mail.*", "passkey");
    }

    @Test
    @DisplayName("spring.mail.host set and still no sender, in every way of running: the sender built from spring.mail.* could not be created")
    void aSenderThatCouldNotBeBuiltIsSaid() {
        assertThat(OwnershipStartupDiagnostics.undeliverableCodeMessage(List.of("mailA", "mailB"), true))
                .contains("could not be created", "spring.mail.*").doesNotContain("does not choose");
        assertThat(OwnershipStartupDiagnostics.undeliverableCodeMessage(List.of(), true))
                .contains("could not be created").doesNotContain("Spring Boot's mail configuration");
    }

    @Test
    @DisplayName("the start check names the application's senders from its beans, and reads spring.mail.host from its settings")
    void theStartCheckReadsTheApplicationsSenders() {
        assertThat(OwnershipStartupDiagnostics.applicationMailSenders(beansWith("mailB", "mailA"))).containsExactly("mailA", "mailB");
        assertThat(OwnershipStartupDiagnostics.applicationMailSenders(new DefaultListableBeanFactory())).isEmpty();
        assertThat(OwnershipStartupDiagnostics.mailHostSet(new MockEnvironment().withProperty("spring.mail.host", "smtp.example.test"))).isTrue();
        assertThat(OwnershipStartupDiagnostics.mailHostSet(new MockEnvironment().withProperty("spring.mail.host", " "))).isFalse();
        assertThat(OwnershipStartupDiagnostics.mailHostSet(new MockEnvironment())).isFalse();
        assertThat(OwnershipStartupDiagnostics.mailHostSet(null)).isFalse();
    }

    private static DefaultListableBeanFactory beansWith(String... senders) {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        for (String sender : senders) {
            beans.registerSingleton(sender, mock(JavaMailSender.class));
        }
        return beans;
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

    /** PR-173: on the servlet stack Contexa brings, the WebFlux filters of an application are beans nothing calls. */
    @Test
    void theWebFluxBeansOfAnApplicationAreNamedAsNeverRunning() {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton("hostWebFilter", mock(WebFilter.class));

        assertThat(OwnershipStartupDiagnostics.reactiveBeansNotice(beans, getClass().getClassLoader()))
                .contains("hostWebFilter").contains("never run");
        assertThat(OwnershipStartupDiagnostics.reactiveBeansNotice(new DefaultListableBeanFactory(), getClass().getClassLoader()))
                .isNull();
    }

    @Test
    void whatComesWithContexaIsNamedOnlyWhenItIsThere() {
        assertThat(OwnershipStartupDiagnostics.classPathImpact(getClass().getClassLoader())).contains("Reactor Netty")
                .contains("Spring MVC (Spring Boot runs the application on the servlet stack");
        assertThat(OwnershipStartupDiagnostics.classPathImpact(new ClassLoader(null) {
        })).isNull();
    }

    @Test
    void theServletStackIsNamedWhereSpringMvcIsThereOnly() {
        String servlet = "org.springframework.web.servlet.DispatcherServlet";
        ClassLoader springMvcOnly = new ClassLoader(null) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (name.equals(servlet)) {
                    return OwnershipStartupDiagnosticsTest.class.getClassLoader().loadClass(name);
                }
                throw new ClassNotFoundException(name);
            }
        };

        assertThat(OwnershipStartupDiagnostics.classPathImpact(springMvcOnly))
                .contains("Spring MVC (Spring Boot runs the application on the servlet stack")
                .contains("spring.main.web-application-type=reactive")
                .doesNotContain("Reactor Netty");
    }
}
