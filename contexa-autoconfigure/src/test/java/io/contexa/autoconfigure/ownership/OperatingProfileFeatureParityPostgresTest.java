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
package io.contexa.autoconfigure.ownership;

import io.contexa.autoconfigure.ai.ContexaFilterSlot;
import io.contexa.autoconfigure.ai.ContexaFilterSlotConfiguration;
import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacore.autonomous.agent.AgentTokenRevoker;
import io.contexa.contexacore.autonomous.service.IForceLogoutService;
import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.contexaiam.admin.web.agent.service.AgentProvisioning;
import io.contexa.contexaiam.admin.web.auth.filter.SessionTrackingFilter;
import io.contexa.contexaiam.security.core.LoginAttemptEventListener;
import io.contexa.contexaidentity.controller.MfaConfigController;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaPasswordSignIn;
import io.contexa.contexaidentity.security.filter.ContexaWebAuthnRegistrationPageFilter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;
import org.springframework.security.web.webauthn.registration.DefaultWebAuthnRegistrationPageGeneratingFilter;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M0 of the operating-mode plan (docs/agent/운영모드-정상화-구현계획.md): every way of running Contexa, SANDBOX or FULL with
 * either ownership of the sign-in, starts and has the whole of Contexa. The modes decide who builds the main chain and the
 * ownership how Contexa gives way to what the host already has (R-1, R-2); neither switches a feature of Contexa off.
 * <p>
 * Each case starts a real application (Spring Boot, Tomcat on a free port, a throwaway PostgreSQL database for Contexa and
 * an in-memory one for the host) and reads the list of Contexa's features from it. Two shapes of host are run: one with a
 * security chain and users of its own (an existing Spring Security application), and one with neither (a legacy
 * application). Within a shape the list is the same table for all four combinations.
 * <p>
 * Two kinds of entries, named apart in the table:
 * <ul>
 *   <li>what the running application does when it is asked over HTTP (Contexa's sign-in, its console, a URL policy, session
 *       tracking): behaviour;</li>
 *   <li>what the running application holds after its conditions were evaluated (a bean, a filter, an answer of a bean):
 *       the configuration only. What these components then do in each combination (a forced sign-out, a lock after failed
 *       sign-ins, a decision, an address rule) is measured on the real-server grid (M7), not here.</li>
 * </ul>
 * Decisions are off in this test so that no answer depends on a model.
 */
@Timeout(3600)
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@DisplayName("네 운영 조합의 Contexa 기능 동등 계약(실제 기동)")
class OperatingProfileFeatureParityPostgresTest {

    private static final String SIGN_IN = "behaviour: Contexa's sign-in (password, then the code by mail)";
    private static final String CONSOLE = "behaviour: the console after Contexa's sign-in";
    private static final String CONTEXA_SESSION_TRACKED = "behaviour: the session of Contexa's sign-in is tracked";
    private static final String HOST_SESSION_TRACKED = "behaviour: the session of the application's sign-in is tracked";
    private static final String URL_POLICY = "behaviour: a URL policy on a page the application leaves open";
    private static final String PASSKEY = "configuration: the passkey sign-in on a chain of Contexa's";
    private static final String PASSKEY_PAGE = "configuration: the passkey registration page on a chain of Contexa's";
    private static final String USER_STORE = "configuration: Contexa's user store";
    private static final String PROVIDER = "configuration: Contexa's password provider";
    private static final String TRACKING_FILTER = "configuration: the session tracking filter";
    private static final String FORCED_SIGN_OUT = "configuration: the forced sign-out service";
    private static final String AUTHORIZATION_SERVER = "configuration: the OAuth2 authorization server of Contexa's";
    private static final String METHOD_SECURITY = "configuration: method security on Contexa's classes";
    private static final String ATTEMPT_LISTENER = "configuration: the sign-in attempt listener";
    private static final String MFA_SETTINGS = "configuration: the MFA settings endpoint";
    private static final String AGENT_REGISTRATION = "configuration: agent registration";
    private static final String AGENT_REVOCATION = "configuration: agent token revocation";
    private static final String ADDRESS_CONTROL = "configuration: the address control";

    @BeforeAll
    static void driver() throws Exception {
        Class.forName("org.postgresql.Driver");
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(OperatingCombination.class)
    @DisplayName("보안 체인과 사용자가 있는 호스트: 네 조합 모두 기동하고 Contexa 기능 목록이 같다")
    void anApplicationWithItsOwnChainHasTheWholeOfContexa(OperatingCombination combination) throws Exception {
        try (GridRun run = GridRun.start(SandboxWithItsChain.class, FullWithItsChain.class, combination)) {
            Map<String, String> observed = features(run, true, combination);
            System.out.println("FEATURES [with its chain, " + combination + "] " + observed);

            assertThat(observed).isEqualTo(expected(true, combination));
        }
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(OperatingCombination.class)
    @DisplayName("보안 체인도 사용자도 없는 레거시 호스트: 네 조합 모두 기동하고 Contexa 기능 목록이 같다")
    void aLegacyApplicationWithoutSecurityHasTheWholeOfContexa(OperatingCombination combination) throws Exception {
        try (GridRun run = GridRun.start(SandboxWithoutSecurity.class, FullWithoutSecurity.class, combination)) {
            Map<String, String> observed = features(run, false, combination);
            System.out.println("FEATURES [without security, " + combination + "] " + observed);

            assertThat(observed).isEqualTo(expected(false, combination));
        }
    }

    /**
     * The one table every combination of a shape must answer. Contexa's OAuth2 plane, and with it the registration of agents
     * with their clients and the revocation of their tokens, is there where Contexa is the main security configuration (mode
     * FULL); in mode SANDBOX the application's own tokens carry its agents.
     */
    private static Map<String, String> expected(boolean hostSignsIn, OperatingCombination combination) {
        boolean full = combination.mode() == SecurityMode.FULL;
        Map<String, String> expected = new LinkedHashMap<>();
        expected.put("start", GridRun.STARTED);
        expected.put(USER_STORE, "present");
        expected.put(PROVIDER, "present");
        expected.put(TRACKING_FILTER, "present");
        expected.put(FORCED_SIGN_OUT, "present");
        expected.put(AUTHORIZATION_SERVER, full ? "present" : "absent");
        expected.put(METHOD_SECURITY, "present");
        expected.put(ATTEMPT_LISTENER, "present");
        expected.put(MFA_SETTINGS, "present");
        expected.put(AGENT_REGISTRATION, full ? "available" : "refused");
        expected.put(AGENT_REVOCATION, full ? "available" : "none");
        expected.put(ADDRESS_CONTROL, "every path");
        expected.put(PASSKEY, "present");
        expected.put(PASSKEY_PAGE, "Contexa's page");
        expected.put(SIGN_IN, "200 MFA_COMPLETED");
        expected.put(CONSOLE, "200");
        expected.put(CONTEXA_SESSION_TRACKED, "tracked");
        if (hostSignsIn) {
            expected.put(HOST_SESSION_TRACKED, "tracked");
        }
        expected.put(URL_POLICY, "refused");
        return expected;
    }

    private static Map<String, String> features(GridRun run, boolean hostSignsIn, OperatingCombination combination) {
        Map<String, String> observed = new LinkedHashMap<>();
        observed.put("start", run.startOutcome());
        if (!run.started()) {
            return observed;
        }
        ConfigurableApplicationContext context = run.context();
        observed.put(USER_STORE, GridRun.attempt(() -> present(context.containsBean(ContexaUserStore.BEAN_NAME))));
        observed.put(PROVIDER, GridRun.attempt(() -> present(context.containsBean(ContexaPasswordSignIn.PROVIDER_BEAN))));
        observed.put(TRACKING_FILTER, GridRun.attempt(() -> present(runsInTheFilterSlot(context, SessionTrackingFilter.class))));
        observed.put(FORCED_SIGN_OUT, GridRun.attempt(() -> present(context.getBeanNamesForType(IForceLogoutService.class).length > 0)));
        // Spring Boot's own authorization server configuration makes an AuthorizationServerSettings of its own wherever the
        // library is on the class path, so Contexa's server is told by the store of its authorizations and its clients, by their
        // names: they are held where they are not offered by type (R-17)
        observed.put(AUTHORIZATION_SERVER, GridRun.attempt(() -> present(context.containsBean("contexaAuthorizationService")
                && context.containsBean("contexaRegisteredClientRepository"))));
        observed.put(METHOD_SECURITY, GridRun.attempt(() -> present(context.containsBean("contexaPreAuthorizeAdvisor"))));
        observed.put(ATTEMPT_LISTENER, GridRun.attempt(() -> present(
                context.getBeanNamesForType(LoginAttemptEventListener.class).length > 0)));
        observed.put(MFA_SETTINGS, GridRun.attempt(() -> present(context.getBeanNamesForType(MfaConfigController.class).length > 0)));
        observed.put(AGENT_REGISTRATION, GridRun.attempt(() -> {
            AgentProvisioning provisioning = context.getBeanProvider(AgentProvisioning.class).getIfAvailable();
            return provisioning == null ? "absent" : provisioning.available() ? "available" : "refused";
        }));
        observed.put(AGENT_REVOCATION, GridRun.attempt(() -> {
            AgentTokenRevoker revoker = context.getBeanProvider(AgentTokenRevoker.class).getIfAvailable();
            return revoker == null ? "absent" : revoker == AgentTokenRevoker.NONE ? "none" : "available";
        }));
        observed.put(ADDRESS_CONTROL, GridRun.attempt(() -> {
            if (!context.containsBean("contexaIpAccessFilter")) {
                return "absent";
            }
            FilterRegistrationBean<?> filter = context.getBean("contexaIpAccessFilter", FilterRegistrationBean.class);
            return filter.getUrlPatterns().contains("/*") ? "every path" : "only " + filter.getUrlPatterns();
        }));
        observed.put(PASSKEY, GridRun.attempt(() -> {
            Object hostChain = context.containsBean("hostChain") ? context.getBean("hostChain") : null;
            return present(context.getBean(FilterChainProxy.class).getFilterChains().stream()
                    .filter(chain -> chain != hostChain)
                    .anyMatch(chain -> chain.getFilters().stream().anyMatch(filter -> filter instanceof WebAuthnAuthenticationFilter)));
        }));
        observed.put(PASSKEY_PAGE, GridRun.attempt(() -> {
            Object hostChain = context.containsBean("hostChain") ? context.getBean("hostChain") : null;
            List<SecurityFilterChain> passkeyChains = context.getBean(FilterChainProxy.class).getFilterChains().stream()
                    .filter(chain -> chain != hostChain)
                    .filter(chain -> chain.getFilters().stream().anyMatch(filter -> filter instanceof WebAuthnAuthenticationFilter))
                    .toList();
            if (passkeyChains.isEmpty()) {
                return "no passkey chain";
            }
            boolean springsPage = passkeyChains.stream().anyMatch(chain -> chain.getFilters().stream()
                    .anyMatch(filter -> filter instanceof DefaultWebAuthnRegistrationPageGeneratingFilter));
            boolean contexasPage = passkeyChains.stream().allMatch(chain -> chain.getFilters().stream()
                    .anyMatch(filter -> filter instanceof ContexaWebAuthnRegistrationPageFilter));
            return springsPage ? "Spring Security's page" : contexasPage ? "Contexa's page" : "no page";
        }));

        GridRun.Browser administrator = run.browser();
        observed.put(SIGN_IN, GridRun.attempt(() -> run.contexaSignIn(administrator)));
        observed.put(CONSOLE, GridRun.attempt(() ->
                String.valueOf(administrator.get("/contexa/admin/api/blacklist", "application/json").statusCode())));
        observed.put(CONTEXA_SESSION_TRACKED, GridRun.attempt(() -> run.tracked(GridRun.ADMIN)));
        if (hostSignsIn) {
            observed.put(HOST_SESSION_TRACKED, GridRun.attempt(() -> {
                GridRun.Browser user = run.browser();
                String signIn = run.hostSignIn(user, GridRun.HOST_USER, GridRun.HOST_PASSWORD, GridRun.hostLoginPath(combination));
                user.get(GridController.SECURED, "application/json");
                String tracked = run.tracked(GridRun.HOST_USER);
                return "tracked".equals(tracked) ? tracked : tracked + " (the application's sign-in answered " + signIn + ")";
            }));
        }
        // A policy that opens a page beside the one it closes: the refusal counts only where the open page is served, so that a
        // chain that closes every page (Spring Boot's default one) is not taken for the policy.
        observed.put(URL_POLICY, GridRun.attempt(() -> {
            run.urlPolicy("GRID_OPEN_INFO", GridController.OPEN, "permitAll");
            run.urlPolicy("GRID_OPEN_STAFF", "/h/open/staff/**", "hasAuthority('ROLE_ADMIN')");
            GridRun.Browser anonymous = run.browser();
            String open = anonymous.anonymous(GridController.OPEN);
            if (!open.startsWith("200 open info")) {
                return "the page a policy opens answered " + open.split(" ", 2)[0];
            }
            String answer = anonymous.anonymous(GridController.OPEN_STAFF);
            if (answer.startsWith("401 ") || answer.startsWith("403 ")) {
                return answer.contains("staff report") ? "refused, with the page " + answer : "refused";
            }
            return answer.startsWith("200 staff report") ? "served without asking the policy" : answer;
        }));
        return observed;
    }

    private static String present(boolean present) {
        return present ? "present" : "absent";
    }

    /** R-10: Contexa's filters behind the Spring Security chain run in its one filter slot, so they are looked for there. */
    private static boolean runsInTheFilterSlot(ConfigurableApplicationContext context, Class<?> filterType) {
        if (!context.containsBean(ContexaFilterSlotConfiguration.REGISTRATION_BEAN)) {
            return false;
        }
        Object filter = context.getBean(ContexaFilterSlotConfiguration.REGISTRATION_BEAN, FilterRegistrationBean.class).getFilter();
        return filter instanceof ContexaFilterSlot slot && slot.filters().stream().anyMatch(filterType::isInstance);
    }

    // ----- the applications: each shape once per mode, as an application declares its mode on the annotation -----

    /**
     * An existing Spring Security application: a chain that leaves {@code /h/open/**} open and closes the rest, and users of
     * its own. With mode FULL its chain is narrowed to its own paths ({@link GridRun#hostChain}, R-14).
     */
    abstract static class ApplicationWithItsChain extends GridModels {

        @Bean
        SecurityFilterChain hostChain(HttpSecurity http) throws Exception {
            return GridRun.hostChain(http, narrowed());
        }

        boolean narrowed() {
            return false;
        }

        @Bean
        UserDetailsService hostUsers() {
            return new InMemoryUserDetailsManager(User.withUsername(GridRun.HOST_USER)
                    .password("{noop}" + GridRun.HOST_PASSWORD).roles("USER").build());
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    static class SandboxWithItsChain extends ApplicationWithItsChain {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FullWithItsChain extends ApplicationWithItsChain {

        @Override
        boolean narrowed() {
            return true;
        }
    }

    /** A legacy application: pages and a database of its own, no security chain and no users of Spring Security. */
    abstract static class ApplicationWithoutSecurity extends GridModels {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity
    static class SandboxWithoutSecurity extends ApplicationWithoutSecurity {
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FullWithoutSecurity extends ApplicationWithoutSecurity {
    }
}
