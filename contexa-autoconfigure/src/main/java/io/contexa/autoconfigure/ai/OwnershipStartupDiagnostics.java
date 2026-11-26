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

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacommon.operating.ContexaOperatingProfileException;
import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.autoconfigure.identity.IdentitySignInConfiguration;
import io.contexa.contexacore.security.UnifiedUserDetailsService;
import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.OrderedSecurityFilterChain;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.webauthn.PasskeyLibrary;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.core.env.Environment;
import org.springframework.lang.Nullable;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

import java.util.LinkedHashMap;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * What an installation should know at start about how it runs Contexa (findings F-1, F-2, F-8 of the ownership harness, and
 * R-14 of docs/agent/운영모드-정상화-구현계획.md):
 * <ul>
 *   <li>FULL: Contexa's main chain takes every request the chains before it leave, so an application chain that takes every
 *   request as well cannot run beside it, and the start is refused with what to change;</li>
 *   <li>FULL with CONTEXA_OWNED: a user store the application declared is not read by Contexa's sign-in, which looks its
 *   own accounts up in Contexa's own store; the application's users do not sign in to Contexa;</li>
 *   <li>every way of running: a one-time-code factor is offered but no mail sender is configured, so no code can be
 *   delivered;</li>
 *   <li>FULL: the settings row holds PERMIT for URLs no policy names, so such a path is open to everyone. A new
 *   installation holds no decision and closes them; an upgrade never changes a stored one, whether an operator chose it or
 *   the column default of an older version put it there.</li>
 * </ul>
 */
@Slf4j
public class OwnershipStartupDiagnostics implements SmartInitializingSingleton {

    private static final String REACTIVE_ROUTES = "org.springframework.web.reactive.function.server.RouterFunction";
    /** What an application written for WebFlux declares and the servlet stack never calls. */
    private static final List<String> REACTIVE_ONLY = List.of("org.springframework.web.server.WebFilter",
            "org.springframework.security.web.server.SecurityWebFilterChain");

    private static final String UNDELIVERABLE = "[Contexa] A one-time-code factor is offered but no code can be delivered: ";
    private static final String NO_MAIL_SENDER = "[Contexa] A one-time-code factor is offered but no mail sender is configured "
            + "(spring.mail.*), so no code can be delivered: configure mail, or users verify with a passkey only.";

    /** What comes with Contexa and changes what Spring Boot configures in the application. */
    private static final Map<String, String> CLASS_PATH_IMPACT = orderedImpact();

    private final ListableBeanFactory beans;
    private final ContexaOperatingProfile profile;
    private final boolean reportClassPath;

    public OwnershipStartupDiagnostics(ListableBeanFactory beans, ContexaOperatingProfile profile) {
        this(beans, profile, true);
    }

    public OwnershipStartupDiagnostics(ListableBeanFactory beans, ContexaOperatingProfile profile, boolean reportClassPath) {
        this.beans = beans;
        this.profile = profile;
        this.reportClassPath = reportClassPath;
    }

    private static Map<String, String> orderedImpact() {
        Map<String, String> impact = new LinkedHashMap<>();
        impact.put("reactor.netty.http.client.HttpClient",
                "Reactor Netty (RestClient, RestTemplate and WebClient built by Boot use it unless the application has its own client)");
        impact.put("org.thymeleaf.spring6.view.ThymeleafViewResolver", "Thymeleaf (Contexa's screens write their views "
                + "with an engine of their own; Spring Boot configures Thymeleaf only for an application that uses it itself)");
        impact.put("io.micrometer.prometheusmetrics.PrometheusMeterRegistry", "Prometheus (Boot's simple meter registry is not created)");
        impact.put("jakarta.validation.Validator", "Bean Validation (@Valid and @Validated take effect)");
        // PR-173: an application written for WebFlux that declares no WebFlux bean (its controllers only) cannot be told from a
        // Spring MVC one while it runs, so this line, which every application gets, says what Spring Boot does with it
        impact.put("org.springframework.web.servlet.DispatcherServlet",
                "Spring MVC (Spring Boot runs the application on the servlet stack, one written for WebFlux too unless it sets "
                        + "spring.main.web-application-type=reactive, which Contexa refuses: WebFlux is not supported)");
        return impact;
    }

    @Override
    public void afterSingletonsInstantiated() {
        refuseReactiveRoutes(beans, getClass().getClassLoader());
        String reactive = reactiveBeansNotice(beans, getClass().getClassLoader());
        if (reactive != null) {
            log.warn(reactive);
        }
        log.info(report(profile, enforcement()));
        if (reportClassPath) {
            String impact = classPathImpact(getClass().getClassLoader());
            if (impact != null) {
                log.info(impact);
            }
        }
        String passkeys = PasskeyLibrary.unavailableNotice(getClass().getClassLoader());
        if (passkeys != null) {
            log.warn(passkeys);
        }
        if (profile.declaredDatabaseUnused()) {
            log.warn("[Contexa] contexa.datasource.isolation.contexa-owned-application=true: the application's "
                    + "spring.datasource is not used; Contexa's database serves the application.");
        }
        if (profile.mode() == SecurityMode.FULL) {
            refuseApplicationChains(beans.getBeansOfType(FilterChainProxy.class).values().stream()
                    .flatMap(proxy -> proxy.getFilterChains().stream()).toList(), placeholderChain());
        }
        try {
            if (profile.mode() == SecurityMode.FULL && profile.ownership() == SecurityOwnershipMode.CONTEXA_OWNED) {
                List<String> stores = applicationUserStores(beans.getBeansOfType(UserDetailsService.class));
                if (!stores.isEmpty()) {
                    log.warn(userStoresNotice(stores));
                }
            }
            boolean oneTimeCode = beans.getBeansOfType(PlatformConfig.class).values().stream()
                    .anyMatch(OwnershipStartupDiagnostics::offersOneTimeCode);
            EmailService email = beans.getBeanProvider(EmailService.class).getIfAvailable();
            if (oneTimeCodeUndeliverable(oneTimeCode, email != null && email.isMailSenderConfigured())) {
                log.warn(email == null ? NO_MAIL_SENDER : undeliverableCodeMessage(applicationMailSenders(beans),
                        mailHostSet(beans.getBeanProvider(Environment.class).getIfAvailable())));
            }
            if (profile.mode() == SecurityMode.FULL) {
                SystemRuntimeSettingsService settings = beans.getBeanProvider(SystemRuntimeSettingsService.class).getIfAvailable();
                String open = settings == null ? null
                        : openUnnamedPathsNotice(profile, settings.getSettings().getNoMatchingUrlPolicyDecision());
                if (open != null) {
                    log.warn(open);
                }
            }
        } catch (RuntimeException e) {
            log.warn("[Contexa] The ownership start-up checks could not run: {}", e.getMessage());
        }
    }

    private Object placeholderChain() {
        return beans.containsBean(IdentitySignInConfiguration.PLACEHOLDER_CHAIN)
                ? beans.getBean(IdentitySignInConfiguration.PLACEHOLDER_CHAIN) : null;
    }

    private String enforcement() {
        SecurityZeroTrustProperties zeroTrust = beans.getBeanProvider(SecurityZeroTrustProperties.class).getIfAvailable();
        return zeroTrust != null ? zeroTrust.getMode().name() : "none";
    }

    /**
     * Contexa brings the servlet stack, and Boot then runs an application written for WebFlux on it. Its annotated controllers
     * keep working, but its functional routes are never mapped: every one of them would answer 404 without a word.
     */
    static void refuseReactiveRoutes(ListableBeanFactory beans, ClassLoader loader) {
        String[] names = reactiveRoutes(beans, loader);
        if (names.length > 0) {
            throw reactiveRoutesRefused(names);
        }
    }

    /**
     * PR-173: Boot runs an application written for WebFlux on the servlet stack Contexa brings, and says nothing. Its WebFlux
     * filters and its WebFlux security chain are then beans nothing calls, so the start names them. Read from what the beans
     * are declared as: it creates none of them.
     */
    @Nullable
    static String reactiveBeansNotice(ListableBeanFactory beans, ClassLoader loader) {
        List<String> names = REACTIVE_ONLY.stream()
                .filter(type -> ClassUtils.isPresent(type, loader))
                .flatMap(type -> Arrays.stream(beans.getBeanNamesForType(ClassUtils.resolveClassName(type, loader), true, false)))
                .distinct()
                .sorted()
                .toList();
        if (names.isEmpty()) {
            return null;
        }
        return "[Contexa] This application runs on the servlet stack, which Contexa brings, and these WebFlux beans of it never"
                + " run there: " + String.join(", ", names) + ". An application written for WebFlux is not supported: remove"
                + " @EnableAISecurity from it.";
    }

    /** The application's WebFlux routes by bean name, read from what the beans are declared as: it creates none of them. */
    static String[] reactiveRoutes(ListableBeanFactory beans, ClassLoader loader) {
        if (!ClassUtils.isPresent(REACTIVE_ROUTES, loader)) {
            return new String[0];
        }
        return beans.getBeanNamesForType(ClassUtils.resolveClassName(REACTIVE_ROUTES, loader), true, false);
    }

    /** The one refusal of the application's WebFlux routes, whether they are found as beans or as their bean definitions. */
    static ContexaOperatingProfileException reactiveRoutesRefused(String[] names) {
        return new ContexaOperatingProfileException(
                "Contexa runs on a servlet stack, and this application has WebFlux routes that it never maps: "
                        + Arrays.toString(names) + ".",
                "Run this application on the servlet stack with Spring MVC, or remove Contexa from it.");
    }

    /** What the class path brought, for an application that wonders why Boot behaves differently. */
    static String classPathImpact(ClassLoader loader) {
        List<String> present = CLASS_PATH_IMPACT.entrySet().stream()
                .filter(entry -> ClassUtils.isPresent(entry.getKey(), loader))
                .map(Map.Entry::getValue)
                .toList();
        if (present.isEmpty()) {
            return null;
        }
        return "[Contexa] On the class path with Contexa, unless the application declares them itself: " + String.join("; ", present)
                + ". contexa.startup.class-path-report=false turns this line off.";
    }

    /** One line at start: how this application runs Contexa. */
    static String report(ContexaOperatingProfile profile, String enforcement) {
        return "[Contexa] mode=" + profile.mode() + " ownership=" + profile.ownership()
                + " data=" + (profile.contexaOwnsApplicationData() ? "contexa" : "application")
                + " enforcement=" + enforcement;
    }

    /**
     * With mode FULL Contexa's main chain takes every request the chains before it leave, and Spring Security runs no chain
     * after one that takes every request: an application chain that takes every request and Contexa's main chain cannot
     * both run (R-14 of docs/agent/운영모드-정상화-구현계획.md). So such an application does not start, and is told what to change.
     * A chain of the application's narrowed to its own paths runs ahead of Contexa's main chain and stays. Contexa's own
     * chains and its placeholder are not the application's, and neither is what {@code web.ignoring()} leaves.
     */
    static void refuseApplicationChains(List<SecurityFilterChain> chains, Object placeholder) {
        List<String> application = applicationChains(chains, placeholder).isEmpty() ? List.of()
                : chains.stream()
                        .filter(chain -> chain != placeholder && !(chain instanceof OrderedSecurityFilterChain) && !chain.getFilters().isEmpty())
                        .filter(chain -> chain instanceof DefaultSecurityFilterChain d && d.getRequestMatcher() instanceof AnyRequestMatcher)
                        .map(chain -> ((DefaultSecurityFilterChain) chain).getRequestMatcher().toString())
                        .toList();
        if (!application.isEmpty()) {
            throw applicationChainsRefused(application);
        }
    }

    /** The one refusal of the application's chains, whether they are found as built chains or as their bean definitions. */
    static ContexaOperatingProfileException applicationChainsRefused(List<String> application) {
        return new ContexaOperatingProfileException(
                "With mode FULL Contexa's main chain takes every request, and the application declares its own security chain(s) "
                        + application + " for every request as well. Spring Security runs no chain after one that takes every "
                        + "request, so one of the two would never run.",
                "Narrow the application's chain to the paths it protects, with http.securityMatcher(...): it then runs ahead of "
                        + "Contexa's main chain. For an application whose own chain stays its main one, use @EnableAISecurity without "
                        + "mode = FULL (SANDBOX).");
    }

    static List<String> applicationChains(List<SecurityFilterChain> chains, Object placeholder) {
        List<String> application = new ArrayList<>();
        for (SecurityFilterChain chain : chains) {
            if (chain != placeholder && !(chain instanceof OrderedSecurityFilterChain) && !chain.getFilters().isEmpty()) {
                application.add(chain instanceof DefaultSecurityFilterChain d ? d.getRequestMatcher().toString() : chain.getClass().getSimpleName());
            }
        }
        return application;
    }

    /** The user stores other than Contexa's own, by bean name. */
    static List<String> applicationUserStores(Map<String, UserDetailsService> stores) {
        return stores.entrySet().stream()
                .filter(entry -> !(entry.getValue() instanceof UnifiedUserDetailsService))
                .map(Map.Entry::getKey)
                .sorted()
                .toList();
    }

    /** The mail senders the application declares, by bean name: the ones Contexa would have to choose between. */
    static List<String> applicationMailSenders(ListableBeanFactory beans) {
        return Arrays.stream(beans.getBeanNamesForType(JavaMailSender.class, true, false)).sorted().toList();
    }

    /** Whether the application's settings name a mail host, which is what a mail sender is built from. */
    static boolean mailHostSet(@Nullable Environment environment) {
        return environment != null && StringUtils.hasText(environment.getProperty("spring.mail.host"));
    }

    /**
     * Why no code can be delivered, as it is: the application has several senders and Contexa does not choose one, and has no
     * {@code spring.mail.host} to build a sender of its own from; or there is none at all. Contexa's administrators reach the
     * console by a mailed code in every way of running Contexa, so where a host is set a sender is built from it whatever the
     * application declares, and none is left only when it could not be built.
     */
    static String undeliverableCodeMessage(List<String> applicationSenders, boolean mailHostSet) {
        if (mailHostSet) {
            return UNDELIVERABLE + "the sender Contexa builds from spring.mail.* could not be created (see the error logged before this "
                    + "line). Correct spring.mail.*, or users verify with a passkey only.";
        }
        if (applicationSenders.size() > 1) {
            String several = UNDELIVERABLE + "the application has several JavaMailSender beans " + applicationSenders
                    + " and Contexa does not choose one of them";
            return several + ", and spring.mail.host is not set, so Contexa has no sender of its own to build. Set spring.mail.host "
                    + "(Contexa then mails the codes with a sender it builds from spring.mail.*), or mark one of them @Primary, "
                    + "or users verify with a passkey only.";
        }
        if (applicationSenders.isEmpty()) {
            return UNDELIVERABLE + "the application has no JavaMailSender and spring.mail.host is not set. Set spring.mail.*, "
                    + "or users verify with a passkey only.";
        }
        return NO_MAIL_SENDER;
    }

    /** What the start says of the application's user stores: Contexa's sign-in does not read them, however many there are. */
    static String userStoresNotice(List<String> stores) {
        return "[Contexa] FULL mode with CONTEXA_OWNED: the application declares the user store(s) " + stores + ", which Contexa's sign-in "
                + "does not read: Contexa's own accounts sign in from Contexa's own user store, and the application's users "
                + "do not sign in to Contexa.";
    }

    static boolean oneTimeCodeUndeliverable(boolean oneTimeCodeOffered, boolean mailConfigured) {
        return oneTimeCodeOffered && !mailConfigured;
    }

    /**
     * In mode FULL, where Contexa's main chain decides the requests no policy names, a stored PERMIT for URLs no policy
     * names leaves every such path open to everyone, also those Spring Boot's default chain would have closed. An
     * installation made before the default changed holds PERMIT without anyone having chosen it, and an upgrade does not
     * change what is stored. In mode SANDBOX that decision decides no request of the application: on the application's
     * paths a URL policy that decides nothing leaves the decision of the application's own chain, so it is of no
     * consequence there.
     *
     * @param storedDecision the decision the settings row holds, null when none was saved
     * @return the line to log, null when there is nothing to tell
     */
    static String openUnnamedPathsNotice(ContexaOperatingProfile profile, String storedDecision) {
        if (profile.mode() != SecurityMode.FULL
                || storedDecision == null || !NoPolicyDecision.PERMIT.name().equals(storedDecision.trim())) {
            return null;
        }
        return "[Contexa] FULL: the stored decision for URLs no policy names is PERMIT, so everyone passes on a "
                + "path no policy names, also where Spring Boot's default chain would have asked for a sign-in. An "
                + "installation made before a signed-in user became the default holds PERMIT without anyone having "
                + "chosen it, and an upgrade does not change it: choose \"Decision when no URL policy applies\" on the "
                + "system settings screen.";
    }

    private static boolean offersOneTimeCode(PlatformConfig config) {
        for (AuthenticationFlowConfig flow : config.getFlows()) {
            if (flow.getRegisteredFactorOptions().keySet().stream()
                    .anyMatch(type -> type.name().contains("OTT"))) {
                return true;
            }
        }
        return false;
    }
}
