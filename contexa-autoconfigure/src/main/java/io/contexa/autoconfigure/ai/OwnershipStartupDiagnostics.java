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
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.autoconfigure.identity.IdentitySecurityCoreContexaOwnedConfiguration;
import io.contexa.contexacore.security.UnifiedUserDetailsService;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.OrderedSecurityFilterChain;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * What an installation should know at start about its ownership (findings F-1, F-2, F-8 of the ownership harness):
 * <ul>
 *   <li>CONTEXA_OWNED: Contexa's chain takes every request first, so a chain the application declared is never
 *   reached and its sign-in is silently gone;</li>
 *   <li>CONTEXA_OWNED: a user store the application declared answers Contexa's sign-in, so Contexa's seeded
 *   administrator can sign in only if that store has it;</li>
 *   <li>either ownership: a one-time-code factor is offered but no mail sender is configured, so no code can be
 *   delivered.</li>
 * </ul>
 */
@Slf4j
public class OwnershipStartupDiagnostics implements SmartInitializingSingleton {

    private final ListableBeanFactory beans;
    private final ContexaOperatingProfile profile;

    public OwnershipStartupDiagnostics(ListableBeanFactory beans, ContexaOperatingProfile profile) {
        this.beans = beans;
        this.profile = profile;
    }

    @Override
    public void afterSingletonsInstantiated() {
        log.info(report(profile, enforcement()));
        if (profile.declaredDatabaseUnused()) {
            log.warn("[Contexa] contexa.datasource.isolation.contexa-owned-application=true: the application's "
                    + "spring.datasource is not used; Contexa's database serves the application.");
        }
        if (profile.ownership() == SecurityOwnershipMode.CONTEXA_OWNED) {
            refuseApplicationChains(beans.getBeansOfType(FilterChainProxy.class).values().stream()
                    .flatMap(proxy -> proxy.getFilterChains().stream()).toList(), placeholderChain());
        }
        try {
            if (profile.ownership() == SecurityOwnershipMode.CONTEXA_OWNED) {
                List<String> stores = applicationUserStores(beans.getBeansOfType(UserDetailsService.class));
                if (stores.size() == 1) {
                    log.warn("[Contexa] CONTEXA_OWNED: Contexa's sign-in looks users up in the application's {} "
                            + "instead of Contexa's user store; Contexa's seeded administrator can sign in only if "
                            + "that store has the account.", stores);
                } else if (stores.size() > 1) {
                    log.warn("[Contexa] CONTEXA_OWNED: the application has several user stores {}, so Contexa's sign-in "
                            + "uses Contexa's own unless one of them is marked @Primary.", stores);
                }
            }
            boolean oneTimeCode = beans.getBeansOfType(PlatformConfig.class).values().stream()
                    .anyMatch(OwnershipStartupDiagnostics::offersOneTimeCode);
            EmailService email = beans.getBeanProvider(EmailService.class).getIfAvailable();
            if (oneTimeCodeUndeliverable(oneTimeCode, email != null && email.isMailSenderConfigured())) {
                log.warn("[Contexa] A one-time-code factor is offered but no mail sender is configured "
                        + "(spring.mail.*), so no code can be delivered: configure mail, or users verify with a "
                        + "passkey only.");
            }
        } catch (RuntimeException e) {
            log.warn("[Contexa] The ownership start-up checks could not run: {}", e.getMessage());
        }
    }

    private Object placeholderChain() {
        return beans.containsBean(IdentitySecurityCoreContexaOwnedConfiguration.PLACEHOLDER_CHAIN)
                ? beans.getBean(IdentitySecurityCoreContexaOwnedConfiguration.PLACEHOLDER_CHAIN) : null;
    }

    private String enforcement() {
        SecurityZeroTrustProperties zeroTrust = beans.getBeanProvider(SecurityZeroTrustProperties.class).getIfAvailable();
        return zeroTrust != null ? zeroTrust.getMode().name() : "none";
    }

    /** One line at start: how this application runs Contexa. */
    static String report(ContexaOperatingProfile profile, String enforcement) {
        return "[Contexa] mode=" + profile.mode() + " ownership=" + profile.ownership()
                + " data=" + (profile.contexaOwnsApplicationData() ? "contexa" : "application")
                + " enforcement=" + enforcement;
    }

    /**
     * An application that owns a chain keeps its sign-in, and Contexa's chain, which takes every request first, would leave
     * what that chain protects open. So it does not start. Contexa's own chains and its placeholder, which only keeps Boot's
     * default chain away, are not the application's, and neither is what {@code web.ignoring()} leaves: a chain without
     * filters signs nobody in.
     */
    static void refuseApplicationChains(List<SecurityFilterChain> chains, Object placeholder) {
        List<String> application = applicationChains(chains, placeholder);
        if (!application.isEmpty()) {
            throw new ContexaOperatingProfileException(
                    "Contexa owns the sign-in of this application, but the application declares its own security chain(s) " + application
                            + ". Contexa's chain takes every request first, so they would never run and what they protect would be open.",
                    "For an application that keeps its sign-in, use @EnableAISecurity without mode = FULL. For a new application "
                            + "whose sign-in Contexa owns, remove those chains.");
        }
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

    static boolean oneTimeCodeUndeliverable(boolean oneTimeCodeOffered, boolean mailConfigured) {
        return oneTimeCodeOffered && !mailConfigured;
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
