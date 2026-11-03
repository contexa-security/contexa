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
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

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
    private final boolean contexaOwned;

    public OwnershipStartupDiagnostics(ListableBeanFactory beans, boolean contexaOwned) {
        this.beans = beans;
        this.contexaOwned = contexaOwned;
    }

    @Override
    public void afterSingletonsInstantiated() {
        try {
            if (contexaOwned) {
                List<SecurityFilterChain> chains = new ArrayList<>();
                beans.getBeansOfType(FilterChainProxy.class).values()
                        .forEach(proxy -> chains.addAll(proxy.getFilterChains()));
                List<String> shadowed = shadowedApplicationChains(chains);
                if (!shadowed.isEmpty()) {
                    log.error("[Contexa] CONTEXA_OWNED: Contexa's security chain takes every request first, so the "
                            + "application's own chain(s) {} are never reached and their sign-in is not used. For an "
                            + "application that keeps its own sign-in, use HOST_OWNED (@EnableAISecurity without "
                            + "mode = FULL, or contexa.bridge.ownership=HOST_OWNED); otherwise remove those chains.",
                            shadowed);
                }
                List<String> stores = applicationUserStores(beans.getBeansOfType(UserDetailsService.class));
                if (!stores.isEmpty()) {
                    log.warn("[Contexa] CONTEXA_OWNED: Contexa's sign-in looks users up in the application's {} "
                            + "instead of Contexa's user store; Contexa's seeded administrator can sign in only if "
                            + "that store has the account.", stores);
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

    /** The chains after Contexa's chain for every request, in the order the security filter chain proxy tries them. */
    static List<String> shadowedApplicationChains(List<SecurityFilterChain> chains) {
        List<String> shadowed = new ArrayList<>();
        boolean behindContexa = false;
        for (SecurityFilterChain chain : chains) {
            if (behindContexa) {
                shadowed.add(chain instanceof DefaultSecurityFilterChain d
                        ? d.getRequestMatcher().toString() : chain.getClass().getSimpleName());
            } else if (chain instanceof OrderedSecurityFilterChain contexa
                    && contexa.getRequestMatcher() instanceof AnyRequestMatcher) {
                behindContexa = true;
            }
        }
        return shadowed;
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
