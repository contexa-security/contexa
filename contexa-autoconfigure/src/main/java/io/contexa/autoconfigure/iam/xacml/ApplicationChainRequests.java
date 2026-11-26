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
package io.contexa.autoconfigure.iam.xacml;

import io.contexa.autoconfigure.ai.SandboxIsolationAutoConfiguration;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

/**
 * The application's requests (R-7 and R-16 of docs/agent/운영모드-정상화-구현계획.md): those the Spring Security filter chain
 * proxy gives a chain of the application's own, or no chain. A chain of the application's own is a chain bean whose name
 * does not start with "contexa", Spring Boot's default chain among them, and Contexa's isolation chain, which stands in for
 * an application without security of its own (R-15). Every other chain the proxy holds is Contexa's: its flows (the realm
 * of its administrators, the main chain of mode FULL) and the paths it leaves outside security; a request one of them takes
 * is that chain's to decide. As the proxy does, the first chain in its order that matches a request takes it.
 */
final class ApplicationChainRequests implements RequestMatcher {

    private final ListableBeanFactory beanFactory;
    private volatile Chains chains;

    ApplicationChainRequests(ListableBeanFactory beanFactory) {
        this.beanFactory = beanFactory;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        Chains current = chains();
        if (current == null) {
            return true;
        }
        for (SecurityFilterChain chain : current.ordered()) {
            if (chain.matches(request)) {
                return current.applications().contains(chain);
            }
        }
        return true;
    }

    /** The proxy's chains, read once it exists; null while there is no proxy, so no chain of Contexa's takes a request. */
    @Nullable
    private Chains chains() {
        Chains current = chains;
        if (current != null) {
            return current;
        }
        FilterChainProxy proxy = proxy();
        if (proxy == null) {
            return null;
        }
        Set<SecurityFilterChain> applications = Collections.newSetFromMap(new IdentityHashMap<>());
        beanFactory.getBeansOfType(SecurityFilterChain.class).forEach((name, chain) -> {
            if (!name.startsWith("contexa") || SandboxIsolationAutoConfiguration.ISOLATION_CHAIN.equals(name)) {
                applications.add(chain);
            }
        });
        current = new Chains(List.copyOf(proxy.getFilterChains()), applications);
        chains = current;
        return current;
    }

    @Nullable
    private FilterChainProxy proxy() {
        String name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME;
        if (!beanFactory.containsBean(name)) {
            return null;
        }
        Object filter = beanFactory.getBean(name);
        if (filter instanceof FilterChainProxy proxy) {
            return proxy;
        }
        return filter instanceof DebugFilter debug ? debug.getFilterChainProxy() : null;
    }

    /**
     * @param ordered      the proxy's chains, in its order
     * @param applications the chains of the application's own, by identity
     */
    private record Chains(List<SecurityFilterChain> ordered, Set<SecurityFilterChain> applications) {
    }
}
