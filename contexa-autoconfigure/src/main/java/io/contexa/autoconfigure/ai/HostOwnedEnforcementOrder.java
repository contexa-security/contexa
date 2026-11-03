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

import jakarta.servlet.Filter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.core.Ordered;

/**
 * Where Contexa's enforcement runs when the application owns sign-in (HOST_OWNED): as servlet filters right after the
 * Spring Security filter chain, in the order they have inside Contexa's chain (bridge, CHALLENGE, BLOCK and ESCALATE).
 * The application's chain has then established who the user is, its own rules have run first, and Contexa adds no
 * chain of its own. Under CONTEXA_OWNED the same filters run inside Contexa's chain and their registrations stay off;
 * the bridge keeps the servlet registration it always had.
 */
public final class HostOwnedEnforcementOrder {

    public static final int BRIDGE = 1;
    public static final int CHALLENGE = 2;
    public static final int ACCESS_CONTROL = 3;
    public static final int USER_PATH_GUARD = 4;

    private HostOwnedEnforcementOrder() {
    }

    /** The order of the Spring Security filter chain ({@code spring.security.filter.order}, -100 by default). */
    public static int securityFilterOrder(ObjectProvider<SecurityProperties> securityProperties) {
        SecurityProperties properties = securityProperties != null ? securityProperties.getIfAvailable() : null;
        return properties != null ? properties.getFilter().getOrder() : SecurityProperties.DEFAULT_FILTER_ORDER;
    }

    public static <T extends Filter> FilterRegistrationBean<T> bridge(FilterRegistrationBean<T> registration,
                                                               boolean hostOwned, int securityFilterOrder) {
        registration.setEnabled(true);
        registration.setOrder(hostOwned ? securityFilterOrder + BRIDGE : Ordered.LOWEST_PRECEDENCE);
        registration.addUrlPatterns("/*");
        return registration;
    }

    public static <T extends Filter> FilterRegistrationBean<T> enforcement(FilterRegistrationBean<T> registration,
                                                                    boolean hostOwned, int securityFilterOrder,
                                                                    int position) {
        registration.setEnabled(hostOwned);
        if (hostOwned) {
            registration.setOrder(securityFilterOrder + position);
            registration.addUrlPatterns("/*");
        }
        return registration;
    }
}
