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

/**
 * Where Contexa's servlet filters run (R-10 of docs/agent/운영모드-정상화-구현계획.md). The ones that act on what the Spring
 * Security filter chain established run in Contexa's one filter slot ({@link ContexaFilterSlot}), mapped after that
 * chain and after every filter of the application's, whatever the mode and the ownership, in a fixed order: the bridge,
 * the CHALLENGE, the BLOCK and ESCALATE, the guard of the user paths, the URL policies, the session tracking. The
 * application's filters have all run when they decide, and none runs between two of them, so the order the application
 * gives its own filters changes nothing in what Contexa does. Which of them is on stays the mode's
 * matter: under mode FULL the zero trust filters run inside Contexa's own chain and stay out of the slot. The address
 * control and the refusal answer run ahead of the chain on their own registrations, and the clean-up of the sign-in
 * attempts first of all.
 */
public final class ContexaServletFilterOrder {

    /** The places inside the slot, in the order its members run. */
    public static final int BRIDGE = 1;
    public static final int CHALLENGE = 2;
    public static final int ACCESS_CONTROL = 3;
    public static final int USER_PATH_GUARD = 4;
    /**
     * The URL policies on the application's requests (R-7 of docs/agent/운영모드-정상화-구현계획.md), in every way of running
     * Contexa: after the decisions, as authorization is last in Contexa's own chain.
     */
    public static final int URL_POLICY = 5;

    /**
     * The tracking of the signed-in sessions, in every way of running Contexa: last, behind the Spring Security filter chain
     * and the application's filters, so that it sees whom the chain that took the request signed in.
     */
    public static final int SESSION_TRACKING = 10;
    /**
     * The address control, ahead of the Spring Security filter chain and of the refusal filter right ahead of it, on a
     * registration of its own: an address its rules shut out reaches no chain, the application's or Contexa's.
     */
    public static final int ADDRESS_CONTROL = -2;

    private ContexaServletFilterOrder() {
    }

    /** The order of the Spring Security filter chain ({@code spring.security.filter.order}, -100 by default). */
    public static int securityFilterOrder(ObjectProvider<SecurityProperties> securityProperties) {
        SecurityProperties properties = securityProperties != null ? securityProperties.getIfAvailable() : null;
        return properties != null ? properties.getFilter().getOrder() : SecurityProperties.DEFAULT_FILTER_ORDER;
    }

    /**
     * A member of Contexa's filter slot: the given filter, under the given name, on every path, at the given place in the
     * slot. Its order is the Spring Security filter chain's plus its place, so that it reads where it stands; only its
     * place among the slot's members counts, as the servlet container never maps it on its own.
     */
    public static <T extends Filter> ContexaSlotFilterRegistration<T> member(T filter, String name, int securityFilterOrder,
                                                                             int position) {
        ContexaSlotFilterRegistration<T> registration = new ContexaSlotFilterRegistration<>(filter);
        registration.setName(name);
        registration.setOrder(securityFilterOrder + position);
        registration.addUrlPatterns("/*");
        return registration;
    }
}
