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
package io.contexa.contexacommon.operating;

import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;

/**
 * What the ownership of the sign-in decides while the application runs, in one place: code asks what to do, not who owns
 * the sign-in.
 */
public enum OwnershipBehaviour {

    /** The application signs its users in; Contexa reads what the application decided and guards from the servlet filters. */
    HOST_OWNED(false, false, true, "/contexa/*", true),

    /** Contexa signs the users in, on a chain of its own that takes every request first. */
    CONTEXA_OWNED(true, true, false, "/*", false);

    private final boolean buildsSecurityChain;
    private final boolean writesSecurityContext;
    private final boolean enforcesFromServletFilters;
    private final String adminIpFilterPattern;
    private final boolean consoleSignsInOnItsOwnChain;

    OwnershipBehaviour(boolean buildsSecurityChain, boolean writesSecurityContext, boolean enforcesFromServletFilters,
                       String adminIpFilterPattern, boolean consoleSignsInOnItsOwnChain) {
        this.buildsSecurityChain = buildsSecurityChain;
        this.writesSecurityContext = writesSecurityContext;
        this.enforcesFromServletFilters = enforcesFromServletFilters;
        this.adminIpFilterPattern = adminIpFilterPattern;
        this.consoleSignsInOnItsOwnChain = consoleSignsInOnItsOwnChain;
    }

    public static OwnershipBehaviour of(SecurityOwnershipMode ownership) {
        return ownership == SecurityOwnershipMode.CONTEXA_OWNED ? CONTEXA_OWNED : HOST_OWNED;
    }

    /** Whether Contexa builds the sign-in chain from the platform configuration. */
    public boolean buildsSecurityChain() {
        return buildsSecurityChain;
    }

    /** Whether Contexa may write the security context; where the application signs in, that is the application's. */
    public boolean writesSecurityContext() {
        return writesSecurityContext;
    }

    /** Whether the verdicts are enforced by servlet filters behind the application's chain, rather than on Contexa's chain. */
    public boolean enforcesFromServletFilters() {
        return enforcesFromServletFilters;
    }

    /** The requests the administrators' address filter sees. */
    public String adminIpFilterPattern() {
        return adminIpFilterPattern;
    }

    /** Whether the console signs its administrators in on a chain of its own. */
    public boolean consoleSignsInOnItsOwnChain() {
        return consoleSignsInOnItsOwnChain;
    }
}
