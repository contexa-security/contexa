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

import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;

/**
 * What the way of running Contexa decides while the application runs, in one place: code asks what to do, not which mode
 * or ownership is set. The mode decides who signs the application's users in and so who builds the main chain; the
 * ownership decides how Contexa gives way to the application's own components and whether Contexa's administrators sign in
 * apart from the application's users. Neither turns a feature of Contexa off.
 *
 * @param mode      the mode it was computed from
 * @param ownership the ownership it was computed from
 */
public record OperatingBehaviour(SecurityMode mode, SecurityOwnershipMode ownership) {

    public static OperatingBehaviour of(SecurityMode mode, SecurityOwnershipMode ownership) {
        return new OperatingBehaviour(mode, ownership);
    }

    public static OperatingBehaviour of(ContexaOperatingProfile profile) {
        return new OperatingBehaviour(profile.mode(), profile.ownership());
    }

    /** Whether Contexa builds the application's main chain, which signs the application's users in (FULL). */
    public boolean buildsMainChain() {
        return mode == SecurityMode.FULL;
    }

    /** Whether Contexa's chain signs the application's users in; where it does not, their sign-in is the application's. */
    public boolean signsInTheApplicationsUsers() {
        return mode == SecurityMode.FULL;
    }

    /**
     * Whether Contexa may write the security context of the application's requests: only where its own chain signs those
     * users in. An application kept apart (SANDBOX) keeps its security context to itself.
     */
    public boolean writesSecurityContext() {
        return mode == SecurityMode.FULL;
    }

    /**
     * Whether the decisions on the application's requests are enforced by servlet filters behind the application's chain
     * (SANDBOX), rather than on Contexa's main chain (FULL).
     */
    public boolean enforcesFromServletFilters() {
        return mode == SecurityMode.SANDBOX;
    }

    /**
     * Whether Contexa's administrators sign in on a chain of Contexa's own, apart from the application's users. Only where
     * Contexa's main chain signs the application's users in with Contexa's own components (FULL with CONTEXA_OWNED) are the
     * two one, so that one person's sign-in is not split in two.
     */
    public boolean adminRealmOnItsOwnChain() {
        return !(mode == SecurityMode.FULL && ownership == SecurityOwnershipMode.CONTEXA_OWNED);
    }

    /** Whether a component the application brings itself wins over Contexa's of the same kind for the application. */
    public boolean hostComponentsWin() {
        return ownership == SecurityOwnershipMode.HOST_OWNED;
    }
}
