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
package io.contexa.autoconfigure.core;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.operating.OperatingBehaviour;
import io.contexa.contexacommon.security.ConsoleSession;
import org.springframework.core.env.Environment;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.function.BooleanSupplier;

/**
 * Whether the sign-in of the current request is that of an account of Contexa's (docs/agent/운영모드-정상화-구현계획.md): a
 * request of Contexa's console, whose administrators are Contexa's accounts, or any request where Contexa's main chain signs
 * the application's users in with Contexa's own store (mode FULL with CONTEXA_OWNED). Everywhere else the application's
 * users are its own: kept apart (SANDBOX), the application signs them in itself, and in mode FULL with HOST_OWNED Contexa's
 * chain signs them in with the application's store.
 */
public final class ContexaAccountRequests {

    private ContexaAccountRequests() {
    }

    /** The answer for the request of the moment, asked when it is needed; the way of running is read once. */
    public static BooleanSupplier of(Environment environment) {
        boolean applicationsUsersAreContexas = applicationsUsersAreContexas(environment);
        return () -> applicationsUsersAreContexas || consoleRequest();
    }

    /** Whether Contexa's main chain signs the application's users in with Contexa's own store. */
    public static boolean applicationsUsersAreContexas(Environment environment) {
        return applicationsUsersAreContexas(OperatingBehaviour.of(ContexaOperatingProfile.resolve(environment)));
    }

    /** The same answer for a way of running Contexa already read, for what runs before the context has its beans. */
    public static boolean applicationsUsersAreContexas(OperatingBehaviour behaviour) {
        return behaviour.signsInTheApplicationsUsers() && !behaviour.hostComponentsWin();
    }

    private static boolean consoleRequest() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                && ConsoleSession.of(attributes.getRequest());
    }
}
