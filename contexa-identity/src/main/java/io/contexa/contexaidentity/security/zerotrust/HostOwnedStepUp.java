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
package io.contexa.contexaidentity.security.zerotrust;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

/**
 * The step-up of a CHALLENGE when the application owns sign-in (HOST_OWNED). The application keeps its login, session
 * and cookies, so Contexa starts no MFA flow of its own: the user is sent to Contexa's verification-only step-up, which
 * records the result as a decision and leaves the application's authentication as it was. A re-authentication the
 * application itself made after the CHALLENGE (its own MFA or identity provider, seen in the bridge's authentication
 * stamp) answers the CHALLENGE as well.
 */
public interface HostOwnedStepUp {

    /** Where the step-up continues; the pages under it are Contexa's own. */
    String STEP_UP_PATH = "/contexa/step-up";

    /**
     * Where a console session verifies itself: inside the block list, the one place of the console that stays
     * open to it. The console's chain takes it, so the user is the console's administrator.
     */
    String CONSOLE_STEP_UP_PATH = "/contexa/admin/blacklist/step-up";

    /** The step-up page for this request, context path included. */
    default String stepUpUrl(HttpServletRequest request) {
        return request.getContextPath() + STEP_UP_PATH;
    }

    /**
     * Whether the application re-authenticated the user with more than one factor after the CHALLENGE in force; when
     * it did, the CHALLENGE is resolved here as a completed step-up and the request goes on.
     *
     * @param decisionKey the key the CHALLENGE is stored under
     */
    boolean resolvedByHostReauthentication(HttpServletRequest request, Authentication authentication,
                                           String decisionKey);
}
