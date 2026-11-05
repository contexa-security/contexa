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
package io.contexa.contexacommon.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.lang.Nullable;

/**
 * A session whose first factor passed and whose MFA has not finished. Its authentication proves the password alone,
 * though it is saved like a finished sign-in so that it survives the redirects of the MFA flow: what must not take a
 * password for a sign-in reads this mark. The MFA flow of contexa-identity sets it and removes it.
 */
public final class MfaPendingSession {

    /** Starts with SPRING_SECURITY_ so that session fixation strategies keep it with the security context. */
    public static final String ATTRIBUTE = "SPRING_SECURITY_CONTEXA_MFA_PENDING_FLOW";

    private MfaPendingSession() {
    }

    /** Whether the session of the request waits for its MFA. */
    public static boolean of(@Nullable HttpServletRequest request) {
        HttpSession session = request != null ? request.getSession(false) : null;
        if (session == null) {
            return false;
        }
        try {
            return session.getAttribute(ATTRIBUTE) != null;
        } catch (IllegalStateException invalidated) {
            return false;
        }
    }
}
