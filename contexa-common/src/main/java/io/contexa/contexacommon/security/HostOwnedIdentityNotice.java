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
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * When the application owns sign-in (HOST_OWNED), Contexa's request filters run right after its Spring Security chain.
 * An application that sets the signed-in user later (in an MVC interceptor or a controller) is seen there without a
 * user, so a decision in force is enforced for its requests at {@code @Protectable} methods only (ownership design
 * S-7). The request filters mark such a request; a protected method that then sees a user reports it once.
 */
@Slf4j
public final class HostOwnedIdentityNotice {

    /** The request attribute the request filters set when they saw no signed-in user. */
    public static final String FRONT_SAW_NO_USER = "ctxa.zerotrust.front.no-user";

    private static final AtomicBoolean REPORTED = new AtomicBoolean();
    private static final AtomicLong LATE_SIGN_INS = new AtomicLong();

    private HostOwnedIdentityNotice() {
    }

    /** At the request filters: marks the request when no signed-in user is known yet. */
    public static void markWhenNoUser(HttpServletRequest request, @Nullable Authentication authentication) {
        if (!signedIn(authentication)) {
            request.setAttribute(FRONT_SAW_NO_USER, Boolean.TRUE);
        }
    }

    /** Whether the request filters saw no user and the protected method sees one. */
    public static boolean isLateSignIn(@Nullable HttpServletRequest request, @Nullable Authentication authentication) {
        return request != null && Boolean.TRUE.equals(request.getAttribute(FRONT_SAW_NO_USER))
                && signedIn(authentication);
    }

    /** At a protected method: reports, once per application, that the application signs users in late. */
    public static void reportAtProtectedMethod(@Nullable HttpServletRequest request,
                                               @Nullable Authentication authentication) {
        if (!isLateSignIn(request, authentication)) {
            return;
        }
        LATE_SIGN_INS.incrementAndGet();
        if (REPORTED.compareAndSet(false, true)) {
            log.warn("[Contexa] HOST_OWNED: the application sets the signed-in user after Spring Security's filters "
                    + "(in an MVC interceptor or a controller), so Contexa's request filters see no user and a "
                    + "decision in force is enforced at @Protectable methods only for such requests (first seen at "
                    + "{}). Set the user in a Spring Security filter to have every path enforced.",
                    request.getRequestURI());
        }
    }

    /** How many protected calls had a user the request filters did not see. */
    public static long lateSignIns() {
        return LATE_SIGN_INS.get();
    }

    private static boolean signedIn(@Nullable Authentication authentication) {
        return authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);
    }
}
