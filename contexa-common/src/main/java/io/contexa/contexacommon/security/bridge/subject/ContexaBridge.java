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
package io.contexa.contexacommon.security.bridge.subject;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;

/**
 * What a legacy application may tell Contexa about its sign-ins (section 6 of docs/agent/bridge-v2-연동표준-초안.md). Every
 * call is optional: Contexa works without them, and they add the moment of a sign-in, a failed one and a sign-out, which
 * only the application knows when it signs its users in without Spring Security. An application that signs in with Spring
 * Security has nothing to call: Contexa listens to Spring Security's own events.
 * <p>
 * No call throws. Each answers a {@link ContexaBridgeResult}, and the application's request goes on whatever it is.
 */
public final class ContexaBridge {

    @Nullable
    private static volatile Handler handler;

    private ContexaBridge() {
    }

    /**
     * The user signed in on this request. Call it where the sign-in succeeded, after the application changed the session
     * id. Contexa makes the user the identity of the request and waits for its copy of the user (a second at most), so the
     * requests after it find the user known.
     */
    public static ContexaBridgeResult signedIn(@Nullable HttpServletRequest request, @Nullable ContexaSubject subject) {
        if (request == null || subject == null) {
            return BridgeCalls.invalid("no request or no subject");
        }
        if (!subject.hasUserId()) {
            return BridgeCalls.invalid("the user id breaks its rules");
        }
        return BridgeCalls.call(handler, "sign-in", current -> current.signedIn(request, subject));
    }

    /** A sign-in of the user failed on this request: the decisions count it as the failed sign-ins of the user. */
    public static ContexaBridgeResult signInFailed(@Nullable HttpServletRequest request, @Nullable String userId) {
        String user = BridgeCalls.userId(userId);
        if (request == null || user == null) {
            return BridgeCalls.invalid("no request, or a user id that breaks its rules");
        }
        return BridgeCalls.call(handler, "failed sign-in", current -> current.signInFailed(request, user));
    }

    /**
     * The user signed out on this request. Contexa ends its tracking of the request's session and lets go of what it kept
     * for the sign-in; a restriction of the user (a block, a challenge, a review) stays.
     */
    public static ContexaBridgeResult signedOut(@Nullable HttpServletRequest request, @Nullable String userId) {
        String user = BridgeCalls.userId(userId);
        if (request == null || user == null) {
            return BridgeCalls.invalid("no request, or a user id that breaks its rules");
        }
        return BridgeCalls.call(handler, "sign-out", current -> current.signedOut(request, user));
    }

    public static boolean isInitialized() {
        return handler != null;
    }

    /** At Contexa's start: the handler that does what the calls ask. */
    public static void registerHandler(Handler bridgeHandler) {
        handler = bridgeHandler;
    }

    public static void clearHandler() {
        handler = null;
    }

    /** What Contexa does for the calls; Contexa registers its own when it starts. */
    public interface Handler {

        ContexaBridgeResult signedIn(HttpServletRequest request, ContexaSubject subject);

        ContexaBridgeResult signInFailed(HttpServletRequest request, String userId);

        ContexaBridgeResult signedOut(HttpServletRequest request, String userId);
    }
}
