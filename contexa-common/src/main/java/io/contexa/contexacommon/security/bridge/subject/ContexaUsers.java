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

import org.springframework.lang.Nullable;

/**
 * What a legacy application may tell Contexa about its users outside a request (section 6 of
 * docs/agent/bridge-v2-연동표준-초안.md). The call is optional: an administrator can delete a user in Contexa's console too.
 * No call throws; each answers a {@link ContexaBridgeResult}.
 */
public final class ContexaUsers {

    @Nullable
    private static volatile Handler handler;

    private ContexaUsers() {
    }

    /**
     * The user left the application (left the company, was deleted). Contexa deletes its copy of the user and every state
     * it keeps for the user's decisions. The same user id coming again later is a new user to Contexa.
     */
    public static ContexaBridgeResult delete(@Nullable String userId) {
        String user = BridgeCalls.userId(userId);
        if (user == null) {
            return BridgeCalls.invalid("a user id that breaks its rules");
        }
        return BridgeCalls.call(handler, "deletion of a user", current -> current.delete(user));
    }

    public static boolean isInitialized() {
        return handler != null;
    }

    /** At Contexa's start: the handler that does what the call asks. */
    public static void registerHandler(Handler usersHandler) {
        handler = usersHandler;
    }

    public static void clearHandler() {
        handler = null;
    }

    /** What Contexa does for the call; Contexa registers its own when it starts. */
    @FunctionalInterface
    public interface Handler {

        ContexaBridgeResult delete(String userId);
    }
}
