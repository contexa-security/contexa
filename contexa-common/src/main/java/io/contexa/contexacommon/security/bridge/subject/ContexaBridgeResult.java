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

import java.util.Objects;

/**
 * What a call of {@link ContexaBridge} or {@link ContexaUsers} came to (section 6 of docs/agent/bridge-v2-연동표준-초안.md).
 * Contexa never throws to the application for one of these calls: the outcome tells it, and the application's request goes
 * on whatever it is.
 *
 * @param outcome what happened
 * @param reason  why, for the application's own log; it never holds a user id or a mail address
 */
public record ContexaBridgeResult(Outcome outcome, String reason) {

    public ContexaBridgeResult {
        Objects.requireNonNull(outcome, "outcome");
        reason = reason != null ? reason : "";
    }

    public enum Outcome {

        /** Contexa did what the call asked. */
        DONE,

        /** The call has nothing to do where Contexa runs as it does, for one in mode FULL, which signs the users in itself. */
        NOT_APPLICABLE,

        /** Contexa has not started, or is not turned on in this application. */
        NOT_INITIALIZED,

        /** What the application passed breaks the contract: no request, no user, or a user id that breaks its rules. */
        INVALID,

        /** Contexa failed to do it. */
        FAILED
    }

    public static ContexaBridgeResult done() {
        return new ContexaBridgeResult(Outcome.DONE, "");
    }

    public static ContexaBridgeResult of(Outcome outcome, String reason) {
        return new ContexaBridgeResult(outcome, reason);
    }

    public boolean isDone() {
        return outcome == Outcome.DONE;
    }
}
