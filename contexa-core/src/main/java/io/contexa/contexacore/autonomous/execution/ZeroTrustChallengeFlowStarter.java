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
package io.contexa.contexacore.autonomous.execution;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Optional;

/**
 * Starts the step-up (MFA) flow of the current user when a synchronous decision answers CHALLENGE.
 *
 * <p>An earlier CHALLENGE is enforced by the request filters, which start the flow before they answer, so the user
 * can step up at once. A synchronous {@code @Protectable} decides inside the request, after those filters, and answers
 * through {@link ZeroTrustExceptionHandler}; this hook lets that answer start the same flow. The identity module
 * provides it; without it the answer stays as it is and the flow starts on the user's next request.</p>
 */
public interface ZeroTrustChallengeFlowStarter {

    /**
     * Starts the flow, or reuses the one already started for this user.
     *
     * @return where the user continues the step-up, or empty when no flow could be started (no authenticated user, a
     *         start already in progress, or a failure)
     */
    Optional<String> start(HttpServletRequest request, HttpServletResponse response);
}
