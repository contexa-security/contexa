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
package io.contexa.contexacommon.security.bridge;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Whether the accountable person confirmed this very request of an agent (docs/agent A5-2, A5-9). A confirmed request
 * answers the CHALLENGE in force for the agent, for this request only: what reads the decision while the request runs
 * (policies, synchronous decisions) reads it as allowed, and a BLOCK stays a BLOCK.
 */
public final class AgentRequestConfirmation {

    private AgentRequestConfirmation() {
    }

    /** The confirmation used by the request, or null. */
    @Nullable
    public static String of(@Nullable HttpServletRequest request) {
        Object confirmation = request != null ? request.getAttribute(BridgeRequestAttributes.AGENT_CONFIRMATION)
                : null;
        return confirmation instanceof String id && !id.isBlank() ? id : null;
    }

    /** The confirmation used by the request this thread serves, or null. */
    @Nullable
    public static String current() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        return attributes instanceof ServletRequestAttributes servlet ? of(servlet.getRequest()) : null;
    }
}
