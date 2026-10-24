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

public final class BridgeRequestAttributes {

    public static final String RESOLUTION_RESULT = "ctxa.bridge.resolution";
    public static final String AUTHENTICATION_STAMP = "ctxa.bridge.authentication.stamp";
    public static final String AUTHORIZATION_STAMP = "ctxa.bridge.authorization.stamp";
    public static final String DELEGATION_STAMP = "ctxa.bridge.delegation.stamp";
    public static final String COVERAGE_REPORT = "ctxa.bridge.coverage.report";
    public static final String USER_SYNC_RESULT = "ctxa.bridge.user.sync.result";
    public static final String HOST_PRINCIPAL_SNAPSHOT = "ctxa.bridge.host.principal.snapshot";
    /** Whether the person a delegated agent acts for may make the request (A1-8): an outcome name. */
    public static final String DELEGATOR_AUTHORITY = "ctxa.bridge.delegation.delegator-authority";
    /**
     * docs/agent A5-2, A5-9: the confirmation the accountable person gave for this very request of an agent, used by
     * it; set only on the request the confirmation is bound to.
     */
    public static final String AGENT_CONFIRMATION = "ctxa.bridge.agent.confirmation";
    /**
     * docs/agent F-5 (RW-1): what that confirmation says ({@link AgentConfirmationFacts}), set with it, so the decision
     * context of the request carries it.
     */
    public static final String AGENT_CONFIRMATION_FACTS = "ctxa.bridge.agent.confirmation.facts";
    /**
     * docs/agent A5-7: how many requests the agent's delegation made in the last minute, this one included (an
     * {@link Integer}); set by the call limits on an agent's request.
     */
    public static final String AGENT_RECENT_CALLS = "ctxa.bridge.agent.recent-calls";

    private BridgeRequestAttributes() {
    }
}
