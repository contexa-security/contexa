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

package io.contexa.contexacommon.security.subject;

import org.springframework.lang.Nullable;

import java.util.Optional;

/**
 * The agents an application approved, looked up by the OAuth2 client their tokens are issued to (A1-2, AG-12b).
 * The resource server accepts a client's own token without a user account only for a client this directory names,
 * and the delegation stamp reads such a client's tokens as the agent's. Contexa's agent registry answers it with its
 * allowlisted agents in service; an application may declare its own bean instead.
 */
@FunctionalInterface
public interface AgentClientDirectory {

    /** No client is an approved agent. */
    AgentClientDirectory NONE = (tenantId, clientId) -> Optional.empty();

    /**
     * The identifier of the approved agent in service that the client is, or empty when the client is not one: never
     * registered, only observed, suspended or deregistered.
     *
     * @param tenantId the tenant the token names, or {@code null} for a single-tenant deployment
     * @param clientId the client the token was issued to
     */
    Optional<String> activeAgentForClient(@Nullable String tenantId, String clientId);

    /**
     * The identifier of the approved agent in service that signed in with this account, or empty for a person's
     * account (A1-13). By default an account stands for the agent registered under that identifier or that client.
     *
     * @param tenantId    the tenant of the request, or {@code null} for a single-tenant deployment
     * @param accountName the name the request authenticated as
     */
    default Optional<String> activeAgentForAccount(@Nullable String tenantId, String accountName) {
        return activeAgentForClient(tenantId, accountName);
    }

    /**
     * docs/agent A5-3: whether the client is an agent a security decision or an operator suspended. Its tokens, its own
     * and those issued to it for people, are refused until it is resumed. None by default.
     *
     * @param tenantId the tenant the token names, or {@code null} for a single-tenant deployment
     * @param clientId the client the token was issued to
     */
    default boolean suspendedAgentClient(@Nullable String tenantId, String clientId) {
        return false;
    }
}
