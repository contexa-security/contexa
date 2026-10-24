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
package io.contexa.contexacore.autonomous.agent;

/**
 * Revokes the tokens an agent holds (docs/agent A5-3, OWASP ASI10 #4): those its client was issued for a person it acts
 * for, or its own. Contexa's authorization server revokes its own authorizations (a revoked access token is refused on
 * the next request); a host whose tokens come from another authorization server declares its own implementation (its
 * revocation or introspection endpoint). Without one, a stop relies on the agent's block and suspension alone, which
 * every token of the agent meets at the resource server.
 */
public interface AgentTokenRevoker {

    /** No authorization server whose tokens Contexa can revoke: every call answers {@link #NOT_REVOCABLE}. */
    AgentTokenRevoker NONE = (principalName, clientId) -> AgentTokenRevoker.NOT_REVOCABLE;

    /** What {@link #revoke} answers when it cannot revoke this deployment's tokens. */
    int NOT_REVOCABLE = -1;

    /**
     * Revokes the tokens issued to the client for the principal: a person the agent acts for, or the client itself for
     * its own tokens.
     *
     * @return how many authorizations were revoked
     */
    int revoke(String principalName, String clientId);
}
