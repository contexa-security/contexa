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
 * Records a person's approval of an agent's request as a verifiable authorization (docs/agent A5-2, IETF AIMS 10.7):
 * where Contexa is the authorization server, an authorization of its own server; where the host owns the
 * authorization server, the host's implementation. The approved request runs only when its authorization verifies,
 * and the authorization is spent by that one use (A5-9).
 */
public interface AgentConfirmationAuthorizer {

    /**
     * Records the approval.
     *
     * @return the identifier of the authorization the approval is recorded as, shown to the person and the agent
     */
    String authorize(AgentConfirmation approved);

    /** Whether the approval's authorization is there, names this approval and is not spent. */
    boolean verify(AgentConfirmation approved);

    /** The approval was used by its request; its authorization is spent. */
    default void consumed(AgentConfirmation used) {
    }
}
