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

import org.springframework.lang.Nullable;

import java.time.Instant;

/**
 * A notice to the person accountable for an agent (docs/agent A5-3, A5-2): the agent was stopped, a request of it waits
 * for the person's confirmation, a confirmation expired. Every notice is kept, so the person and the console see it
 * whatever channel delivered it.
 *
 * @param noticeId      the notice's identifier
 * @param kind          what happened: {@link #AGENT_STOPPED}, {@link #CONFIRMATION_REQUESTED} and the like
 * @param tenantId      the tenant, or null
 * @param recipientId   the accountable person: the delegator, or the agent's sponsor when it acts on its own
 * @param agentId       the agent
 * @param delegationId  the delegation concerned, or null
 * @param subject       a one-line summary
 * @param message       what happened and what the person can do, in plain words
 * @param link          the path of the screen the person acts on, or null
 * @param correlationId the request or decision the notice is about, or null
 * @param createdAt     when the notice was made
 * @param deliveredBy   how it was delivered: {@link #CONSOLE} or the channel's name (MAIL)
 * @param readAt        when the person read it, or null
 */
public record AgentNotice(String noticeId, String kind, @Nullable String tenantId, String recipientId, String agentId,
                          @Nullable String delegationId, String subject, String message, @Nullable String link,
                          @Nullable String correlationId, Instant createdAt, String deliveredBy,
                          @Nullable Instant readAt) {

    /** The agent was stopped (a BLOCK, a report, the kill switch). */
    public static final String AGENT_STOPPED = "AGENT_STOPPED";
    /** A request of the agent waits for the person's confirmation. */
    public static final String CONFIRMATION_REQUESTED = "CONFIRMATION_REQUESTED";
    /** A confirmation was not given in time and the request was refused. */
    public static final String CONFIRMATION_EXPIRED = "CONFIRMATION_EXPIRED";
    /** The agent's requests were refused unusually often (A5-7). */
    public static final String DENIAL_RATE_ALARM = "DENIAL_RATE_ALARM";
    /** Kept for the console only: no channel delivered it. */
    public static final String CONSOLE = "CONSOLE";

    /** The notice as a channel delivered it. */
    public AgentNotice deliveredBy(String channel) {
        return new AgentNotice(noticeId, kind, tenantId, recipientId, agentId, delegationId, subject, message, link,
                correlationId, createdAt, channel, readAt);
    }
}
