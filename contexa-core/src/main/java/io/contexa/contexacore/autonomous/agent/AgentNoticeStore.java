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

import java.util.List;

/**
 * The notices kept for the people accountable for agents (docs/agent A5-3, A5-2). The Contexa database keeps them
 * ({@code agent_notice}); without it they are kept in memory.
 */
public interface AgentNoticeStore {

    AgentNotice save(AgentNotice notice);

    /** The person's notices, latest first, at most {@code limit}. */
    List<AgentNotice> forRecipient(String recipientId, int limit);

    /** Every notice of the tenant (every tenant's for {@code null}), latest first, at most {@code limit}. */
    List<AgentNotice> list(@Nullable String tenantId, int limit);

    /** Marks the person's notice read; false when the person has no such notice. */
    boolean markRead(String noticeId, String recipientId);

    /** Forgets the person's notices (the person's account was deleted). */
    void removeForRecipient(String recipientId);
}
