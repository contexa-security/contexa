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

import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.time.Clock;
import java.util.UUID;

/**
 * Sends and keeps the notices to the people accountable for agents (docs/agent A5-3, A5-2): the channel delivers, the
 * store keeps every notice for the console, delivered or not.
 */
@Slf4j
public class AgentNotices {

    private final AgentNoticeStore store;
    private final AgentNoticeChannel channel;
    private final Clock clock;

    public AgentNotices(AgentNoticeStore store, @Nullable AgentNoticeChannel channel) {
        this(store, channel, Clock.systemUTC());
    }

    public AgentNotices(AgentNoticeStore store, @Nullable AgentNoticeChannel channel, Clock clock) {
        this.store = store;
        this.channel = channel;
        this.clock = clock;
    }

    /**
     * Notifies the person; the notice as kept, or null without a person to notify.
     */
    @Nullable
    public AgentNotice notify(String kind, @Nullable String tenantId, @Nullable String recipientId, String agentId,
                              @Nullable String delegationId, String subject, String message, @Nullable String link,
                              @Nullable String correlationId) {
        return notify(kind, tenantId, recipientId, agentId, delegationId, subject, message, link, correlationId, true);
    }

    /**
     * Notifies the person; without delivery the notice is kept for the console only ({@link AgentNotice#CONSOLE}).
     *
     * @param deliver whether the channel delivers it too
     * @return the notice as kept, or null without a person to notify
     */
    @Nullable
    public AgentNotice notify(String kind, @Nullable String tenantId, @Nullable String recipientId, String agentId,
                              @Nullable String delegationId, String subject, String message, @Nullable String link,
                              @Nullable String correlationId, boolean deliver) {
        if (!StringUtils.hasText(recipientId)) {
            return null;
        }
        AgentNotice notice = new AgentNotice(UUID.randomUUID().toString(), kind, tenantId, recipientId.trim(), agentId,
                delegationId, subject, message, link, correlationId, clock.instant(), AgentNotice.CONSOLE, null);
        String deliveredBy = null;
        if (deliver && channel != null) {
            try {
                deliveredBy = channel.deliver(notice);
            } catch (RuntimeException e) {
                log.error("Agent notice delivery failed; the notice is kept for the console. noticeId={}, kind={}",
                        notice.noticeId(), kind, e);
            }
        }
        return store.save(StringUtils.hasText(deliveredBy) ? notice.deliveredBy(deliveredBy) : notice);
    }

    public AgentNoticeStore store() {
        return store;
    }
}
