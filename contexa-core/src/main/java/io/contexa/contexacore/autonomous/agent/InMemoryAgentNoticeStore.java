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

import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/** The notices kept in memory (docs/agent A5-3): a deployment without the Contexa database. The latest 10,000 stay. */
public class InMemoryAgentNoticeStore implements AgentNoticeStore {

    static final int CAPACITY = 10_000;

    private final List<AgentNotice> notices = new ArrayList<>();
    private final Clock clock;

    public InMemoryAgentNoticeStore() {
        this(Clock.systemUTC());
    }

    public InMemoryAgentNoticeStore(Clock clock) {
        this.clock = clock;
    }

    @Override
    public synchronized AgentNotice save(AgentNotice notice) {
        notices.removeIf(kept -> kept.noticeId().equals(notice.noticeId()));
        notices.add(notice);
        while (notices.size() > CAPACITY) {
            notices.remove(0);
        }
        return notice;
    }

    @Override
    public synchronized List<AgentNotice> forRecipient(String recipientId, int limit) {
        return notices.stream()
                .filter(notice -> notice.recipientId().equals(recipientId))
                .sorted(Comparator.comparing(AgentNotice::createdAt).reversed())
                .limit(Math.max(0, limit))
                .toList();
    }

    @Override
    public synchronized List<AgentNotice> list(String tenantId, int limit) {
        return notices.stream()
                .filter(notice -> tenantId == null || Objects.equals(tenantId, notice.tenantId()))
                .sorted(Comparator.comparing(AgentNotice::createdAt).reversed())
                .limit(Math.max(0, limit))
                .toList();
    }

    @Override
    public synchronized void removeForRecipient(String recipientId) {
        if (recipientId != null) {
            notices.removeIf(notice -> notice.recipientId().equals(recipientId));
        }
    }

    @Override
    public synchronized boolean markRead(String noticeId, String recipientId) {
        for (int index = 0; index < notices.size(); index++) {
            AgentNotice notice = notices.get(index);
            if (notice.noticeId().equals(noticeId) && notice.recipientId().equals(recipientId)) {
                notices.set(index, new AgentNotice(notice.noticeId(), notice.kind(), notice.tenantId(),
                        notice.recipientId(), notice.agentId(), notice.delegationId(), notice.subject(),
                        notice.message(), notice.link(), notice.correlationId(), notice.createdAt(),
                        notice.deliveredBy(), notice.readAt() != null ? notice.readAt() : clock.instant()));
                return true;
            }
        }
        return false;
    }
}
