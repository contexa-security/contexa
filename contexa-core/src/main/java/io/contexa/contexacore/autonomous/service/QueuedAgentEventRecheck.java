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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.agent.AgentAllowReuse;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.util.Map;

/**
 * docs/agent RL-12 (QD): an agent's event that waited its turn in the queue of its session is looked at again when the
 * turn comes. Between the time it was queued and now, another request of the agent may have been decided: a restriction
 * stored for the agent answers the event, and so does an ALLOW anchor that now reaches it. Such an event is recorded as a
 * request that reached no analysis (N-SES-1) and the model is not asked about it. Anything this cannot read leaves the
 * event to its analysis, as it was before.
 * <p>
 * PR-82: a person's call to a resource is read the same way, as the listener reads it when it is made: any decision in
 * force answers it, so the calls that waited behind a decision cost that decision and not one each. A sign-in is
 * analysed whatever is in force. A CHALLENGE no model decided answers nothing (Q-5): only the model ends it.
 */
@Slf4j
public class QueuedAgentEventRecheck implements SecurityPlaneAgent.QueuedEventRecheck {

    private final ZeroTrustActionRepository actionRepository;
    private final AgentAllowReuse agentAllowReuse;
    private final UnanalysedRequestRecorder unanalysedRequestRecorder;

    public QueuedAgentEventRecheck(ZeroTrustActionRepository actionRepository,
                                   @Nullable AgentAllowReuse agentAllowReuse,
                                   @Nullable UnanalysedRequestRecorder unanalysedRequestRecorder) {
        this.actionRepository = actionRepository;
        this.agentAllowReuse = agentAllowReuse;
        this.unanalysedRequestRecorder = unanalysedRequestRecorder;
    }

    @Override
    public boolean answeredWithoutAnalysis(@Nullable SecurityEvent event) {
        if (event == null || event.getUserId() == null || event.getUserId().isBlank() || event.getMetadata() == null) {
            return false;
        }
        boolean agent = agent(event.getMetadata());
        if (!agent && !"AUTHORIZATION".equals(event.getMetadata().get("zerotrust.category"))) {
            return false;
        }
        String contextHash = text(event.getMetadata().get("contextBindingHash"));
        if (contextHash == null) {
            return false;
        }
        try {
            ZeroTrustSubject subject = ZeroTrustSubject.ofFacts(event.getUserId(), event.getMetadata());
            String key = subject != null ? subject.storageKey() : event.getUserId();
            ZeroTrustAction action = actionRepository.getCurrentAction(key, contextHash);
            boolean answered = action == ZeroTrustAction.BLOCK || action == ZeroTrustAction.ESCALATE
                    || (action == ZeroTrustAction.CHALLENGE && !actionRepository.isTechnicalChallenge(key))
                    || (action == ZeroTrustAction.ALLOW && !agent);
            if (!answered && action == ZeroTrustAction.ALLOW && agentAllowReuse != null) {
                String path = text(event.getMetadata().get("requestPath"));
                answered = agentAllowReuse.answers(key, contextHash,
                        AgentAllowReuse.operation(event.getMetadata(), path),
                        AgentAllowReuse.resource(event.getMetadata(), path),
                        AgentAllowReuse.sensitive(event.getMetadata()));
            }
            if (answered && unanalysedRequestRecorder != null) {
                unanalysedRequestRecorder.recordQueued(event, action);
            }
            return answered;
        } catch (RuntimeException unreadable) {
            log.error("[QueuedAgentEventRecheck] The stored state could not be read; the event is analysed: eventId={}",
                    event.getEventId(), unreadable);
            return false;
        }
    }

    /**
     * Q-23: a request past what its user may hold of the analysis is not analysed. One that ran is a fact of its session
     * all the same; one a sensitive resource refused did not run.
     */
    @Override
    public void leftOut(@Nullable SecurityEvent event) {
        if (event == null || unanalysedRequestRecorder == null || event.getMetadata() == null
                || ZeroTrustEventPublisher.METHOD_NOT_RUN.equals(event.getMetadata().get("methodExecutionOutcome"))) {
            return;
        }
        unanalysedRequestRecorder.recordPassed(event);
    }

    private static boolean agent(Map<String, Object> metadata) {
        Object kind = metadata.get("executionSubjectKind");
        if (kind == null) {
            return false;
        }
        try {
            return SubjectKind.valueOf(kind.toString().trim()).agent();
        } catch (IllegalArgumentException unknownKind) {
            return false;
        }
    }

    @Nullable
    private static String text(@Nullable Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }
}
