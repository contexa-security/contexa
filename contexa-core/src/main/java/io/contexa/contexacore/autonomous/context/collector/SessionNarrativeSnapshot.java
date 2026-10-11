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
package io.contexa.contexacore.autonomous.context.collector;

import lombok.Builder;
import lombok.Value;

import java.util.List;
import io.contexa.contexacore.autonomous.context.collector.ContextSnapshot;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;

@Value
@Builder
public class SessionNarrativeSnapshot implements ContextSnapshot {
    String sessionId;
    Integer sessionAgeMinutes;
    /** What the session age counts from: LOGIN, SESSION_CREATED or FIRST_ANALYSED_REQUEST. */
    String sessionAgeBasis;
    /** True when no earlier request of this session was analysed. */
    Boolean newSession;
    String previousPath;
    String previousActionFamily;
    Long lastRequestIntervalMs;
    List<String> sessionActionSequence;
    List<String> sessionProtectableSequence;
    Boolean burstPattern;
    /** How many earlier requests of this session were challenged, blocked or escalated. */
    Integer recentChallengeCount;
    Integer recentBlockCount;
    Integer recentEscalationCount;
    /** The session's most recent decisions, oldest first ({@code SessionDecisionRecord#describe}). */
    List<String> sessionDecisionHistory;
    /** The same decisions as records, with their targets and item counts (W2-5). */
    List<SessionDecisionRecord> sessionDecisions;
    String summary;
}
