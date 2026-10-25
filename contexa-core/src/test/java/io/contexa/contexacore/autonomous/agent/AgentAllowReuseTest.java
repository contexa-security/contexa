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

import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent F-1: how far an ALLOW answers an agent's later requests. */
class AgentAllowReuseTest {

    private static final String KEY = LearningSubject.agentKey("alice", "agent-7");

    @Test
    void anAllowAnswersTheLaterRequestsOfTheSameOperationWithinItsLimits() {
        AgentAllowReuse reuse = new AgentAllowReuse(2, 2, null);
        reuse.decided(KEY, "context-1", ActionFamily.READ, "DOC-1");

        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "DOC-2")).isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "DOC-3")).as("past the request limit").isFalse();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.EXPORT, "DOC-2")).as("another operation").isFalse();
        assertThat(reuse.answers(KEY, "context-2", ActionFamily.READ, "DOC-2")).as("another context").isFalse();
    }

    /** RL-5: an ALLOW answers one sensitive resource, so each further record is decided on its own. */
    @Test
    void anAllowAnswersFewerDistinctResourcesWhenTheResourceIsSensitive() {
        AgentAllowReuse reuse = new AgentAllowReuse(10, 3, 1, null);
        reuse.decided(KEY, "context-1", ActionFamily.READ, "CUS-1");

        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "CUS-1", true)).as("the same record").isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "CUS-2", true)).as("a second record").isFalse();
        // Not sensitive: the three resources of the general limit.
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "DOC-2", false)).isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "DOC-3", false)).isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "DOC-4", false)).isFalse();
    }

    @Test
    void aSensitiveLimitNeverExceedsTheGeneralOneAndTheOldConstructorKeepsTheOldBehaviour() {
        AgentAllowReuse capped = new AgentAllowReuse(10, 2, 5, null);
        capped.decided(KEY, "context-1", ActionFamily.READ, "CUS-1");
        assertThat(capped.answers(KEY, "context-1", ActionFamily.READ, "CUS-2", true)).isTrue();
        assertThat(capped.answers(KEY, "context-1", ActionFamily.READ, "CUS-3", true)).isFalse();

        AgentAllowReuse old = new AgentAllowReuse(10, 3, null);
        old.decided(KEY, "context-1", ActionFamily.READ, "CUS-1");
        assertThat(old.answers(KEY, "context-1", ActionFamily.READ, "CUS-2", true)).isTrue();
        assertThat(old.answers(KEY, "context-1", ActionFamily.READ, "CUS-3", true)).isTrue();
    }

    @Test
    void aRequestIsSensitiveWhenTheSensitivityItsResourceDeclaresClassifiesAsSensitiveOrCritical() {
        assertThat(AgentAllowReuse.sensitive(Map.of("resourceSensitivity", "RESTRICTED"))).isTrue();
        assertThat(AgentAllowReuse.sensitive(Map.of("resourceSensitivity", "CONFIDENTIAL"))).isTrue();
        assertThat(AgentAllowReuse.sensitive(Map.of("sensitivity", "HIGH"))).isTrue();
        assertThat(AgentAllowReuse.sensitive(Map.of("resourceSensitivity", "INTERNAL"))).isFalse();
        assertThat(AgentAllowReuse.sensitive(Map.of("resourceSensitivity", "PUBLIC"))).isFalse();
        assertThat(AgentAllowReuse.sensitive(Map.of())).isFalse();
        assertThat(AgentAllowReuse.sensitive(null)).isFalse();
    }
}
