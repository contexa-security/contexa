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

    /** RC-01: an ALLOW decided for a general resource never answers a sensitive one, whatever the sets would say. */
    @Test
    void anAllowDecidedForAGeneralResourceNeverAnswersASensitiveOne() {
        AgentAllowReuse reuse = new AgentAllowReuse(10, 3, 1, null);
        reuse.decided(KEY, "context-1", ActionFamily.READ, "DOC-1", false);

        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "CUS-1", true)).isFalse();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "DOC-2", false)).isTrue();
    }

    /** RC-02: an ALLOW decided for a sensitive resource answers general ones within the general limits. */
    @Test
    void anAllowDecidedForASensitiveResourceAnswersGeneralOnesWithinTheGeneralLimits() {
        AgentAllowReuse reuse = new AgentAllowReuse(10, 3, 1, null);
        reuse.decided(KEY, "context-1", ActionFamily.READ, "CUS-1", true);

        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "DOC-2", false)).isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "DOC-3", false)).isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "DOC-4", false)).isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "DOC-5", false))
                .as("a fourth general resource").isFalse();
        // The general resources it answered do not use up what it keeps for its own sensitive resource.
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "CUS-1", true)).isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "CUS-2", true)).as("a second record").isFalse();
    }

    /** RC-03: the sensitive and the general ALLOW each keep their own anchor; one does not erase the other. */
    @Test
    void theSensitiveAndTheGeneralAnchorDoNotEraseEachOther() {
        AgentAllowReuse reuse = new AgentAllowReuse(10, 3, 1, null);
        reuse.decided(KEY, "context-1", ActionFamily.READ, "DOC-1", false);
        reuse.decided(KEY, "context-1", ActionFamily.READ, "CUS-1", true);

        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "DOC-2", false)).isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "CUS-1", true)).isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "CUS-2", true)).isFalse();
    }

    /** RC-04: a sensitive request is answered only by an anchor that names the sensitive resource it decided. */
    @Test
    void anAnchorThatNamesNoResourceAnswersNoSensitiveRequest() {
        AgentAllowReuse reuse = new AgentAllowReuse(10, 3, 1, null);
        reuse.decided(KEY, "context-1", ActionFamily.READ, null, true);
        reuse.decided(KEY, "context-1", ActionFamily.READ, null, false);

        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "CUS-1", true)).isFalse();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "DOC-1", false)).isTrue();
    }

    /** The request limit, the operation and the context bind both anchors alike. */
    @Test
    void bothAnchorsAreBoundToTheirOperationContextAndRequestLimit() {
        AgentAllowReuse reuse = new AgentAllowReuse(3, 3, 1, null);
        reuse.decided(KEY, "context-1", ActionFamily.READ, "CUS-1", true);

        assertThat(reuse.answers(KEY, "context-1", ActionFamily.EXPORT, "CUS-1", true)).as("another operation").isFalse();
        assertThat(reuse.answers(KEY, "context-2", ActionFamily.READ, "CUS-1", true)).as("another context").isFalse();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "CUS-1", true)).isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "DOC-2", false)).isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "CUS-1", true)).as("the fourth request").isFalse();
    }

    /**
     * RL-12: a request that joined the decision while it was being made asks the same question as the one that began
     * it, so the request limit does not count it; the resource limits and the binding to operation and context hold.
     */
    @Test
    void requestsThatJoinedTheSameDecisionAreAnsweredBeyondTheRequestLimitButNotBeyondTheResourceLimit() {
        AgentAllowReuse reuse = new AgentAllowReuse(3, 3, 1, null);
        reuse.decided(KEY, "context-1", ActionFamily.READ, "CUS-1", true);

        for (int joined = 0; joined < 50; joined++) {
            assertThat(reuse.answersJoined(KEY, "context-1", ActionFamily.READ, "CUS-1", true)).as("joined %d", joined)
                    .isTrue();
        }
        assertThat(reuse.answersJoined(KEY, "context-1", ActionFamily.READ, "CUS-2", true)).as("another record").isFalse();
        assertThat(reuse.answersJoined(KEY, "context-1", ActionFamily.EXPORT, "CUS-1", true)).as("another operation").isFalse();
        assertThat(reuse.answersJoined(KEY, "context-2", ActionFamily.READ, "CUS-1", true)).as("another context").isFalse();
        // The joined requests did not use up the limit of the requests that come later.
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "CUS-1", true)).isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "CUS-1", true)).isTrue();
        assertThat(reuse.answers(KEY, "context-1", ActionFamily.READ, "CUS-1", true)).as("the third later request").isFalse();
    }

    @Test
    void joinedGeneralRequestsKeepTheGeneralResourceLimitAndASensitiveAnchorAnswersThemToo() {
        AgentAllowReuse reuse = new AgentAllowReuse(10, 3, 1, null);
        reuse.decided(KEY, "context-1", ActionFamily.READ, "DOC-1", false);

        assertThat(reuse.answersJoined(KEY, "context-1", ActionFamily.READ, "DOC-2", false)).isTrue();
        assertThat(reuse.answersJoined(KEY, "context-1", ActionFamily.READ, "DOC-3", false)).isTrue();
        assertThat(reuse.answersJoined(KEY, "context-1", ActionFamily.READ, "DOC-4", false)).as("a fourth resource").isFalse();
        // The ALLOW of a general resource still never answers a sensitive one, joined or not.
        assertThat(reuse.answersJoined(KEY, "context-1", ActionFamily.READ, "CUS-1", true)).isFalse();

        AgentAllowReuse sensitive = new AgentAllowReuse(10, 3, 1, null);
        sensitive.decided(KEY, "context-1", ActionFamily.READ, "CUS-1", true);
        assertThat(sensitive.answersJoined(KEY, "context-1", ActionFamily.READ, "DOC-9", false)).isTrue();
    }

    @Test
    void anAnchorThatNamesNoResourceAnswersNoJoinedSensitiveRequest() {
        AgentAllowReuse reuse = new AgentAllowReuse(10, 3, 1, null);
        reuse.decided(KEY, "context-1", ActionFamily.READ, null, true);

        assertThat(reuse.answersJoined(KEY, "context-1", ActionFamily.READ, "CUS-1", true)).isFalse();
        assertThat(reuse.answersJoined("nobody", "context-1", ActionFamily.READ, "CUS-1", true)).isFalse();
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

    /** RL-14: the importance the method declares is read first, and a host value can raise it but not lower it. */
    @Test
    void theDeclaredImportanceDecidesBeforeTheWordsDo() {
        assertThat(AgentAllowReuse.sensitive(Map.of("resourceImportance", "SENSITIVE"))).isTrue();
        assertThat(AgentAllowReuse.sensitive(Map.of("resourceImportance", "SENSITIVE", "resourceSensitivity", "PUBLIC")))
                .as("the host cannot lower a declared sensitive resource").isTrue();
        assertThat(AgentAllowReuse.sensitive(Map.of("resourceImportance", "NON_SENSITIVE"))).isFalse();
        assertThat(AgentAllowReuse.sensitive(Map.of("resourceImportance", "NON_SENSITIVE",
                "resourceSensitivity", "RESTRICTED"))).as("the host can raise it for one request").isTrue();
        assertThat(AgentAllowReuse.sensitive(Map.of("resourceImportance", "NON_SENSITIVE",
                "resourceSensitivity", "INTERNAL"))).isFalse();
    }
}
