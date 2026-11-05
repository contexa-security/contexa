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
package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The context a user's decision was reached for, which a request is compared with to tell whether its session, address
 * or browser changed. Both stores answer alike for the same writes. Each test uses a user of its own, so the Redis store
 * runs beside other tests.
 */
abstract class AbstractZeroTrustActionRepositoryDecidedContextContractTest {

    private static final String HOME = "context-home";
    private static final String ELSEWHERE = "context-elsewhere";

    protected ZeroTrustActionRepository repository;
    protected String user;

    protected abstract ZeroTrustActionRepository createRepository();

    /** The user's analysis goes past its TTL; the last verified records stay. */
    protected abstract void theAnalysisLapses();

    /** The last verified records go past their 24 hours as well. */
    protected abstract void theLastVerifiedRecordsLapse();

    @BeforeEach
    void setUpRepository() {
        repository = createRepository();
        user = "decided-" + UUID.randomUUID();
    }

    private static Map<String, Object> decidedFor(String context) {
        return Map.of("observationId", "observation-1", "processingGeneration", "1", "contextBindingHash", context);
    }

    private void decided(ZeroTrustAction action, String context) {
        assertThat(repository.saveFinalAction(user, action, decidedFor(context))).isTrue();
    }

    @Test
    @DisplayName("a user without a decision has no context on record")
    void noDecisionNoContext() {
        assertThat(repository.decidedContext(user)).isNull();
    }

    @Test
    @DisplayName("no user has no context on record")
    void noUserNoContext() {
        assertThat(repository.decidedContext(null)).isNull();
        assertThat(repository.decidedContext(" ")).isNull();
    }

    @Test
    @DisplayName("the decision in its TTL names the context it was reached for")
    void theLiveDecisionNamesItsContext() {
        decided(ZeroTrustAction.ALLOW, HOME);

        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
    }

    @Test
    @DisplayName("past the decision's TTL the last verified context answers")
    void theLastVerifiedContextOutlivesTheDecision() {
        decided(ZeroTrustAction.ALLOW, HOME);

        theAnalysisLapses();

        assertThat(repository.getCurrentAction(user, HOME)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
    }

    @Test
    @DisplayName("past its 24 hours nothing is on record")
    void theRecordEndsWithItsTime() {
        decided(ZeroTrustAction.ALLOW, HOME);
        theAnalysisLapses();

        theLastVerifiedRecordsLapse();

        assertThat(repository.decidedContext(user)).isNull();
    }

    @Test
    @DisplayName("the latest decision replaces the context, in its TTL and after it")
    void theLatestDecisionNamesTheContext() {
        decided(ZeroTrustAction.ALLOW, HOME);

        decided(ZeroTrustAction.ALLOW, ELSEWHERE);

        assertThat(repository.decidedContext(user)).isEqualTo(ELSEWHERE);
        theAnalysisLapses();
        assertThat(repository.decidedContext(user)).isEqualTo(ELSEWHERE);
    }

    @Test
    @DisplayName("a decision a stricter one kept out names no context of its own")
    void aDecisionKeptOutChangesNothing() {
        decided(ZeroTrustAction.CHALLENGE, HOME);

        assertThat(repository.writeFinalAction(user, ZeroTrustAction.ALLOW, decidedFor(ELSEWHERE)))
                .isEqualTo(ZeroTrustActionRepository.FinalActionWrite.KEPT_STRICTER);

        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
    }

    @Test
    @DisplayName("an action saved without a context leaves none on record")
    void anActionWithoutAContextLeavesNone() {
        decided(ZeroTrustAction.ALLOW, HOME);

        repository.saveAction(user, ZeroTrustAction.ALLOW, Map.of());

        assertThat(repository.decidedContext(user)).isNull();
        theAnalysisLapses();
        assertThat(repository.decidedContext(user)).isNull();
    }

    @Test
    @DisplayName("an action saved with a context names it, in its TTL and after it")
    void anActionWithAContextNamesIt() {
        repository.saveAction(user, ZeroTrustAction.ALLOW, Map.of("contextBindingHash", HOME));

        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
        theAnalysisLapses();
        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
    }

    @Test
    @DisplayName("the session that answered a challenge is the context on record")
    void theAnswerOfAChallengeNamesItsSession() {
        decided(ZeroTrustAction.CHALLENGE, ELSEWHERE);

        repository.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, HOME);

        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
        theAnalysisLapses();
        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
    }

    @Test
    @DisplayName("a change of the action without a context keeps the analysis's context while it lasts, and no record after it")
    void aChangeWithoutAContextForgetsTheRecord() {
        decided(ZeroTrustAction.CHALLENGE, HOME);

        repository.saveActionWithPrevious(user, ZeroTrustAction.ALLOW);

        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
        theAnalysisLapses();
        assertThat(repository.decidedContext(user)).isNull();
    }

    @Test
    @DisplayName("an approved override keeps the analysis's context while it lasts, and no record after it")
    void anOverrideForgetsTheRecord() {
        decided(ZeroTrustAction.CHALLENGE, HOME);

        repository.approveOverrideAtomically(user, ZeroTrustAction.ALLOW);

        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
        theAnalysisLapses();
        assertThat(repository.decidedContext(user)).isNull();
    }

    @Test
    @DisplayName("a stored ESCALATE that ends keeps the context of its analysis")
    void anEndedEscalateKeepsItsContext() {
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);
        decided(ZeroTrustAction.ESCALATE, HOME);

        assertThat(repository.getCurrentAction(user, HOME)).isEqualTo(ZeroTrustAction.CHALLENGE);

        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
        theAnalysisLapses();
        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
    }

    @Test
    @DisplayName("an ESCALATE that ends after its analysis lapsed leaves no context")
    void anEscalateEndedAfterItsAnalysisLeavesNone() {
        decided(ZeroTrustAction.ESCALATE, HOME);
        theAnalysisLapses();
        repository.setEscalateTerminalAction(ZeroTrustAction.CHALLENGE);

        assertThat(repository.getCurrentAction(user, HOME)).isEqualTo(ZeroTrustAction.CHALLENGE);

        assertThat(repository.decidedContext(user)).isNull();
    }

    @Test
    @DisplayName("a logout takes the record with the user's other state")
    void aLogoutTakesTheRecord() {
        decided(ZeroTrustAction.ALLOW, HOME);

        repository.removeLogoutData(user);

        assertThat(repository.decidedContext(user)).isNull();
    }

    @Test
    @DisplayName("a logout under a restriction keeps it")
    void aLogoutUnderARestrictionKeepsTheRecord() {
        decided(ZeroTrustAction.CHALLENGE, HOME);

        repository.removeLogoutData(user);

        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
        theAnalysisLapses();
        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
    }

    @Test
    @DisplayName("the removal of the user's data takes it")
    void theRemovalOfTheUsersDataTakesIt() {
        decided(ZeroTrustAction.ALLOW, HOME);

        repository.removeAllUserData(user);

        assertThat(repository.decidedContext(user)).isNull();
    }

    @Test
    @DisplayName("the removal of the agents' data takes theirs and leaves the user's")
    void theRemovalOfTheAgentsDataLeavesTheUsers() {
        String agent = LearningSubject.agentKey(user, "agent-1");
        decided(ZeroTrustAction.ALLOW, HOME);
        assertThat(repository.saveFinalAction(agent, ZeroTrustAction.ALLOW, decidedFor(ELSEWHERE))).isTrue();
        theAnalysisLapses();
        assertThat(repository.decidedContext(agent)).isEqualTo(ELSEWHERE);

        repository.removeAllAgentData(user);

        assertThat(repository.decidedContext(agent)).isNull();
        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
    }

    @Test
    @DisplayName("every spelling of a name reads the one record")
    void everySpellingReadsTheOneRecord() {
        decided(ZeroTrustAction.ALLOW, HOME);

        assertThat(repository.decidedContext(user.toUpperCase(Locale.ROOT))).isEqualTo(HOME);
    }
}
