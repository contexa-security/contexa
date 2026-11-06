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
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.FinalActionWrite;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A CHALLENGE no analysis decided, for a person whose sign-ins passed the decisions allowed in a short window: it asks
 * every session of the person to verify, as a decided CHALLENGE does, and it never takes the place of a stricter
 * action nor of a CHALLENGE a model decided. Each test uses a user of its own, so the Redis store runs beside others.
 */
abstract class AbstractZeroTrustActionRepositoryUndecidedChallengeContractTest {

    private static final String HOME = "context-home";
    private static final String NEXT = "context-next-session";
    private static final String VICTIM = "context-victim";

    protected ZeroTrustActionRepository repository;
    protected String user;

    protected abstract ZeroTrustActionRepository createRepository();

    @BeforeEach
    void setUpRepository() {
        repository = createRepository();
        user = "undecided-" + UUID.randomUUID();
    }

    private static Map<String, Object> decision(String context, Object... more) {
        Map<String, Object> fields = new HashMap<>();
        fields.put("observationId", "observation-1");
        fields.put("processingGeneration", "1");
        fields.put("contextBindingHash", context);
        for (int i = 0; i < more.length; i += 2) {
            fields.put(more[i].toString(), more[i + 1]);
        }
        return fields;
    }

    private static Map<String, Object> undecided() {
        Map<String, Object> fields = new HashMap<>();
        fields.put("contextBindingHash", NEXT);
        fields.put("reasoning", "The sign-ins passed the decisions allowed in the window");
        fields.put(ZeroTrustActionRepository.LLM_DECISION_PRESENT, false);
        return fields;
    }

    @Test
    @DisplayName("a person without a decision is asked to verify in every session, the next one on record")
    void aPersonWithoutADecisionIsAskedToVerify() {
        assertThat(repository.writeUndecidedChallenge(user, undecided())).isEqualTo(FinalActionWrite.APPLIED);

        assertThat(repository.getCurrentAction(user, NEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction(user, HOME)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.decidedContext(user)).isEqualTo(NEXT);
        assertThat(repository.isTechnicalChallenge(user)).as("it is no short CHALLENGE that gives way").isFalse();
    }

    @Test
    @DisplayName("an ALLOW in force gives way to it")
    void anAllowGivesWay() {
        assertThat(repository.writeFinalAction(user, ZeroTrustAction.ALLOW, decision(HOME)))
                .isEqualTo(FinalActionWrite.APPLIED);

        assertThat(repository.writeUndecidedChallenge(user, undecided())).isEqualTo(FinalActionWrite.APPLIED);

        assertThat(repository.getCurrentAction(user, HOME)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("a model's later ALLOW does not lift it: only a verification or an administrator does")
    void aLaterAllowDoesNotLiftIt() {
        repository.writeUndecidedChallenge(user, undecided());

        assertThat(repository.writeFinalAction(user, ZeroTrustAction.ALLOW, decision(NEXT)))
                .isEqualTo(FinalActionWrite.KEPT_STRICTER);

        assertThat(repository.getCurrentAction(user, NEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("the session that verified goes on, and the others stay asked")
    void theSessionThatVerifiedGoesOn() {
        repository.writeUndecidedChallenge(user, undecided());

        repository.holdChallengeForOtherSessions(user, VICTIM);
        repository.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, VICTIM);

        assertThat(repository.getCurrentAction(user, VICTIM)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(repository.getCurrentAction(user, NEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(value = ZeroTrustAction.class, names = {"BLOCK", "ESCALATE"})
    @DisplayName("a stricter decision stays as it was")
    void aStricterDecisionStays(ZeroTrustAction stricter) {
        repository.writeFinalAction(user, stricter, decision(HOME, "requestId", "request-1"));

        assertThat(repository.writeUndecidedChallenge(user, undecided())).isEqualTo(FinalActionWrite.KEPT_STRICTER);

        assertThat(repository.getCurrentAction(user, NEXT)).isEqualTo(stricter);
        assertThat(repository.getAnalysisData(user).requestId()).isEqualTo("request-1");
    }

    @Test
    @DisplayName("a BLOCK kept by its flag alone stays")
    void aBlockFlagStays() {
        repository.setBlockedFlag(user);

        assertThat(repository.writeUndecidedChallenge(user, undecided())).isEqualTo(FinalActionWrite.KEPT_STRICTER);

        assertThat(repository.getCurrentAction(user, NEXT)).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("a CHALLENGE a model decided keeps the request and the context it was decided for")
    void aDecidedChallengeKeepsWhatItWasDecidedFor() {
        repository.writeFinalAction(user, ZeroTrustAction.CHALLENGE, decision(HOME, "requestId", "request-1"));

        assertThat(repository.writeUndecidedChallenge(user, undecided())).isEqualTo(FinalActionWrite.KEPT_STRICTER);

        assertThat(repository.getAnalysisData(user).requestId()).isEqualTo("request-1");
        assertThat(repository.decidedContext(user)).isEqualTo(HOME);
        assertThat(repository.getCurrentAction(user, NEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("a short CHALLENGE no model decided becomes one that lasts")
    void aShortChallengeBecomesOneThatLasts() {
        repository.writeFinalAction(user, ZeroTrustAction.CHALLENGE, decision(HOME,
                ZeroTrustActionRepository.TECHNICAL_CHALLENGE, true, ZeroTrustActionRepository.LLM_DECISION_PRESENT, false));
        assertThat(repository.isTechnicalChallenge(user)).isTrue();

        assertThat(repository.writeUndecidedChallenge(user, undecided())).isEqualTo(FinalActionWrite.APPLIED);

        assertThat(repository.isTechnicalChallenge(user)).isFalse();
        assertThat(repository.getCurrentAction(user, NEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("a CHALLENGE held for the sessions that did not answer one already asks a new session")
    void aHeldChallengeAlreadyAsks() {
        repository.writeFinalAction(user, ZeroTrustAction.CHALLENGE, decision(HOME));
        repository.holdChallengeForOtherSessions(user, VICTIM);
        repository.saveActionWithPrevious(user, ZeroTrustAction.ALLOW, VICTIM);

        assertThat(repository.writeUndecidedChallenge(user, undecided())).isEqualTo(FinalActionWrite.KEPT_STRICTER);

        assertThat(repository.getCurrentAction(user, NEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction(user, VICTIM)).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("without a user nothing is written")
    void withoutAUserNothingIsWritten() {
        assertThat(repository.writeUndecidedChallenge(" ", undecided())).isEqualTo(FinalActionWrite.FAILED);
    }
}
