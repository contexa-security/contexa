package io.contexa.showcase.portal.orchestrator;

import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent Agent중심-화면 S3 finding: how long a step's decision record is waited for. A request control D refused for its
 * delegating person to confirm gets no decision record of its own, whatever the kind of its operation: an export (a
 * synchronous one) used to wait the whole 150 seconds for a record that never comes, so the visitor saw the confirmation
 * minutes late. Every other step keeps the wait it had.
 */
class DecisionWaitTest {

    private static final Duration FULL = Duration.ofSeconds(150);

    private static StepOutcome outcome(String outcome, Integer status, String rule) {
        return new StepOutcome("req", "GET", "/api/x", Instant.EPOCH, status, outcome, 0, rule, null, null, 0, Instant.EPOCH,
                null);
    }

    @Test
    void aRequestRefusedForItsConfirmationIsWatchedBrieflyWhateverItsOperation() {
        StepOutcome asked = outcome("REFUSED", 403, ControlSession.AGENT_CONFIRMATION_REQUIRED);

        for (BusinessOperation operation : BusinessOperation.values()) {
            assertThat(RunOrchestrator.decisionWait(EngineDecision.synchronous(operation), asked, FULL))
                    .as(operation.name()).isEqualTo(RunOrchestrator.REFUSED_DECISION_WAIT);
        }
    }

    @Test
    void aRequestRefusedForARevokedDelegationIsWatchedBrieflyToo() {
        // the engine's gate refuses it before any analysis, so no decision record of its own comes (S3 real server)
        StepOutcome revoked = outcome("REFUSED", 403, "DELEGATION_REVOKED");

        for (BusinessOperation operation : BusinessOperation.values()) {
            assertThat(RunOrchestrator.decisionWait(EngineDecision.synchronous(operation), revoked, FULL))
                    .as(operation.name()).isEqualTo(RunOrchestrator.REFUSED_DECISION_WAIT);
        }
    }

    @Test
    void anAsynchronousRefusalIsWatchedBrieflyAsBefore() {
        assertThat(RunOrchestrator.decisionWait(false, outcome("REFUSED", 403, "ZERO_TRUST_BLOCK"), FULL))
                .isEqualTo(RunOrchestrator.REFUSED_DECISION_WAIT);
    }

    @Test
    void aSynchronousRefusalOtherThanTheConfirmationKeepsTheFullWait() {
        // the engine decides a synchronous request before its answer: the record is there, or it is worth waiting for
        assertThat(RunOrchestrator.decisionWait(true, outcome("REFUSED", 403, "ZERO_TRUST_BLOCK"), FULL)).isEqualTo(FULL);
        assertThat(RunOrchestrator.decisionWait(true, outcome("REFUSED", 401, "ZERO_TRUST_CHALLENGE"), FULL)).isEqualTo(FULL);
    }

    @Test
    void aStepThatWasDeliveredKeepsTheFullWait() {
        assertThat(RunOrchestrator.decisionWait(true, outcome("DELIVERED", 200, null), FULL)).isEqualTo(FULL);
        assertThat(RunOrchestrator.decisionWait(false, outcome("DELIVERED", 200, null), FULL)).isEqualTo(FULL);
    }

    @Test
    void aConfirmationRuleWithoutTheForbiddenStatusIsNotTakenForTheConfirmation() {
        // the confirmation is the 403 of its rule; the same rule on another status is some other answer
        assertThat(RunOrchestrator.decisionWait(true, outcome("REFUSED", 429, ControlSession.AGENT_CONFIRMATION_REQUIRED), FULL))
                .isEqualTo(FULL);
    }
}
