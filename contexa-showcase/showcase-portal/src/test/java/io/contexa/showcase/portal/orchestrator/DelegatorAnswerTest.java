package io.contexa.showcase.portal.orchestrator;

import io.contexa.showcase.portal.orchestrator.ChallengeResponder.AgentConfirmation;
import io.contexa.showcase.portal.orchestrator.ControlSession.AgentConfirmationStatus;
import io.contexa.showcase.portal.orchestrator.ControlSession.AgentConfirmationTrace;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

/**
 * docs/agent DD-27: the operator's checks of a confirmation control D asked of an agent's request. An approval is
 * first offered for another request while still unused (A5-9 binding); a report stops the agent while the person's
 * own request goes on (A5-1, A5-3); an unanswered confirmation lets the agent run into the call limit, wait it out
 * and be let through to the gate again (A5-7).
 */
class DelegatorAnswerTest {

    private static final Instant AT = Instant.parse("2026-10-24T05:00:00Z");
    private static final String PATH = "/api/projects/HX-310/documents";

    private final FakeActions actions = new FakeActions();
    private final List<Long> waits = new ArrayList<>();
    private final AgentRetryStorm.Pause pause = waits::add;

    @Test
    void anApprovalIsOfferedForAnotherRequestBeforeTheApprovedRequestIsSentTwice() {
        AgentConfirmationTrace trace = ChallengeResponder.answer(asked(), DelegatorAnswer.APPROVE, 0, pause);

        assertThat(actions.calls).containsExactly("decide:APPROVE", "status", "other", "resend", "resend");
        assertThat(trace.decision()).isEqualTo("APPROVE");
        assertThat(trace.other().deliveredItems()).isZero();
        assertThat(trace.resend().deliveredItems()).isEqualTo(5);
        assertThat(trace.reuse().httpStatus()).isEqualTo(403);
        assertThat(trace.personRequest()).isNull();
        assertThat(trace.retries()).isNull();
    }

    @Test
    void aReportStopsTheAgentsRequestWhileThePersonsOwnSameRequestGoesOn() {
        actions.reported = true;

        AgentConfirmationTrace trace = ChallengeResponder.answer(asked(), DelegatorAnswer.REPORT, 0, pause);

        assertThat(actions.calls).containsExactly("decide:REPORT", "status", "resend", "person");
        assertThat(trace.decision()).isEqualTo("REPORT");
        assertThat(trace.after().status()).isEqualTo("REPORTED");
        assertThat(trace.resend().httpStatus()).isEqualTo(401);
        assertThat(trace.personRequest().deliveredItems()).isEqualTo(5);
        assertThat(trace.reuse()).isNull();
        assertThat(trace.other()).isNull();
    }

    @Test
    void anUnansweredConfirmationLetsTheAgentRunIntoTheCallLimitAndWaitItOut() {
        actions.limitFrom = 4;

        AgentConfirmationTrace trace = ChallengeResponder.answer(asked(), DelegatorAnswer.SILENT, 5, pause);

        assertThat(actions.calls).containsExactly("retry", "retry", "retry", "retry", "retry", "retry", "person");
        assertThat(trace.decision()).isEqualTo("SILENT");
        assertThat(trace.decideStatus()).isNull();
        ControlSession.RetryStorm storm = trace.retries();
        assertThat(storm.sent()).isEqualTo(5);
        assertThat(storm.outcomes()).containsExactly(entry("403 AGENT_CONFIRMATION_REQUIRED", 3),
                entry("429 AGENT_CALL_LIMIT", 2));
        assertThat(storm.firstLimitedAt()).isEqualTo(4);
        assertThat(storm.firstLimited().ruleId()).isEqualTo("AGENT_CALL_LIMIT");
        // The last limit answer asked for 40 seconds; the agent waits one more.
        assertThat(waits).containsExactly(41L);
        assertThat(storm.waitedSeconds()).isEqualTo(41L);
        assertThat(storm.afterWait().ruleId()).isEqualTo("AGENT_CONFIRMATION_REQUIRED");
        assertThat(trace.personRequest().deliveredItems()).isEqualTo(5);
    }

    @Test
    void withoutALimitAnswerTheAgentDoesNotWait() {
        AgentConfirmationTrace trace = ChallengeResponder.answer(asked(), DelegatorAnswer.SILENT, 3, pause);

        assertThat(actions.calls).containsExactly("retry", "retry", "retry", "person");
        assertThat(waits).isEmpty();
        assertThat(trace.retries().firstLimitedAt()).isNull();
        assertThat(trace.retries().waitedSeconds()).isNull();
        assertThat(trace.retries().afterWait()).isNull();
    }

    @Test
    void aLimitAnswerWithoutItsSecondsIsWaitedAMinute() {
        assertThat(AgentRetryStorm.retryAfterSeconds(outcome(429, "REFUSED", 0, "AGENT_CALL_LIMIT", null)))
                .isEqualTo(60);
        assertThat(AgentRetryStorm.retryAfterSeconds(outcome(429, "REFUSED", 0, "AGENT_CALL_LIMIT", "not json")))
                .isEqualTo(60);
        assertThat(AgentRetryStorm.retryAfterSeconds(outcome(429, "REFUSED", 0, "AGENT_CALL_LIMIT",
                "{\"details\":{\"retryAfterSeconds\":17}}"))).isEqualTo(17);
    }

    @Test
    void anInterruptedWaitIsRecordedAsTheCause() {
        actions.limitFrom = 1;
        AgentRetryStorm.Pause interrupted = seconds -> {
            throw new InterruptedException();
        };

        AgentConfirmationTrace trace = ChallengeResponder.answer(asked(), DelegatorAnswer.SILENT, 2, interrupted);

        assertThat(trace.reason()).isEqualTo("InterruptedException");
        assertThat(Thread.interrupted()).isTrue();
    }

    private AgentConfirmation asked() {
        return new AgentConfirmation("THREAT", 1, "cfm-1", "DELEGATION_ENDED", AT.plusSeconds(900).toString(), AT,
                "GET", PATH, actions);
    }

    private static StepOutcome outcome(int status, String outcome, int items, String rule, String excerpt) {
        return new StepOutcome("req-" + status, "GET", PATH, AT, status, outcome, items, rule, null, excerpt, 40, AT,
                null);
    }

    private static final class FakeActions implements AgentConfirmationActions {

        private final List<String> calls = new ArrayList<>();
        private boolean reported;
        private int limitFrom = Integer.MAX_VALUE;
        private int resends;
        private int retries;

        @Override
        public int decide(DelegatorAnswer answer) {
            calls.add("decide:" + answer);
            return 302;
        }

        @Override
        public AgentConfirmationStatus status() {
            calls.add("status");
            return new AgentConfirmationStatus(200, reported ? "REPORTED" : "APPROVED", "authz-7", null, null,
                    "DELEGATION_ENDED", "GET", PATH);
        }

        @Override
        public StepOutcome resend() {
            calls.add("resend");
            resends++;
            if (reported) {
                return outcome(401, "REFUSED", 0, null, null);
            }
            return resends == 1 ? outcome(200, "DELIVERED", 5, null, null)
                    : outcome(403, "REFUSED", 0, "AGENT_CONFIRMATION_REQUIRED", null);
        }

        @Override
        public StepOutcome resendOther() {
            calls.add("other");
            return outcome(403, "REFUSED", 0, "AGENT_CONFIRMATION_REQUIRED", null);
        }

        @Override
        public StepOutcome retry() {
            calls.add("retry");
            retries++;
            return retries >= limitFrom && retries <= 5
                    ? outcome(429, "REFUSED", 0, "AGENT_CALL_LIMIT",
                    "{\"error\":\"AGENT_CALL_LIMIT\",\"retryAfterSeconds\":" + (45 - retries) + "}")
                    : outcome(403, "REFUSED", 0, "AGENT_CONFIRMATION_REQUIRED", null);
        }

        @Override
        public StepOutcome personRequest() {
            calls.add("person");
            return outcome(200, "DELIVERED", 5, null, null);
        }
    }
}
