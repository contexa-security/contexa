package io.contexa.showcase.portal.live;

import io.contexa.showcase.portal.orchestrator.AgentConfirmationActions;
import io.contexa.showcase.portal.orchestrator.ChallengeResponder;
import io.contexa.showcase.portal.orchestrator.ChallengeResponder.AgentConfirmation;
import io.contexa.showcase.portal.orchestrator.ControlSession.AgentConfirmationStatus;
import io.contexa.showcase.portal.orchestrator.ControlSession.AgentConfirmationTrace;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;
import io.contexa.showcase.portal.orchestrator.DelegatorAnswer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent A7-3: control D asked the delegating employee to confirm the agent's request; the visitor answers as the
 * employee, and the agent sends the request again with the confirmation, which the engine serves once.
 */
class LiveRunAgentConfirmationTest {

    private static final Instant START = Instant.parse("2026-10-24T05:00:00Z");

    private final MovableClock clock = new MovableClock(START);
    private final FakeActions actions = new FakeActions();
    private final LiveRun run = new LiveRun("live-1", "visitor-1", "T5", clock);

    @Test
    void theVisitorApprovesAndTheAgentSendsTheRequestAgainWhichTheEngineServesOnce() throws Exception {
        CompletableFuture<AgentConfirmationTrace> answer = confirm(START.plusSeconds(600).toString());
        awaitStatus(LiveRun.Status.CONFIRMING);
        LiveRun.AgentConfirmationView asked = run.view().agentConfirmation();
        assertThat(asked.stage()).isEqualTo(LiveRun.ConfirmationStage.ASKED);
        assertThat(asked.confirmationId()).isEqualTo("cfm-1");
        assertThat(asked.trigger()).isEqualTo("DELEGATION_ENDED");
        assertThat(asked.secondsLeft()).isEqualTo(240);
        assertThat(run.active()).isTrue();

        run.decideAgentConfirmation(true);
        AgentConfirmationTrace trace = answer.get(5, TimeUnit.SECONDS);

        assertThat(trace.decision()).isEqualTo("APPROVE");
        assertThat(trace.reason()).isNull();
        assertThat(actions.calls).containsExactly("decide:APPROVE", "status", "other", "resend", "resend");
        LiveRun.AgentConfirmationView done = run.view().agentConfirmation();
        assertThat(done.stage()).isEqualTo(LiveRun.ConfirmationStage.DONE);
        assertThat(done.statusAfter()).isEqualTo("APPROVED");
        assertThat(done.authorizationId()).isEqualTo("authz-7");
        assertThat(done.resendStatus()).isEqualTo(200);
        assertThat(done.resendDeliveredItems()).isEqualTo(12);
        assertThat(done.reuseStatus()).isEqualTo(403);
        assertThat(done.otherStatus()).isEqualTo(403);
        assertThat(run.view().status()).isEqualTo(LiveRun.Status.RUNNING);
    }

    @Test
    void aRejectionSendsTheRequestAgainOnlyToShowTheEngineRefusesIt() throws Exception {
        CompletableFuture<AgentConfirmationTrace> answer = confirm(START.plusSeconds(600).toString());
        awaitStatus(LiveRun.Status.CONFIRMING);

        run.decideAgentConfirmation(false);
        AgentConfirmationTrace trace = answer.get(5, TimeUnit.SECONDS);

        assertThat(trace.decision()).isEqualTo("REJECT");
        assertThat(actions.calls).containsExactly("decide:REJECT", "status", "resend");
        assertThat(trace.reuse()).isNull();
        assertThat(trace.other()).isNull();
    }

    @Test
    void aVisitorWhoMovesOnLeavesTheConfirmationUnansweredAndIsNotWaitedForAgain() throws Exception {
        CompletableFuture<AgentConfirmationTrace> answer = confirm(START.plusSeconds(600).toString());
        awaitStatus(LiveRun.Status.CONFIRMING);

        run.abandon();

        assertThat(answer.get(5, TimeUnit.SECONDS).reason()).isEqualTo("ABANDONED");
        assertThat(actions.calls).isEmpty();
        assertThat(run.view().agentConfirmation().stage()).isEqualTo(LiveRun.ConfirmationStage.ABANDONED);
        assertThat(confirm(START.plusSeconds(600).toString()).get(5, TimeUnit.SECONDS).reason())
                .isEqualTo("ABANDONED");
    }

    @Test
    void theWaitEndsWhenTheEnginesConfirmationExpiresBeforeTheVisitorsTime() throws Exception {
        CompletableFuture<AgentConfirmationTrace> answer = confirm(START.plusSeconds(60).toString());
        awaitStatus(LiveRun.Status.CONFIRMING);
        assertThat(run.view().agentConfirmation().secondsLeft()).isEqualTo(60);

        clock.move(Duration.ofSeconds(61));
        run.cancel();

        assertThat(answer.get(5, TimeUnit.SECONDS).reason()).isEqualTo("EXPIRED");
        assertThat(actions.calls).isEmpty();
    }

    @Test
    void recordingsLeaveAConfirmationUnansweredUnlessTheRunDecides() throws Exception {
        AgentConfirmation asked = asked(START.plusSeconds(600).toString());

        assertThat(ChallengeResponder.AUTOMATIC.confirmAgent(asked).reason()).isEqualTo("NOT_ASKED");
        assertThat(actions.calls).isEmpty();
        assertThat(ChallengeResponder.deciding(DelegatorAnswer.APPROVE, 0).confirmAgent(asked).decision()).isEqualTo("APPROVE");
        assertThat(actions.calls).containsExactly("decide:APPROVE", "status", "other", "resend", "resend");
    }

    @Test
    void aFailedStepAfterTheAnswerIsRecordedWithItsCause() {
        actions.failDecide = true;

        AgentConfirmationTrace trace = ChallengeResponder.answer(asked(START.plusSeconds(600).toString()), true);

        assertThat(trace.decision()).isEqualTo("APPROVE");
        assertThat(trace.reason()).startsWith("IOException: ");
        assertThat(trace.resend()).isNull();
    }

    private CompletableFuture<AgentConfirmationTrace> confirm(String expiresAt) {
        return CompletableFuture.supplyAsync(() -> run.confirmAgent(asked(expiresAt)));
    }

    private AgentConfirmation asked(String expiresAt) {
        return new AgentConfirmation("THREAT", 1, "cfm-1", "DELEGATION_ENDED", expiresAt, START, "GET",
                "/api/projects/HX-310/documents?type=DRAWING", actions);
    }

    private void awaitStatus(LiveRun.Status status) throws InterruptedException {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < until) {
            if (run.view().status() == status) {
                return;
            }
            Thread.sleep(10);
        }
        throw new AssertionError("status not reached: " + run.view());
    }

    private static StepOutcome outcome(int status, String outcome, int items, String rule) {
        return new StepOutcome("req-" + status, "GET", "/api/projects/HX-310/documents?type=DRAWING", START, status,
                outcome, items, rule, null, null, 40, START, null);
    }

    private static final class FakeActions implements AgentConfirmationActions {

        private final List<String> calls = Collections.synchronizedList(new ArrayList<>());
        private boolean failDecide;
        private int resends;

        @Override
        public int decide(DelegatorAnswer answer) throws IOException {
            if (failDecide) {
                throw new IOException("connection reset");
            }
            calls.add("decide:" + answer);
            return 302;
        }

        @Override
        public AgentConfirmationStatus status() {
            calls.add("status");
            return new AgentConfirmationStatus(200, "APPROVED", "authz-7", START.plusSeconds(600).toString(),
                    START.plusSeconds(30).toString(), "DELEGATION_ENDED", "GET",
                    "/api/projects/HX-310/documents?type=DRAWING");
        }

        @Override
        public StepOutcome resend() {
            calls.add("resend");
            resends++;
            return resends == 1 ? outcome(200, "DELIVERED", 12, null)
                    : outcome(403, "REFUSED", 0, "AGENT_CONFIRMATION_USED");
        }

        @Override
        public StepOutcome resendOther() {
            calls.add("other");
            return outcome(403, "REFUSED", 0, "AGENT_CONFIRMATION_REQUIRED");
        }

        @Override
        public StepOutcome retry() {
            calls.add("retry");
            return outcome(403, "REFUSED", 0, "AGENT_CONFIRMATION_REQUIRED");
        }

        @Override
        public StepOutcome personRequest() {
            calls.add("person");
            return outcome(200, "DELIVERED", 12, null);
        }
    }

    private static final class MovableClock extends Clock {

        private volatile Instant now;

        MovableClock(Instant now) {
            this.now = now;
        }

        void move(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
