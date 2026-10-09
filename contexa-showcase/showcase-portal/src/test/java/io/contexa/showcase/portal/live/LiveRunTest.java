package io.contexa.showcase.portal.live;

import io.contexa.showcase.portal.orchestrator.Approver;
import io.contexa.showcase.portal.orchestrator.ChallengeActions;
import io.contexa.showcase.portal.orchestrator.ChallengeResponder.Release;
import io.contexa.showcase.portal.orchestrator.ChallengeResponder.Challenge;
import io.contexa.showcase.portal.orchestrator.ControlSession.ChallengeTrace;
import io.contexa.showcase.portal.orchestrator.ControlSession.ReleaseTrace;
import io.contexa.showcase.portal.orchestrator.ReleaseActions;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Deck p.12 and p.20 on the live run: the visitor answers the check, cancels, gives up, lets it expire or fails to
 * recover.
 */
class LiveRunTest {

    private static final Instant START = Instant.parse("2026-10-05T06:00:00Z");

    private final MovableClock clock = new MovableClock(START);
    private final FakeActions actions = new FakeActions();
    private final LiveRun run = new LiveRun("live-1", "visitor-1", "K2", clock);

    @Test
    void theVisitorEntersTheInboxCodeAfterAWrongOneAndTheRequestResumes() throws Exception {
        CompletableFuture<ChallengeTrace> answer = respond();
        await(view -> view.stage() == LiveRun.Stage.WAITING);
        assertThat(run.view().status()).isEqualTo(LiveRun.Status.CHALLENGE);

        run.requestCode();
        LiveRun.ChallengeView shown = await(view -> view.stage() == LiveRun.Stage.CODE_SHOWN);
        assertThat(shown.code()).isEqualTo("481516");
        assertThat(shown.secondsLeft()).isEqualTo(120);

        run.answer("000000");
        LiveRun.ChallengeView wrong = await(view -> view.attempts() == 1);
        assertThat(wrong.error()).isEqualTo("WRONG_CODE");
        assertThat(wrong.code()).isEqualTo("481516");

        run.answer(" 481516 ");
        ChallengeTrace trace = answer.get(5, TimeUnit.SECONDS);
        assertThat(trace.answered()).isTrue();
        assertThat(trace.reissue().httpStatus()).isEqualTo(200);
        assertThat(actions.submitted).containsExactly("000000", "481516");
        LiveRun.ChallengeView done = run.view().challenge();
        assertThat(done.stage()).isEqualTo(LiveRun.Stage.DONE);
        assertThat(done.code()).isNull();
        assertThat(done.reissueStatus()).isEqualTo(200);
        assertThat(done.reissueSentMs()).isEqualTo(3000);
        assertThat(done.reissueDoneMs()).as("sent 3 s after the check, served in 30 ms").isEqualTo(3030);
        assertThat(done.reissueOutcome()).isEqualTo("DELIVERED");
        assertThat(done.reissueDeliveredItems()).isEqualTo(1);
    }

    @Test
    void aCancelledCheckKeepsTheRequestOnHoldUntilItsTimeRunsOut() throws Exception {
        CompletableFuture<ChallengeTrace> answer = respond();
        await(view -> view.stage() == LiveRun.Stage.WAITING);
        run.cancel();
        await(view -> view.stage() == LiveRun.Stage.CANCELLED);
        run.requestCode();
        await(view -> view.stage() == LiveRun.Stage.CODE_SHOWN);
        run.cancel();
        LiveRun.ChallengeView cancelled = await(view -> view.stage() == LiveRun.Stage.CANCELLED);
        assertThat(cancelled.code()).as("the code leaves the screen with the cancel").isNull();

        clock.move(Duration.ofSeconds(121));
        run.answer("too-late");
        ChallengeTrace trace = answer.get(5, TimeUnit.SECONDS);

        assertThat(trace.answered()).isFalse();
        assertThat(trace.reason()).isEqualTo("CANCELLED");
        assertThat(run.view().challenge().stage()).isEqualTo(LiveRun.Stage.EXPIRED);
        assertThat(actions.submitted).isEmpty();
    }

    @Test
    void anAbandonedCheckEndsAtOnceAndTheRequestStaysHeld() throws Exception {
        CompletableFuture<ChallengeTrace> answer = respond();
        await(view -> view.stage() == LiveRun.Stage.WAITING);
        run.abandon();

        ChallengeTrace trace = answer.get(5, TimeUnit.SECONDS);
        assertThat(trace.answered()).isFalse();
        assertThat(trace.reason()).isEqualTo("ABANDONED");
        assertThat(trace.reissue()).as("nothing is sent again").isNull();
        assertThat(run.view().challenge().stage()).isEqualTo(LiveRun.Stage.ABANDONED);
        assertThat(run.view().challenge().secondsLeft()).isZero();
        assertThat(actions.submitted).isEmpty();
    }

    @Test
    void threeWrongCodesEndTheCheckAsAFailedRecovery() throws Exception {
        CompletableFuture<ChallengeTrace> answer = respond();
        await(view -> view.stage() == LiveRun.Stage.WAITING);
        run.requestCode();
        await(view -> view.stage() == LiveRun.Stage.CODE_SHOWN);
        run.answer("1");
        run.answer("2");
        run.answer("3");

        ChallengeTrace trace = answer.get(5, TimeUnit.SECONDS);
        assertThat(trace.reason()).isEqualTo("WRONG_CODE_LIMIT");
        assertThat(run.view().challenge().stage()).isEqualTo(LiveRun.Stage.FAILED);
        assertThat(run.view().challenge().cause()).isEqualTo("WRONG_CODE_LIMIT");
    }

    @Test
    void aReissuedRequestThatIsNotServedIsAFailedRecoveryWithItsCause() throws Exception {
        actions.reissueStatus = 403;
        CompletableFuture<ChallengeTrace> answer = respond();
        await(view -> view.stage() == LiveRun.Stage.WAITING);
        run.requestCode();
        await(view -> view.stage() == LiveRun.Stage.CODE_SHOWN);
        run.answer("481516");

        ChallengeTrace trace = answer.get(5, TimeUnit.SECONDS);
        assertThat(trace.answered()).isTrue();
        assertThat(run.view().challenge().stage()).isEqualTo(LiveRun.Stage.FAILED);
        assertThat(run.view().challenge().cause()).isEqualTo("reissue 403 REFUSED");
    }

    @Test
    void theRunWaitsForTheVisitorToSendTheNextStepAndSendsItOnThePress() throws Exception {
        CompletableFuture<Boolean> next = CompletableFuture.supplyAsync(() -> run.awaitVisitor(2));
        awaitStatus(LiveRun.Status.AWAITING);
        assertThat(run.active()).as("the space stays the visitor's while it waits").isTrue();
        assertThat(run.view().awaitingStep()).isEqualTo(2);

        run.proceed();
        assertThat(next.get(5, TimeUnit.SECONDS)).isTrue();
        assertThat(run.view().status()).isEqualTo(LiveRun.Status.RUNNING);
        assertThat(run.view().awaitingStep()).isNull();
    }

    @Test
    void aVisitorWhoMovesOnEndsTheRunWithoutTheStepAndIsNotWaitedForAgain() throws Exception {
        CompletableFuture<Boolean> abandoned = CompletableFuture.supplyAsync(() -> run.awaitVisitor(2));
        awaitStatus(LiveRun.Status.AWAITING);
        run.abandon();
        assertThat(abandoned.get(5, TimeUnit.SECONDS)).isFalse();
        assertThat(CompletableFuture.supplyAsync(() -> run.awaitVisitor(3)).get(5, TimeUnit.SECONDS)).isFalse();
        assertThat(run.view().status()).isEqualTo(LiveRun.Status.RUNNING);
    }

    @Test
    void aVisitorWhoLetsTheTimeRunOutEndsTheRunWithoutTheStep() throws Exception {
        CompletableFuture<Boolean> expired = CompletableFuture.supplyAsync(() -> run.awaitVisitor(2));
        awaitStatus(LiveRun.Status.AWAITING);
        clock.move(Duration.ofSeconds(121));
        run.cancel();
        assertThat(expired.get(5, TimeUnit.SECONDS)).isFalse();
        assertThat(run.view().status()).isEqualTo(LiveRun.Status.RUNNING);
    }

    @Test
    void aVisitorWhoGaveUpTheCheckIsNotWaitedForAgain() throws Exception {
        CompletableFuture<ChallengeTrace> answer = respond();
        await(view -> view.stage() == LiveRun.Stage.WAITING);
        run.abandon();
        assertThat(answer.get(5, TimeUnit.SECONDS).reason()).isEqualTo("ABANDONED");

        assertThat(CompletableFuture.supplyAsync(() -> run.awaitVisitor(2)).get(5, TimeUnit.SECONDS))
                .as("the attacker who moved on does not hold the run for the second try").isFalse();
        assertThat(run.view().status()).isEqualTo(LiveRun.Status.RUNNING);
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

    @Test
    void anAttackerAskingForTheCodeHasItSentToTheEmployeeAndNeverSeesIt() throws Exception {
        CompletableFuture<ChallengeTrace> answer = CompletableFuture.supplyAsync(
                () -> run.respond(new Challenge("THREAT", START, actions)));
        await(view -> view.stage() == LiveRun.Stage.WAITING);
        run.requestCode();

        ChallengeTrace trace = answer.get(5, TimeUnit.SECONDS);
        assertThat(trace.reason()).isEqualTo("NO_MAILBOX");
        assertThat(run.view().challenge().stage()).isEqualTo(LiveRun.Stage.NO_MAILBOX);
        assertThat(run.view().challenge().code()).isNull();
        assertThat(actions.submitted).isEmpty();
    }

    @Test
    void theRealEmployeePassesTheCheckFilesTheRequestAndTheApprovalBringsTheWorkBack() throws Exception {
        FakeRelease release = new FakeRelease();
        release.reissueStatuses.add(403);
        release.reissueStatuses.add(200);
        CompletableFuture<ReleaseTrace> trace = release("NORMAL", release);
        awaitRelease(view -> view.stage() == LiveRun.ReleaseStage.BLOCKED);
        assertThat(run.view().status()).isEqualTo(LiveRun.Status.BLOCKED);
        assertThat(run.active()).isTrue();

        run.startRelease();
        LiveRun.ReleaseView shown = awaitRelease(view -> view.stage() == LiveRun.ReleaseStage.CODE_SHOWN);
        assertThat(shown.code()).isEqualTo("271828");
        assertThat(release.calls).containsExactly("startCheck", "requestCode");

        run.answer("000000");
        awaitRelease(view -> view.attempts() == 1);
        run.answer("271828");
        awaitRelease(view -> view.stage() == LiveRun.ReleaseStage.VERIFIED);
        run.requestRelease("   ");
        run.requestRelease("Approved GB-500 transfer, approver pm-11");
        LiveRun.ReleaseView filed = awaitRelease(view -> view.stage() == LiveRun.ReleaseStage.REQUESTED);
        assertThat(filed.reason()).isEqualTo("Approved GB-500 transfer, approver pm-11");
        assertThat(filed.block().reasoning()).isEqualTo("engine reasoning");
        assertThat(filed.block().username()).as("the account as the engine recorded it").isEqualTo("run-principal");
        assertThat(filed.approverName()).as("the approver's name from the employee record").isEqualTo(
                "Administrator B");
        assertThat(release.filedReasons).as("an empty reason is not filed").containsExactly(
                "Approved GB-500 transfer, approver pm-11");

        run.approve();
        ReleaseTrace done = trace.get(10, TimeUnit.SECONDS);
        assertThat(done.released()).isTrue();
        assertThat(release.approved).containsExactly(41L);
        assertThat(release.approvalReasons).singleElement().asString()
                .as("built from the run's records, not a fixed sentence (survey P2)")
                .startsWith("Approved the release request filed at ")
                .contains("after the identity check passed at ")
                .endsWith("requester's reason: Approved GB-500 transfer, approver pm-11")
                .doesNotContain("null");
        assertThat(release.calls).as("the block holds for a moment after the approval, so the request goes again")
                .containsSubsequence("reissue", "reissue");
        LiveRun.ReleaseView view = run.view().release();
        assertThat(view.stage()).isEqualTo(LiveRun.ReleaseStage.DONE);
        assertThat(view.reissueStatus()).isEqualTo(200);
        assertThat(view.reissueDeliveredItems()).isEqualTo(1);
        assertThat(run.view().status()).isEqualTo(LiveRun.Status.RUNNING);
    }

    @Test
    void anAttackerAskingForTheReleaseHasTheCodeSentToTheEmployeeAndStops() throws Exception {
        FakeRelease release = new FakeRelease();
        CompletableFuture<ReleaseTrace> trace = release("THREAT", release);
        awaitRelease(view -> view.stage() == LiveRun.ReleaseStage.BLOCKED);
        run.startRelease();

        ReleaseTrace stopped = trace.get(5, TimeUnit.SECONDS);
        assertThat(stopped.released()).isFalse();
        assertThat(stopped.reason()).isEqualTo("NO_MAILBOX");
        assertThat(release.calls).as("the code really goes out").containsExactly("startCheck", "requestCode");
        assertThat(run.view().release().code()).isNull();
        assertThat(release.approved).isEmpty();
        assertThat(CompletableFuture.supplyAsync(() -> run.awaitVisitor(2)).get(5, TimeUnit.SECONDS))
                .as("the attacker is not waited for again").isFalse();
    }

    @Test
    void aVisitorWhoMovesOnLeavesTheBlockInPlace() throws Exception {
        FakeRelease release = new FakeRelease();
        CompletableFuture<ReleaseTrace> trace = release("NORMAL", release);
        awaitRelease(view -> view.stage() == LiveRun.ReleaseStage.BLOCKED);
        run.abandon();

        assertThat(trace.get(5, TimeUnit.SECONDS).reason()).isEqualTo("ABANDONED");
        assertThat(release.calls).isEmpty();
        assertThat(run.view().release().stage()).isEqualTo(LiveRun.ReleaseStage.ABANDONED);
    }

    private CompletableFuture<ReleaseTrace> release(String classification, FakeRelease release) {
        return CompletableFuture.supplyAsync(
                () -> run.release(new Release(classification, START, "v0123456789ab-adm-a", release, release)));
    }

    private LiveRun.ReleaseView awaitRelease(Predicate<LiveRun.ReleaseView> condition) throws InterruptedException {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < until) {
            LiveRun.ReleaseView view = run.view().release();
            if (view != null && condition.test(view)) {
                return view;
            }
            Thread.sleep(10);
        }
        throw new AssertionError("release condition not reached: " + run.view());
    }

    /** The blocked principal's own actions and the run's approver, as the engine would answer them. */
    private static final class FakeRelease implements ReleaseActions, Approver {

        private final List<String> calls = new ArrayList<>();
        private final List<String> filedReasons = new ArrayList<>();
        private final List<Long> approved = new ArrayList<>();
        private final List<String> approvalReasons = new ArrayList<>();
        private final List<Integer> reissueStatuses = new ArrayList<>();

        @Override
        public int startCheck() {
            calls.add("startCheck");
            return 200;
        }

        @Override
        public int requestCode() {
            calls.add("requestCode");
            return 200;
        }

        @Override
        public Optional<String> readCode() {
            return Optional.of("271828");
        }

        @Override
        public int submitCode(String code) {
            return "271828".equals(code) ? 200 : 401;
        }

        @Override
        public int requestRelease(String reason) {
            filedReasons.add(reason);
            return 200;
        }

        @Override
        public StepOutcome reissue() {
            calls.add("reissue");
            int status = reissueStatuses.isEmpty() ? 200 : reissueStatuses.remove(0);
            return new StepOutcome("reissue", "GET", "/api/documents/x", START, status,
                    status == 200 ? "DELIVERED" : "REFUSED", status == 200 ? 1 : 0, null, null, null, 30,
                    START.plusSeconds(9), null);
        }

        @Override
        public Optional<BlockRecord> request(String username) {
            return Optional.of(new BlockRecord(41L, "run-principal", "UNBLOCK_REQUESTED", "engine reasoning",
                    "2026-10-06T03:17:00", filedReasons.isEmpty() ? null : filedReasons.get(0), true,
                    "2026-10-06T03:18:00"));
        }

        @Override
        public String displayName() {
            return "Administrator B";
        }

        @Override
        public int approve(long blockId, String reason) {
            approved.add(blockId);
            approvalReasons.add(reason);
            return 200;
        }
    }

    private CompletableFuture<ChallengeTrace> respond() {
        return CompletableFuture.supplyAsync(() -> run.respond(new Challenge("NORMAL", START, actions)));
    }

    private LiveRun.ChallengeView await(Predicate<LiveRun.ChallengeView> condition) throws InterruptedException {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < until) {
            LiveRun.ChallengeView view = run.view().challenge();
            if (view != null && condition.test(view)) {
                return view;
            }
            Thread.sleep(10);
        }
        throw new AssertionError("condition not reached: " + run.view());
    }

    private static final class FakeActions implements ChallengeActions {

        private final List<String> submitted = new ArrayList<>();
        private int reissueStatus = 200;

        @Override
        public int requestCode() {
            return 200;
        }

        @Override
        public Optional<String> readCode() {
            return Optional.of("481516");
        }

        @Override
        public int submitCode(String code) {
            submitted.add(code);
            return "481516".equals(code) ? 200 : 401;
        }

        @Override
        public StepOutcome reissue() {
            return new StepOutcome("reissue", "GET", "/api/documents/x", START, reissueStatus,
                    reissueStatus == 200 ? "DELIVERED" : "REFUSED", reissueStatus == 200 ? 1 : 0, null, null, null,
                    30, START.plusSeconds(3), null);
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
