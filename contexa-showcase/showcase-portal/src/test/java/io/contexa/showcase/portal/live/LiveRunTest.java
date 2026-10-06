package io.contexa.showcase.portal.live;

import io.contexa.showcase.portal.orchestrator.ChallengeActions;
import io.contexa.showcase.portal.orchestrator.ChallengeResponder.Challenge;
import io.contexa.showcase.portal.orchestrator.ControlSession.ChallengeTrace;
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
