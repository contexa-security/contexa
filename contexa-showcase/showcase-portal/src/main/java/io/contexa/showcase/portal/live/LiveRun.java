package io.contexa.showcase.portal.live;

import io.contexa.showcase.portal.orchestrator.ChallengeResponder;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;
import io.contexa.showcase.portal.orchestrator.ControlSession.ChallengeTrace;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;
import io.contexa.showcase.portal.orchestrator.RunListener;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.RunSummary;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * One scenario a visitor runs live (docs/showcase/P3-설계.md 3절). It hears every control's result as it arrives and,
 * when control D asks for an additional check, waits for the visitor: ask for the code, enter it from the demo inbox,
 * or cancel. Each wait ends after {@link #STAGE_TIMEOUT}; three wrong codes end the check as a failed recovery.
 */
public final class LiveRun implements ChallengeResponder, RunListener {

    static final Duration STAGE_TIMEOUT = Duration.ofSeconds(120);
    static final int MAX_ATTEMPTS = 3;

    public enum Status { QUEUED, STARTING, RUNNING, CHALLENGE, COMPLETED, FAILED, EXPIRED }

    /**
     * WAITING: the check was asked, nothing requested yet. CODE_SHOWN: the demo inbox holds a code. CANCELLED: the
     * visitor stepped back; the request stays on hold until the time runs out. The rest are final.
     */
    public enum Stage { WAITING, CODE_SHOWN, CANCELLED, VERIFYING, DONE, EXPIRED, FAILED }

    sealed interface Command permits RequestCode, Answer, Cancel {
    }

    record RequestCode() implements Command {
    }

    record Answer(String code) implements Command {
    }

    record Cancel() implements Command {
    }

    public record LayerView(String outcome, Integer httpStatus) {
    }

    public record StepView(int stepNo, String operation, Map<String, LayerView> layers) {
    }

    /**
     * @param code        the code in the demo inbox, shown only while the visitor can enter it
     * @param secondsLeft time left for the current wait
     * @param error       WRONG_CODE after a code that did not verify
     * @param cause       why the check could not complete, for "see the cause"
     */
    public record ChallengeView(Stage stage, String code, long secondsLeft, int attempts, String error, String cause,
                                Long codeRequestedMs, Long verifiedMs, Long reissueSentMs, Long reissueDoneMs,
                                Integer reissueStatus, String reissueOutcome) {
    }

    /**
     * @param queuePosition 1-based place in the queue while QUEUED, 0 otherwise
     */
    /**
     * @param readyMs     milliseconds from the request to the space being ready (principal cloned and signed in),
     *                    null until then (P4-BE-01)
     * @param readyStages milliseconds of each preparation stage of the space
     */
    public record View(String liveRunId, String scenario, Status status, int queuePosition, String runId,
                       Long readyMs, Map<String, Long> readyStages, List<StepView> steps, ChallengeView challenge,
                       String failure) {
    }

    private final String liveRunId;
    private final String visitor;
    private final String scenario;
    private final Clock clock;
    private final BlockingQueue<Command> commands = new LinkedBlockingQueue<>();
    private final Map<Integer, StepView> steps = new LinkedHashMap<>();
    private final Instant requestedAt;
    private Instant readyAt;
    private Map<String, Long> readyStages = Map.of();

    private Status status = Status.STARTING;
    private int queuePosition;
    private String runId;
    private String failure;
    private Stage stage;
    private String code;
    private Instant deadline;
    private int attempts;
    private String error;
    private String cause;
    private ChallengeTrace trace;

    public LiveRun(String liveRunId, String visitor, String scenario, Clock clock) {
        this.liveRunId = liveRunId;
        this.visitor = visitor;
        this.scenario = scenario;
        this.clock = clock;
        this.requestedAt = clock.instant();
    }

    public String visitor() {
        return visitor;
    }

    public String liveRunId() {
        return liveRunId;
    }

    public synchronized boolean active() {
        return status == Status.QUEUED || status == Status.STARTING || status == Status.RUNNING
                || status == Status.CHALLENGE;
    }

    public synchronized Status status() {
        return status;
    }

    synchronized void queued(int position) {
        status = Status.QUEUED;
        queuePosition = position;
    }

    synchronized void starting() {
        status = Status.STARTING;
        queuePosition = 0;
    }

    /** A queued run whose space was cleaned before its turn. */
    synchronized void expire() {
        status = Status.EXPIRED;
        queuePosition = 0;
    }

    public void requestCode() {
        commands.add(new RequestCode());
    }

    public void answer(String code) {
        commands.add(new Answer(code == null ? "" : code.trim()));
    }

    public void cancel() {
        commands.add(new Cancel());
    }

    @Override
    public String liveVisitor() {
        return visitor;
    }

    @Override
    public synchronized void principalReady(Map<String, Long> stageMs) {
        readyAt = clock.instant();
        readyStages = Map.copyOf(stageMs);
    }

    @Override
    public synchronized void runStarted(String runId) {
        this.runId = runId;
        this.status = Status.RUNNING;
    }

    @Override
    public synchronized void stepResult(int stepNo, String operation, Control control, StepOutcome outcome) {
        StepView step = steps.computeIfAbsent(stepNo, number -> new StepView(number, operation, new LinkedHashMap<>()));
        step.layers().put(control.name(), new LayerView(outcome(control, outcome), outcome.httpStatus()));
    }

    synchronized void finish(RunSummary summary) {
        runId = summary.runId();
        if ("COMPLETED".equals(summary.status())) {
            status = Status.COMPLETED;
        } else {
            status = Status.FAILED;
            failure = summary.failure();
        }
    }

    synchronized void fail(String reason) {
        status = Status.FAILED;
        failure = reason;
    }

    @Override
    public ChallengeTrace respond(Challenge challenge) {
        Instant requested = null;
        Instant verified = null;
        boolean cancelled = false;
        enter(Stage.WAITING);
        try {
            while (true) {
                Command command = commands.poll(remainingMillis(), TimeUnit.MILLISECONDS);
                if (command == null) {
                    return finish(Stage.EXPIRED, new ChallengeTrace(false, cancelled ? "CANCELLED" : "EXPIRED",
                            challenge.challengedAt(), requested, verified, null), null);
                }
                if (command instanceof RequestCode && stage() != Stage.CODE_SHOWN) {
                    int requestStatus = challenge.actions().requestCode();
                    requested = clock.instant();
                    if (requestStatus != 200 && requestStatus != 302) {
                        return failed(challenge, "code request " + requestStatus, requested, null);
                    }
                    String inbox = challenge.actions().readCode().orElse(null);
                    if (inbox == null) {
                        return failed(challenge, "no code in the demo inbox", requested, null);
                    }
                    cancelled = false;
                    show(inbox);
                } else if (command instanceof Answer answer && stage() == Stage.CODE_SHOWN) {
                    int verification = challenge.actions().submitCode(answer.code());
                    if (verification == 200) {
                        verified = clock.instant();
                        enter(Stage.VERIFYING);
                        StepOutcome reissue = challenge.actions().reissue();
                        ChallengeTrace done = new ChallengeTrace(true, null, challenge.challengedAt(), requested,
                                verified, reissue);
                        boolean resumed = reissue.httpStatus() != null && reissue.httpStatus() == 200;
                        return finish(resumed ? Stage.DONE : Stage.FAILED, done,
                                resumed ? null : "reissue " + reissue.httpStatus() + " " + reissue.outcome());
                    }
                    if (wrongCode() >= MAX_ATTEMPTS) {
                        return finish(Stage.FAILED, new ChallengeTrace(false, "WRONG_CODE_LIMIT",
                                challenge.challengedAt(), requested, null, null), "WRONG_CODE_LIMIT");
                    }
                } else if (command instanceof Cancel && stage() != Stage.CANCELLED) {
                    cancelled = true;
                    enter(Stage.CANCELLED);
                }
            }
        } catch (IOException e) {
            return failed(challenge, e.getClass().getSimpleName() + ": " + e.getMessage(), requested, verified);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return failed(challenge, "interrupted", requested, verified);
        }
    }

    public synchronized View view() {
        List<StepView> stepViews = new ArrayList<>();
        steps.values().forEach(step -> stepViews.add(new StepView(step.stepNo(), step.operation(),
                Map.copyOf(step.layers()))));
        ChallengeView challenge = null;
        if (stage != null) {
            StepOutcome reissue = trace == null ? null : trace.reissue();
            Instant challengedAt = trace == null ? null : trace.challengedAt();
            challenge = new ChallengeView(stage, stage == Stage.CODE_SHOWN ? code : null, secondsLeft(), attempts,
                    error, cause, trace == null ? null : since(challengedAt, trace.codeRequestedAt()),
                    trace == null ? null : since(challengedAt, trace.verifiedAt()),
                    reissue == null ? null : since(challengedAt, reissue.sentAt()),
                    reissue == null ? null : since(challengedAt, reissue.sentAt().plusMillis(reissue.elapsedMs())),
                    reissue == null ? null : reissue.httpStatus(),
                    reissue == null ? null : outcome(Control.D, reissue));
        }
        return new View(liveRunId, scenario, status, queuePosition, runId,
                readyAt == null ? null : Duration.between(requestedAt, readyAt).toMillis(), readyStages, stepViews,
                challenge, failure);
    }

    private synchronized void enter(Stage next) {
        if (next == Stage.WAITING || next == Stage.CANCELLED) {
            deadline = clock.instant().plus(STAGE_TIMEOUT);
        }
        if (next == Stage.WAITING) {
            status = Status.CHALLENGE;
            attempts = 0;
            error = null;
            cause = null;
        }
        code = null;
        stage = next;
    }

    private synchronized void show(String inbox) {
        stage = Stage.CODE_SHOWN;
        code = inbox;
        error = null;
        deadline = clock.instant().plus(STAGE_TIMEOUT);
    }

    private synchronized int wrongCode() {
        attempts++;
        error = "WRONG_CODE";
        return attempts;
    }

    private synchronized Stage stage() {
        return stage;
    }

    private synchronized long remainingMillis() {
        return Math.max(0, Duration.between(clock.instant(), deadline).toMillis());
    }

    private synchronized long secondsLeft() {
        if (deadline == null || stage == Stage.DONE || stage == Stage.EXPIRED || stage == Stage.FAILED) {
            return 0;
        }
        return Math.max(0, Duration.between(clock.instant(), deadline).toSeconds());
    }

    private synchronized ChallengeTrace finish(Stage last, ChallengeTrace result, String failureCause) {
        stage = last;
        code = null;
        trace = result;
        cause = failureCause;
        status = Status.RUNNING;
        return result;
    }

    private ChallengeTrace failed(Challenge challenge, String reason, Instant requested, Instant verified) {
        return finish(Stage.FAILED, ChallengeResponder.failed(challenge, reason, requested, verified), reason);
    }

    /** The business outcome word of a live result, as in the replays: the engine's 401 and 423 hold the data. */
    static String outcome(Control control, StepOutcome outcome) {
        return switch (outcome.outcome()) {
            case "DELIVERED" -> "DELIVERED";
            case "ERROR" -> "UNRESOLVED";
            case "CUT" -> "CUT";
            default -> control == Control.D && outcome.httpStatus() != null
                    && (outcome.httpStatus() == 401 || outcome.httpStatus() == 423) ? "HELD" : "STOPPED";
        };
    }

    private static Long since(Instant from, Instant to) {
        return from == null || to == null ? null : Duration.between(from, to).toMillis();
    }
}
