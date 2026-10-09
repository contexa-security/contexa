package io.contexa.showcase.portal.live;

import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.orchestrator.Approver;
import io.contexa.showcase.portal.orchestrator.ChallengeResponder;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;
import io.contexa.showcase.portal.orchestrator.ControlSession.ChallengeTrace;
import io.contexa.showcase.portal.orchestrator.ControlSession.ReleaseTrace;
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
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * One scenario a visitor runs live (docs/showcase/P3-설계.md 3절). It hears every control's result as it arrives and,
 * when control D asks for an additional check, waits for the visitor: ask for the code, enter it from the demo inbox,
 * cancel, or give up at once (the attacker of the first scene has no access to the employee's mailbox). Before a step
 * the visitor sends (the attacker trying again), it waits for the visitor's press. When control D blocks the account,
 * it waits for the visitor to ask for the release (ADR-33): pass the identity check, file the request with a reason, and
 * approve it as the run's security administrator; the original request then goes out again. An attacker holds the
 * password and the session but not the employee's mailbox: a code goes out for real, and the run never shows it. Each
 * wait ends after {@link #STAGE_TIMEOUT}; three wrong codes end the check as a failed recovery.
 */
public final class LiveRun implements ChallengeResponder, RunListener {

    static final Duration STAGE_TIMEOUT = Duration.ofSeconds(120);
    static final int MAX_ATTEMPTS = 3;

    /**
     * AWAITING: the run waits for the visitor to send its next step. BLOCKED: control D blocked the account and the
     * run waits for the visitor on the release.
     */
    public enum Status { QUEUED, STARTING, RUNNING, CHALLENGE, AWAITING, BLOCKED, COMPLETED, FAILED, EXPIRED }

    /**
     * WAITING: the check was asked, nothing requested yet. CODE_SHOWN: the demo inbox holds a code. CANCELLED: the
     * visitor stepped back; the request stays on hold until the time runs out. ABANDONED: the visitor gave up the check
     * and the request stays held. The rest are final too.
     */
    public enum Stage { WAITING, CODE_SHOWN, CANCELLED, VERIFYING, DONE, EXPIRED, FAILED, ABANDONED, NO_MAILBOX }

    /**
     * The release of a block. BLOCKED: nothing asked yet. CODE_SHOWN: the check of the blocked account sent a code
     * to the demo inbox. VERIFIED: the check passed. REQUESTED: the release request is filed and the administrator can
     * read it. APPROVING: approved, the original request goes out again. NO_MAILBOX: the code went to the employee's
     * mailbox, which the attacker does not have. The rest are final too.
     */
    public enum ReleaseStage {
        BLOCKED, CODE_SHOWN, VERIFIED, REQUESTED, APPROVING, DONE, NO_MAILBOX, EXPIRED, FAILED, ABANDONED
    }

    sealed interface Command permits RequestCode, Answer, Cancel, Abandon, Proceed, StartRelease, RequestRelease,
            Approve {
    }

    record StartRelease() implements Command {
    }

    record RequestRelease(String reason) implements Command {
    }

    record Approve() implements Command {
    }

    record RequestCode() implements Command {
    }

    record Answer(String code) implements Command {
    }

    record Cancel() implements Command {
    }

    record Abandon() implements Command {
    }

    record Proceed() implements Command {
    }

    /**
     * @param deliveredItems items the control actually handed over in its response
     * @param elapsedMs      milliseconds from sending the request to its response
     */
    /**
     * @param ruleId the rule the control recorded for its answer (for control D, ACCOUNT_BLOCKED or
     *               MFA_CHALLENGE_REQUIRED when a decision already in force refused the request); null when none
     */
    public record LayerView(String outcome, Integer httpStatus, int deliveredItems, long elapsedMs, String ruleId) {
    }

    /**
     * How far a control's streamed export got while it is still being read.
     *
     * @param total announced items, null when the response did not say
     * @param atMs  milliseconds since the request was sent
     */
    public record StreamView(Integer total, int delivered, long atMs) {
    }

    /**
     * @param streams progress of each control's stream while it runs; the final count is in {@code layers}
     */
    public record StepView(int stepNo, String operation, Map<String, LayerView> layers,
                           Map<String, StreamView> streams) {
    }

    /** Control D's request of a step, by which the engine's analysis of it is read while it runs. */
    public record EngineRequest(int stepNo, BusinessOperation operation, String requestId, Instant sentAt) {
    }

    /**
     * @param code        the code in the demo inbox, shown only while the visitor can enter it
     * @param secondsLeft time left for the current wait
     * @param error       WRONG_CODE after a code that did not verify
     * @param cause       why the check could not complete, for "see the cause"
     * @param reissueDeliveredItems items the re-issued request actually handed over
     */
    public record ChallengeView(Stage stage, String code, long secondsLeft, int attempts, String error, String cause,
                                Long codeRequestedMs, Long verifiedMs, Long reissueSentMs, Long reissueDoneMs,
                                Integer reissueStatus, String reissueOutcome, Integer reissueDeliveredItems) {
    }

    /**
     * The release of a block as the visitor sees it. Milliseconds are counted from the moment the block came back.
     *
     * @param code   the code in the demo inbox, shown only while the visitor can enter it
     * @param reason the reason the visitor filed the request with
     * @param block  the engine's record of the block as the administrator reads it, once the request is filed
     * @param approverName the security administrator who reads the request, as the work database names them
     */
    public record ReleaseView(ReleaseStage stage, String code, long secondsLeft, int attempts, String error,
                              String cause, String reason, Approver.BlockRecord block, String approverName,
                              Long codeRequestedMs,
                              Long verifiedMs, Long requestedMs, Long approvedMs, Long reissueSentMs,
                              Long reissueDoneMs, Integer reissueStatus, String reissueOutcome,
                              Integer reissueDeliveredItems) {
    }

    /**
     * @param queuePosition    1-based place in the queue while QUEUED, 0 otherwise
     * @param queueWaitSeconds about how many seconds until the queued run starts, from the times of recent live runs
     *                         ({@link LiveRuns}); null when not queued or before any live run finished
     * @param readyMs          milliseconds from the request to the space being ready (principal cloned and signed
     *                         in), null until then (P4-BE-01)
     * @param readyStages      milliseconds of each preparation stage of the space
     * @param awaitingStep     the step the run waits for the visitor to send, null unless AWAITING
     */
    public record View(String liveRunId, String scenario, Status status, int queuePosition, Integer queueWaitSeconds,
                       String runId, Long readyMs, Map<String, Long> readyStages, List<StepView> steps, ChallengeView challenge,
                       String failure, Integer awaitingStep, ReleaseView release) {
    }

    /** Longest reason a visitor can file a release request with. */
    static final int MAX_REASON = 300;
    /** The engine's authority cache can hold the block a few seconds after the approval (up to 5 s). */
    static final Duration REISSUE_WAIT = Duration.ofSeconds(2);
    static final int REISSUE_TRIES = 4;

    private final String liveRunId;
    private final String visitor;
    private final String scenario;
    private final Clock clock;
    private final BlockingQueue<Command> commands = new LinkedBlockingQueue<>();
    private final Map<Integer, StepView> steps = new LinkedHashMap<>();
    private final Map<Integer, Map<String, StreamView>> streams = new LinkedHashMap<>();
    private final Map<Integer, EngineRequest> engineRequests = new LinkedHashMap<>();
    private Integer awaitingStep;
    private Instant awaitDeadline;
    /** The visitor gave up and moved on: the run sends nothing more that waits for the visitor. */
    private boolean visitorLeft;
    private ReleaseStage releaseStage;
    private String releaseCode;
    private int releaseAttempts;
    private String releaseError;
    private String releaseCause;
    private String releaseReason;
    private Approver.BlockRecord releaseBlock;
    private String releaseApproverName;
    private Instant blockedAt;
    private Instant releaseCodeAt;
    private Instant releaseVerifiedAt;
    private Instant releaseRequestedAt;
    private Instant releaseApprovedAt;
    private StepOutcome releaseReissue;
    private final Instant requestedAt;
    private Instant readyAt;
    private Map<String, Long> readyStages = Map.of();

    private Status status = Status.STARTING;
    private int queuePosition;
    private Instant expectedStart;
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

    public String scenario() {
        return scenario;
    }

    public synchronized boolean active() {
        return status == Status.QUEUED || status == Status.STARTING || status == Status.RUNNING
                || status == Status.CHALLENGE || status == Status.AWAITING || status == Status.BLOCKED;
    }

    public synchronized Status status() {
        return status;
    }

    /** @param expectedStart when the run is expected to start; null when nothing tells it yet */
    synchronized void queued(int position, Instant expectedStart) {
        status = Status.QUEUED;
        queuePosition = position;
        this.expectedStart = expectedStart;
    }

    synchronized void starting() {
        status = Status.STARTING;
        queuePosition = 0;
        expectedStart = null;
    }

    /** A queued run whose space was cleaned before its turn. */
    synchronized void expire() {
        status = Status.EXPIRED;
        queuePosition = 0;
        expectedStart = null;
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

    /** Gives up the additional check, or ends the run without the step it waits for the visitor to send. */
    public void abandon() {
        commands.add(new Abandon());
    }

    /** Sends the step the run waits for the visitor to send. */
    public void proceed() {
        commands.add(new Proceed());
    }

    /** Starts the identity check of the blocked account, which sends a one-time code. */
    public void startRelease() {
        commands.add(new StartRelease());
    }

    /** Files the release request with the visitor's reason. */
    public void requestRelease(String reason) {
        commands.add(new RequestRelease(reason == null ? "" : reason.trim()));
    }

    /** Approves the filed request as the run's security administrator. */
    public void approve() {
        commands.add(new Approve());
    }

    /** The run ID of this run once it completed, for its full result; empty while it runs or after a failure. */
    public synchronized Optional<String> completedRunId() {
        return status == Status.COMPLETED ? Optional.ofNullable(runId) : Optional.empty();
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
    public synchronized void requestSent(int stepNo, Control control, BusinessOperation operation, String requestId,
                                         Instant sentAt) {
        if (control == Control.D) {
            engineRequests.put(stepNo, new EngineRequest(stepNo, operation, requestId, sentAt));
        }
    }

    @Override
    public synchronized void streamProgress(int stepNo, Control control, Integer total, long atMs, int delivered) {
        streams.computeIfAbsent(stepNo, number -> new LinkedHashMap<>())
                .put(control.name(), new StreamView(total, delivered, atMs));
    }

    /** Control D's request of a step of this run, or its latest when the step is null, if it has sent one. */
    public synchronized Optional<EngineRequest> engineRequest(Integer stepNo) {
        if (stepNo != null) {
            return Optional.ofNullable(engineRequests.get(stepNo));
        }
        EngineRequest latest = null;
        for (EngineRequest request : engineRequests.values()) {
            latest = request;
        }
        return Optional.ofNullable(latest);
    }

    @Override
    public boolean awaitVisitor(int stepNo) {
        synchronized (this) {
            if (visitorLeft) {
                return false;
            }
            commands.clear();
            status = Status.AWAITING;
            awaitingStep = stepNo;
            awaitDeadline = clock.instant().plus(STAGE_TIMEOUT);
        }
        try {
            while (true) {
                long left;
                synchronized (this) {
                    left = Math.max(0, Duration.between(clock.instant(), awaitDeadline).toMillis());
                }
                Command command = commands.poll(left, TimeUnit.MILLISECONDS);
                if (command == null || command instanceof Abandon) {
                    return resume(false);
                }
                if (command instanceof Proceed) {
                    return resume(true);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return resume(false);
        }
    }

    private synchronized void leave() {
        visitorLeft = true;
    }

    private synchronized boolean resume(boolean send) {
        // A visitor who did not send the step moved on; later steps of the visitor's are not waited for either.
        visitorLeft = visitorLeft || !send;
        status = Status.RUNNING;
        awaitingStep = null;
        awaitDeadline = null;
        return send;
    }

    @Override
    public synchronized void stepResult(int stepNo, String operation, Control control, StepOutcome outcome) {
        StepView step = steps.computeIfAbsent(stepNo,
                number -> new StepView(number, operation, new LinkedHashMap<>(), Map.of()));
        step.layers().put(control.name(), new LayerView(outcome(control, outcome), outcome.httpStatus(),
                outcome.deliveredItems(), outcome.elapsedMs(), outcome.ruleId()));
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
                    if ("THREAT".equals(challenge.classification())) {
                        return finish(Stage.NO_MAILBOX, new ChallengeTrace(false, "NO_MAILBOX",
                                challenge.challengedAt(), requested, null, null), null);
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
                } else if (command instanceof Abandon) {
                    leave();
                    return finish(Stage.ABANDONED, new ChallengeTrace(false, "ABANDONED", challenge.challengedAt(),
                            requested, null, null), null);
                }
            }
        } catch (IOException e) {
            return failed(challenge, e.getClass().getSimpleName() + ": " + e.getMessage(), requested, verified);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return failed(challenge, "interrupted", requested, verified);
        }
    }

    @Override
    public ReleaseTrace release(Release release) {
        enterRelease(release.blockedAt());
        try {
            while (true) {
                Command command = commands.poll(remainingMillis(), TimeUnit.MILLISECONDS);
                ReleaseStage at = releaseStage();
                if (command == null) {
                    return endRelease(ReleaseStage.EXPIRED, false, "EXPIRED");
                }
                if (command instanceof Abandon) {
                    leave();
                    return endRelease(ReleaseStage.ABANDONED, false, "ABANDONED");
                }
                if (command instanceof StartRelease && at == ReleaseStage.BLOCKED) {
                    int started = release.actions().startCheck();
                    if (started != 200) {
                        return endRelease(ReleaseStage.FAILED, false, "check start " + started);
                    }
                    int sent = release.actions().requestCode();
                    markRelease(stamp -> releaseCodeAt = stamp);
                    if (sent != 200 && sent != 302) {
                        return endRelease(ReleaseStage.FAILED, false, "code request " + sent);
                    }
                    if ("THREAT".equals(release.classification())) {
                        leave();
                        return endRelease(ReleaseStage.NO_MAILBOX, false, "NO_MAILBOX");
                    }
                    String inbox = release.actions().readCode().orElse(null);
                    if (inbox == null) {
                        return endRelease(ReleaseStage.FAILED, false, "no code in the demo inbox");
                    }
                    showReleaseCode(inbox);
                } else if (command instanceof Answer answer && at == ReleaseStage.CODE_SHOWN) {
                    if (release.actions().submitCode(answer.code()) == 200) {
                        markRelease(stamp -> releaseVerifiedAt = stamp);
                        enterReleaseStage(ReleaseStage.VERIFIED);
                    } else if (wrongReleaseCode() >= MAX_ATTEMPTS) {
                        return endRelease(ReleaseStage.FAILED, false, "WRONG_CODE_LIMIT");
                    }
                } else if (command instanceof RequestRelease filed && at == ReleaseStage.VERIFIED) {
                    String reason = filed.reason();
                    if (reason.isEmpty() || reason.length() > MAX_REASON) {
                        continue;
                    }
                    int status = release.actions().requestRelease(reason);
                    if (status != 200) {
                        return endRelease(ReleaseStage.FAILED, false, "release request " + status);
                    }
                    markRelease(stamp -> releaseRequestedAt = stamp);
                    Approver.BlockRecord block = release.approver().request(release.username()).orElse(null);
                    if (block == null || !"UNBLOCK_REQUESTED".equals(block.status())) {
                        return endRelease(ReleaseStage.FAILED, false, "no filed request in the block list: "
                                + (block == null ? "none" : block.status()));
                    }
                    fileRelease(reason, block, release.approver().displayName());
                } else if (command instanceof Approve && at == ReleaseStage.REQUESTED) {
                    enterReleaseStage(ReleaseStage.APPROVING);
                    int status = release.approver().approve(releaseBlockId(), approvalReason());
                    if (status != 200) {
                        return endRelease(ReleaseStage.FAILED, false, "approval " + status);
                    }
                    markRelease(stamp -> releaseApprovedAt = stamp);
                    StepOutcome reissue = release.actions().reissue();
                    for (int tries = 1; tries < REISSUE_TRIES && reissue.httpStatus() != null
                            && reissue.httpStatus() == 403; tries++) {
                        Thread.sleep(REISSUE_WAIT.toMillis());
                        reissue = release.actions().reissue();
                    }
                    boolean served = reissue.httpStatus() != null && reissue.httpStatus() == 200;
                    synchronized (this) {
                        releaseReissue = reissue;
                    }
                    return endRelease(served ? ReleaseStage.DONE : ReleaseStage.FAILED, true,
                            served ? null : "reissue " + reissue.httpStatus() + " " + reissue.outcome());
                }
            }
        } catch (IOException e) {
            return endRelease(ReleaseStage.FAILED, false, e.getClass().getSimpleName() + ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return endRelease(ReleaseStage.FAILED, false, "interrupted");
        }
    }

    private synchronized void enterRelease(Instant at) {
        commands.clear();
        blockedAt = at;
        status = Status.BLOCKED;
        releaseAttempts = 0;
        releaseError = null;
        releaseCause = null;
        enterReleaseStage(ReleaseStage.BLOCKED);
    }

    private synchronized void enterReleaseStage(ReleaseStage next) {
        releaseStage = next;
        releaseCode = null;
        deadline = clock.instant().plus(STAGE_TIMEOUT);
    }

    private synchronized ReleaseStage releaseStage() {
        return releaseStage;
    }

    private synchronized void markRelease(Consumer<Instant> field) {
        field.accept(clock.instant());
    }

    private synchronized void showReleaseCode(String inbox) {
        enterReleaseStage(ReleaseStage.CODE_SHOWN);
        releaseCode = inbox;
        releaseError = null;
    }

    private synchronized int wrongReleaseCode() {
        releaseAttempts++;
        releaseError = "WRONG_CODE";
        return releaseAttempts;
    }

    private synchronized void fileRelease(String reason, Approver.BlockRecord block, String approverName) {
        releaseReason = reason;
        releaseBlock = block;
        releaseApproverName = approverName;
        enterReleaseStage(ReleaseStage.REQUESTED);
    }

    /**
     * The security administrator's approval reason, built from what this run recorded (fabricated-data survey P2): when
     * the identity check passed, when the request was filed and the requester's own reason.
     */
    synchronized String approvalReason() {
        return approvalReason(releaseVerifiedAt, releaseRequestedAt, releaseReason);
    }

    static String approvalReason(Instant verifiedAt, Instant requestedAt, String requestReason) {
        return "Approved the release request filed at " + requestedAt + " after the identity check passed at "
                + verifiedAt + "; requester's reason: " + requestReason;
    }

    private synchronized long releaseBlockId() {
        return releaseBlock.id();
    }

    private synchronized ReleaseTrace endRelease(ReleaseStage last, boolean released, String cause) {
        releaseStage = last;
        releaseCode = null;
        releaseCause = cause;
        status = Status.RUNNING;
        return new ReleaseTrace(released && last == ReleaseStage.DONE, cause, blockedAt, releaseCodeAt,
                releaseVerifiedAt, releaseRequestedAt, releaseApprovedAt, releaseBlock, releaseReissue);
    }

    public synchronized View view() {
        List<StepView> stepViews = new ArrayList<>();
        steps.values().forEach(step -> stepViews.add(new StepView(step.stepNo(), step.operation(),
                Map.copyOf(step.layers()), Map.copyOf(streams.getOrDefault(step.stepNo(), Map.of())))));
        // A stream whose first answer has not arrived yet still shows how far it got.
        streams.forEach((stepNo, progress) -> {
            if (!steps.containsKey(stepNo)) {
                stepViews.add(new StepView(stepNo, null, Map.of(), Map.copyOf(progress)));
            }
        });
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
                    reissue == null ? null : outcome(Control.D, reissue),
                    reissue == null ? null : reissue.deliveredItems());
        }
        ReleaseView release = null;
        if (releaseStage != null) {
            StepOutcome reissue = releaseReissue;
            release = new ReleaseView(releaseStage, releaseStage == ReleaseStage.CODE_SHOWN ? releaseCode : null,
                    releaseSecondsLeft(), releaseAttempts, releaseError, releaseCause, releaseReason, releaseBlock,
                    releaseApproverName,
                    since(blockedAt, releaseCodeAt), since(blockedAt, releaseVerifiedAt),
                    since(blockedAt, releaseRequestedAt), since(blockedAt, releaseApprovedAt),
                    reissue == null ? null : since(blockedAt, reissue.sentAt()),
                    reissue == null ? null : since(blockedAt, reissue.sentAt().plusMillis(reissue.elapsedMs())),
                    reissue == null ? null : reissue.httpStatus(),
                    reissue == null ? null : outcome(Control.D, reissue),
                    reissue == null ? null : reissue.deliveredItems());
        }
        Integer queueWaitSeconds = status != Status.QUEUED || expectedStart == null ? null
                : (int) Math.max(0, (Duration.between(clock.instant(), expectedStart).toMillis() + 999) / 1000);
        return new View(liveRunId, scenario, status, queuePosition, queueWaitSeconds, runId,
                readyAt == null ? null : Duration.between(requestedAt, readyAt).toMillis(), readyStages, stepViews,
                challenge, failure, awaitingStep, release);
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

    private synchronized long releaseSecondsLeft() {
        if (deadline == null || releaseStage == ReleaseStage.DONE || releaseStage == ReleaseStage.EXPIRED
                || releaseStage == ReleaseStage.FAILED || releaseStage == ReleaseStage.ABANDONED
                || releaseStage == ReleaseStage.NO_MAILBOX) {
            return 0;
        }
        return Math.max(0, Duration.between(clock.instant(), deadline).toSeconds());
    }

    private synchronized long secondsLeft() {
        if (deadline == null || stage == Stage.DONE || stage == Stage.EXPIRED || stage == Stage.FAILED
                || stage == Stage.ABANDONED) {
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

    /**
     * The business outcome word of a live result, as in the replays: the engine's 401 and 423 hold the data; a request
     * that broke after data had left is BROKEN with that data, never unresolved (docs/showcase/데모-재설계.md 5.0).
     */
    static String outcome(Control control, StepOutcome outcome) {
        return switch (outcome.outcome()) {
            case "DELIVERED" -> "DELIVERED";
            case "ERROR" -> outcome.deliveredItems() > 0 ? "BROKEN" : "UNRESOLVED";
            case "CUT" -> "CUT";
            default -> control == Control.D && outcome.httpStatus() != null
                    && (outcome.httpStatus() == 401 || outcome.httpStatus() == 423) ? "HELD" : "STOPPED";
        };
    }

    private static Long since(Instant from, Instant to) {
        return from == null || to == null ? null : Duration.between(from, to).toMillis();
    }
}
