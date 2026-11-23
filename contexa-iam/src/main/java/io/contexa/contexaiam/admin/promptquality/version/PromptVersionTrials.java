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
package io.contexa.contexaiam.admin.promptquality.version;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityClosingRules;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexacore.std.llm.gate.ModelCallTimer;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV1OutputInspector;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.QualityMeasureLock;
import io.contexa.contexaiam.admin.promptquality.measure.QualityRunLease;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;

import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * The trial of a prompt version (plan 3.10 (4), 6-5): the latest sealed decisions, up to the count asked for, decided
 * again with the version and with the version it is compared with. Nothing is applied: each answer is kept in the
 * trial's tables and the trial shows how the two versions answered. A trial runs one at a time per prompt, in the line
 * of this server with the measurements, and its model calls wait behind the decisions at the model server's gate; it
 * can be cancelled. Quality plan 3.10: after a first answer of ESCALATE the second pass is asked with the server's
 * second-layer model, and the closing rules of the server's settings give each answer's final action beside its first.
 *
 * <p>Quality plan 3.3 (supplement U2): the servers of one database run the trials and the measurements one at a time,
 * under the lock they share ({@link QualityRunLease}). A trial keeps the sealed decisions it chose, and the server that
 * runs it keeps a heartbeat on it; a server that stops lets the lock and the heartbeat run out, and whichever server
 * takes the lock next resumes the trial, skipping the sealed decisions and versions already answered. A cancellation
 * is written to the trial, so the server that runs it stops before its next replay.</p>
 */
public class PromptVersionTrials implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(PromptVersionTrials.class);

    /** How many sealed decisions a trial may ask for. */
    public static final List<Integer> COUNTS = List.of(20, 50, 100);
    public static final String QUEUED = QualityRunLease.QUEUED;
    public static final String RUNNING = QualityRunLease.RUNNING;
    public static final String DONE = "DONE";
    public static final String FAILED = "FAILED";
    public static final String CANCELLED = QualityRunLease.CANCELLED;
    /** The actions a decision may answer, in the order the screen shows them. */
    public static final List<String> ACTIONS = List.of("ALLOW", "CHALLENGE", "ESCALATE", "BLOCK");
    /** The heartbeat of a trial when none is set: that of the measurements by default. */
    public static final Duration DEFAULT_HEARTBEAT = Duration.ofSeconds(30);
    /** How many decisions that changed a trial lists. */
    static final int CHANGED_LIMIT = 100;
    /**
     * The longest one replay may take: a call and its retry, each within the first layer's limit, then the second pass
     * after an ESCALATE.
     */
    private static final long REPLAY_LIMIT_MS = TimeUnit.MINUTES.toMillis(12);
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<List<String>> PACKAGE_IDS = new TypeReference<>() {
    };

    /** Why a trial cannot start. */
    public enum Refusal {
        /** The count is not one the screen offers. */
        COUNT,
        /** A version is missing, hidden, or the two are the same. */
        VERSION,
        /** Only the security decision has sealed decisions to decide again (plan 3.11). */
        PROMPT,
        /** Another trial of the prompt has not finished. */
        RUNNING,
        /** No sealed decision can be decided again. */
        NO_SEALED_DECISIONS
    }

    /** A trial that cannot start, and why. */
    public static class RefusedException extends RuntimeException {

        private final Refusal refusal;

        public RefusedException(Refusal refusal) {
            super("The trial cannot start: " + refusal.name());
            this.refusal = refusal;
        }

        public Refusal refusal() {
            return refusal;
        }
    }

    /**
     * One sealed decision decided again with one version.
     *
     * @param action       the action the first answer gave; null when the replay gave no usable answer
     * @param reason       the answer's reason
     * @param formatError  the first answer broke the output contract, or no usable answer came
     * @param decisionMs   how long the replay took
     * @param answerTokens the tokens of the answer, when the model counted them
     * @param failure      why the replay gave no answer; null otherwise
     * @param finalAction  quality plan 3.10: the action the decision ends in under the closing rules, after the second
     *                     pass of an ESCALATE; null when it cannot be computed
     */
    public record Replayed(String action, String reason, boolean formatError, Long decisionMs, Integer answerTokens,
                           String failure, String finalAction) {

        /** A replay whose final action is not known. */
        public Replayed(String action, String reason, boolean formatError, Long decisionMs, Integer answerTokens,
                        String failure) {
            this(action, reason, formatError, decisionMs, answerTokens, failure, null);
        }
    }

    /** Decides a sealed decision again with a version (the sealed decision replay); empty when the package is gone. */
    @FunctionalInterface
    public interface Replayer {

        Optional<Replayed> replay(String actor, String packageId, String version);
    }

    /** A trial as its row keeps it, with how many replays are done. */
    public record Trial(long id, String scope, String prompt, int candidate, int reference, int requested,
                        Integer actual, String status, Instant startedAt, Instant finishedAt, String failure,
                        String createdBy, Instant createdAt, int replayed) {

        @JsonProperty("candidateName")
        public String candidateName() {
            return PromptVersionNames.name(candidate);
        }

        @JsonProperty("referenceName")
        public String referenceName() {
            return PromptVersionNames.name(reference);
        }

        /** How many replays the trial makes: two per sealed decision. */
        @JsonProperty("replays")
        public int replays() {
            return actual != null ? actual * 2 : requested * 2;
        }
    }

    /**
     * How one version answered in a trial.
     *
     * @param finalAnswered quality plan 3.10: the answers with a final action under the closing rules
     * @param finalActions  the final actions, in the order of {@link #ACTIONS}
     */
    public record Side(int number, String name, long answered, long noAnswer, long formatErrors, Long averageMs,
                       Long averageAnswerTokens, Map<String, Long> actions, long finalAnswered,
                       Map<String, Long> finalActions) {
    }

    /** A sealed decision the two versions answered with different actions. */
    public record Changed(String requestId, String observationId, Instant capturedAt, String userId, String method,
                          String path, String referenceAction, String candidateAction, String candidateReason) {
    }

    /** What a trial found: the pairs, how many kept their action, each side, and the decisions that changed. */
    public record Result(Trial trial, int pairs, int sameAction, Side candidate, Side reference,
                         List<Changed> changed) {
    }

    private record Sealed(String packageId, String requestId, String observationId) {
    }

    private record Case(String packageId, String observationId, int number, String action, boolean formatError,
                        Long decisionMs, Integer answerTokens, String reason, String finalAction) {
    }

    private final Supplier<JdbcTemplate> jdbc;
    private final PromptVersionService versions;
    private final Replayer replayer;
    private final ExecutorService executor;
    private final PromptVersionAudit audit;
    private final Clock clock;
    private final QualityRunLease lease;
    private final ScheduledExecutorService timer;
    private final AtomicBoolean drainWaiting = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile ScheduledFuture<?> sweep;

    /**
     * Trials of this server alone, under a lock of its own.
     *
     * @param executor the line the trials run in, closed with this service
     */
    public PromptVersionTrials(Supplier<JdbcTemplate> jdbc, PromptVersionService versions, Replayer replayer,
                               ExecutorService executor, PromptVersionAudit audit, Clock clock) {
        this(jdbc, versions, replayer, executor, audit, clock, QualityMeasureLock.local(), DEFAULT_HEARTBEAT,
                "server");
    }

    /**
     * @param executor  the line the trials run in, with the measurements; closed with this service
     * @param lock      the lock the servers of the database share with the measurements, or the lock of this server
     * @param heartbeat how often the running server renews the lock and the heartbeat, and the servers look for trials
     * @param serverId  the name of this server in the heartbeat of a trial it runs
     */
    public PromptVersionTrials(Supplier<JdbcTemplate> jdbc, PromptVersionService versions, Replayer replayer,
                               ExecutorService executor, PromptVersionAudit audit, Clock clock,
                               QualityMeasureLock lock, Duration heartbeat, String serverId) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.versions = Objects.requireNonNull(versions, "versions");
        this.replayer = Objects.requireNonNull(replayer, "replayer");
        this.executor = Objects.requireNonNull(executor, "executor");
        this.audit = audit != null ? audit : PromptVersionAudit.none();
        this.clock = clock != null ? clock : Clock.systemUTC();
        this.lease = new QualityRunLease(jdbc, "ctxa_prompt_version_trial", "trial",
                Objects.requireNonNull(lock, "lock"), heartbeat != null ? heartbeat : DEFAULT_HEARTBEAT, this.clock,
                serverId);
        this.timer = Executors.newSingleThreadScheduledExecutor(work -> {
            Thread thread = new Thread(work, "contexa-prompt-version-trial-heartbeat");
            thread.setDaemon(true);
            return thread;
        });
    }

    /** Whether trials can be run for the prompt: only the security decision has sealed decisions (plan 3.11). */
    public static boolean offeredFor(String prompt) {
        return SecurityDecisionPromptDocument.PROMPT.equals(prompt);
    }

    /**
     * Looks for trials to run, or to resume after a server stopped, at every heartbeat from now on: a trial queued on
     * a server that is busy, or that stopped, is run by whichever server takes the lock.
     */
    public void startLookingForWork() {
        if (sweep == null && !closed.get()) {
            long every = lease.heartbeat().toMillis();
            sweep = timer.scheduleWithFixedDelay(this::lookForWork, every, every, TimeUnit.MILLISECONDS);
        }
    }

    /**
     * Starts a trial of the candidate against the reference with the latest sealed decisions, as many as there are up
     * to the count; returns its id. It waits in this server's line, or is run by the server that holds the lock.
     *
     * @throws RefusedException when it cannot start
     */
    public long start(String scope, String prompt, int candidate, int reference, int count, String actor) {
        if (!COUNTS.contains(count)) {
            throw new RefusedException(Refusal.COUNT);
        }
        if (!offeredFor(prompt)) {
            throw new RefusedException(Refusal.PROMPT);
        }
        if (candidate == reference || !shown(scope, prompt, candidate) || !shown(scope, prompt, reference)) {
            throw new RefusedException(Refusal.VERSION);
        }
        String scopeName = scopeOf(scope);
        Integer open = jdbc.get().queryForObject("select count(*) from ctxa_prompt_version_trial where registry_scope = ?"
                + " and prompt_key = ? and status in (?, ?)", Integer.class, scopeName, prompt, QUEUED, RUNNING);
        if (open != null && open > 0) {
            throw new RefusedException(Refusal.RUNNING);
        }
        List<String> sealed = latestSealed(scopeName, count);
        if (sealed.isEmpty()) {
            throw new RefusedException(Refusal.NO_SEALED_DECISIONS);
        }
        long id = insertTrial(scopeName, prompt, candidate, reference, count, sealed, actor);
        audit.record(PromptVersionAudit.TRIAL_STARTED, scopeName, prompt, PromptVersionNames.name(candidate), actor,
                PromptVersionNames.name(reference) + " " + sealed.size() + "/" + count);
        submitDrain();
        return id;
    }

    /**
     * Cancels a trial that has not finished, on whichever server runs it: the server stops before its next replay.
     * Returns whether it was cancelled.
     */
    public boolean cancel(long id, String actor) {
        Optional<Trial> trial = find(id);
        if (trial.isEmpty() || !(QUEUED.equals(trial.get().status()) || RUNNING.equals(trial.get().status()))) {
            return false;
        }
        int updated = jdbc.get().update("update ctxa_prompt_version_trial set status = ?, finished_at = ? where id = ?"
                + " and status in (?, ?)", CANCELLED, Timestamp.from(clock.instant()), id, QUEUED, RUNNING);
        if (updated == 1) {
            audit.record(PromptVersionAudit.TRIAL_CANCELLED, trial.get().scope(), trial.get().prompt(),
                    trial.get().candidateName(), actor, null);
        }
        return updated == 1;
    }

    public Optional<Trial> find(long id) {
        return jdbc.get().query(TRIAL_SQL + " where t.id = ?", TRIAL_ROW, id).stream().findFirst();
    }

    /** The latest trials of the prompt, newest first. */
    public List<Trial> recent(String scope, String prompt, int limit) {
        return jdbc.get().query(TRIAL_SQL + " where t.registry_scope = ? and t.prompt_key = ?"
                + " order by t.created_at desc, t.id desc limit ?", TRIAL_ROW, scopeOf(scope), prompt,
                Math.max(1, limit));
    }

    /** Quality plan 3.8: how many trials the prompt has in the scope, of every state. */
    public long count(String scope, String prompt) {
        Long count = jdbc.get().queryForObject("select count(*) from ctxa_prompt_version_trial where registry_scope = ?"
                + " and prompt_key = ?", Long.class, scopeOf(scope), prompt);
        return count != null ? count : 0L;
    }

    /** The latest finished trial of the version, whichever version it was compared with. */
    public Optional<Trial> latestDone(String scope, String prompt, int candidate) {
        return jdbc.get().query(TRIAL_SQL + " where t.registry_scope = ? and t.prompt_key = ? and t.candidate_number = ?"
                + " and t.status = ? order by t.finished_at desc limit 1", TRIAL_ROW, scopeOf(scope),
                prompt, candidate, DONE).stream().findFirst();
    }

    /** What the trial found so far (all of it once it is done). */
    public Optional<Result> result(long id) {
        Optional<Trial> trial = find(id);
        if (trial.isEmpty()) {
            return Optional.empty();
        }
        List<Case> cases = jdbc.get().query("select sealed_package_id, observation_id, version_number, action,"
                + " format_error, decision_ms, answer_tokens, reason, final_action from ctxa_prompt_version_trial_case"
                + " where trial_id = ? order by id", CASE_ROW, id);
        return Optional.of(result(trial.get(), cases));
    }

    /**
     * A trial that keeps no list of its sealed decisions, left unfinished by a server of a release before the trials
     * were resumed, is marked failed when the service starts: no server can resume it. A trial that keeps its list is
     * left to the server that runs it, or resumed once its heartbeat runs out. Returns how many were marked failed.
     */
    public int closeInterrupted() {
        int updated = jdbc.get().update("update ctxa_prompt_version_trial set status = ?, finished_at = ?, failure = ?"
                + " where status in (?, ?) and sealed_package_ids is null", FAILED, Timestamp.from(clock.instant()),
                "The server stopped before the trial finished", QUEUED, RUNNING);
        if (updated > 0) {
            log.warn("[PromptVersionTrial] {} trials left unfinished by a stop were marked failed", updated);
        }
        return updated;
    }

    @Override
    public void close() {
        closed.set(true);
        timer.shutdownNow();
        executor.shutdownNow();
    }

    /**
     * Whether a replay's first answer broke the output contract, or no usable answer came: a retry for the contract
     * (its explanations, its reason codes, a cut answer, an answer that could not be read) counts; a retry for a rule
     * of the decision (a boundary, a floor, a past record claim, a cited line) does not.
     */
    public static boolean formatError(String action, String failure, Map<String, Object> telemetry) {
        if (failure != null || action == null || action.isBlank()) {
            return true;
        }
        return askedAgainForTheContract(telemetry);
    }

    /**
     * Quality plan 3.3: whether the model was asked again because its answer broke the output contract (its
     * explanations, its reason codes, a cut answer, an answer that could not be read); a retry for a rule of the
     * decision (a boundary, a floor, a past record claim, a cited line) is none.
     */
    public static boolean askedAgainForTheContract(Map<String, Object> telemetry) {
        Object retries = telemetry != null ? telemetry.get(PromptRuntimeTelemetrySupport.OUTPUT_RETRIES) : null;
        if (!(retries instanceof List<?> list)) {
            return false;
        }
        for (Object retry : list) {
            if (retry instanceof Map<?, ?> record && !ruleRetry(String.valueOf(record.get("reason")))) {
                return true;
            }
        }
        return false;
    }

    /**
     * A replay of the sealed decision replay as the trial keeps it, its final action under the closing rules of a
     * server that ends an ESCALATE with CHALLENGE.
     */
    public static Replayed replayed(SealedDecisionReplayService.Result result) {
        return replayed(result, QualityClosingRules.DEFAULTS);
    }

    /**
     * A replay of the sealed decision replay as the trial keeps it: its first action, reason, format, time and tokens,
     * and quality plan 3.10 its final action under the closing rules, after the second pass of an ESCALATE.
     */
    public static Replayed replayed(SealedDecisionReplayService.Result result, QualityClosingRules rules) {
        Map<String, Object> telemetry = result.telemetry() != null ? result.telemetry() : Map.of();
        Object tokens = telemetry.get("actualCompletionTokens");
        QualityAction last = PromptQualityMeasurements.finalAction(result,
                rules != null ? rules : QualityClosingRules.DEFAULTS);
        return new Replayed(result.action(), result.reason(),
                formatError(result.action(), result.failure(), telemetry), result.elapsedMs(),
                tokens instanceof Number number && number.intValue() > 0 ? number.intValue() : null, result.failure(),
                last != null ? last.name() : null);
    }

    private static final Set<String> RULE_REASONS = Set.of(SecurityDecisionFactChecks.REQUIRED_BLOCK,
            SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE, SecurityDecisionFactChecks.REQUIRED_LOW_RISK,
            SecurityDecisionFactChecks.REQUIRED_COVERED_WORK, SecurityDecisionFactChecks.REASON_CODE_MISMATCH,
            SecurityDecisionFactChecks.FALSE_PAST_RECORD_CLAIM);

    private static boolean ruleRetry(String reason) {
        String first = reason == null ? "" : reason.trim().split("[\\s,;:]+", 2)[0];
        return RULE_REASONS.contains(first) || first.startsWith(SecurityDecisionV1OutputInspector.MINIMUM_ACTION_VIOLATION);
    }

    // ----- the run -----

    private void lookForWork() {
        try {
            if (lease.anyWaiting()) {
                submitDrain();
            }
        }
        catch (RuntimeException failure) {
            log.error("[PromptVersionTrial] Looking for trials to run failed", failure);
        }
    }

    private void submitDrain() {
        if (closed.get() || !drainWaiting.compareAndSet(false, true)) {
            return;
        }
        try {
            executor.execute(() -> {
                drainWaiting.set(false);
                drain();
            });
        }
        catch (RejectedExecutionException closing) {
            drainWaiting.set(false);
            log.info("[PromptVersionTrial] The line is closing; the trials wait for another server");
        }
    }

    /** Runs the trials that wait, while this server holds the lock it shares with the measurements. */
    void drain() {
        if (closed.get()) {
            return;
        }
        Optional<QualityMeasureLock.Held> held;
        try {
            held = lease.acquire();
        }
        catch (RuntimeException failure) {
            log.error("[PromptVersionTrial] The lock of the trials could not be taken", failure);
            return;
        }
        if (held.isEmpty()) {
            log.debug("[PromptVersionTrial] Another server runs the measurements or the trials");
            return;
        }
        try {
            Set<Long> tried = new HashSet<>();
            while (!closed.get() && !Thread.currentThread().isInterrupted()) {
                Optional<Trial> next = lease.waiting(TRIAL_SQL, "t", TRIAL_ROW, 20).stream()
                        .filter(trial -> !tried.contains(trial.id())).findFirst();
                if (next.isEmpty()) {
                    break;
                }
                tried.add(next.get().id());
                if (!run(next.get(), held.get())) {
                    break;
                }
            }
        }
        finally {
            held.get().release();
        }
    }

    /** Runs the trial from where it stands; returns whether the lock is still held. */
    private boolean run(Trial trial, QualityMeasureLock.Held held) {
        long id = trial.id();
        if (!lease.claim(id)) {
            return true;
        }
        QualityRunLease.Stop stop = new QualityRunLease.Stop();
        ScheduledFuture<?> heartbeat = lease.keepAlive(timer, id, held, stop);
        try {
            List<String> packages = sealedOf(id);
            if (packages == null) {
                finish(id, FAILED, "The trial keeps no list of its sealed decisions to resume from");
                return true;
            }
            Set<String> done = new HashSet<>(jdbc.get().queryForList("select sealed_package_id || '#' ||"
                    + " version_number from ctxa_prompt_version_trial_case where trial_id = ?", String.class, id));
            log.info("[PromptVersionTrial] Trial {} runs on {}: {} sealed decisions, {} replays kept", id,
                    lease.serverId(), packages.size(), done.size());
            replays:
            for (String packageId : packages) {
                Sealed decision = null;
                for (int number : List.of(trial.candidate(), trial.reference())) {
                    if (done.contains(packageId + "#" + number)) {
                        continue;
                    }
                    if (stopped(id, stop)) {
                        break replays;
                    }
                    if (decision == null) {
                        decision = sealed(packageId);
                    }
                    Replayed replayed = behindTheDecisions(trial.createdBy(), packageId,
                            PromptVersionNames.name(number));
                    insertCase(id, decision, number, replayed);
                }
            }
            if (closed.get() || stop.lockLost() || Thread.currentThread().isInterrupted()) {
                // Left as it is: the server that takes the lock next resumes it once its heartbeat runs out.
                log.warn("[PromptVersionTrial] Trial {} stopped on {} before its end; it is resumed later", id,
                        lease.serverId());
                return !stop.lockLost() && !closed.get();
            }
            if (stop.cancelled() || CANCELLED.equals(lease.status(id))) {
                log.info("[PromptVersionTrial] Trial {} was cancelled", id);
                return true;
            }
            finish(id, DONE, null);
            return true;
        }
        catch (RuntimeException failure) {
            log.error("[PromptVersionTrial] Trial {} failed", id, failure);
            finish(id, FAILED, failure.getClass().getSimpleName() + ": " + failure.getMessage());
            return true;
        }
        finally {
            heartbeat.cancel(false);
        }
    }

    /** Whether the trial stops before its next replay: cancelled on any server, the lock lost, or this server closing. */
    private boolean stopped(long id, QualityRunLease.Stop stop) {
        if (stop.any() || closed.get() || Thread.currentThread().isInterrupted()) {
            return true;
        }
        if (CANCELLED.equals(lease.status(id))) {
            stop.cancel();
            return true;
        }
        return false;
    }

    /** One replay, its model calls in line behind the decisions waiting at the model server's gate. */
    private Replayed behindTheDecisions(String actor, String packageId, String version) {
        ModelCallTimer timer = ModelCallTimer.start(REPLAY_LIMIT_MS).behindDecisions(true);
        try {
            return timer.bind(() -> replayer.replay(actor, packageId, version)).call()
                    .orElse(new Replayed(null, null, true, null, null, "SEALED_PACKAGE_GONE"));
        }
        catch (RuntimeException failure) {
            throw failure;
        }
        catch (Exception failure) {
            return new Replayed(null, null, true, null, null, failure.getClass().getSimpleName());
        }
    }

    private void finish(long id, String status, String failure) {
        jdbc.get().update("update ctxa_prompt_version_trial set status = ?, finished_at = ?, failure = ? where id = ?"
                + " and status in (?, ?)", status, Timestamp.from(clock.instant()), truncate(failure, 2000), id, QUEUED,
                RUNNING);
    }

    /** The sealed decisions the trial chose, in their order; null when it keeps none that can be read. */
    private List<String> sealedOf(long id) {
        String text = jdbc.get().query("select sealed_package_ids from ctxa_prompt_version_trial where id = ?",
                (rs, row) -> rs.getString(1), id).stream().findFirst().orElse(null);
        if (text == null || text.isBlank()) {
            return null;
        }
        try {
            return JSON.readValue(text, PACKAGE_IDS);
        }
        catch (JsonProcessingException unreadable) {
            log.warn("[PromptVersionTrial] The sealed decisions of trial {} cannot be read", id);
            return null;
        }
    }

    private List<String> latestSealed(String scope, int count) {
        boolean platform = PromptVersionService.PLATFORM_SCOPE.equals(scope);
        List<Object> arguments = new ArrayList<>();
        if (!platform) {
            arguments.add(scope);
        }
        arguments.add(count);
        return jdbc.get().query("select p.package_id from ctxa_sealed_evidence_package p"
                + " where p.seal_state = 'SEALED' and coalesce(contexa_safe_jsonb(p.decision_json) ->>"
                + " 'decisionAppliedStage', '') <> 'SHADOW'" + (platform ? "" : " and p.tenant_id = ?")
                + " order by p.captured_at desc limit ?", (rs, row) -> rs.getString(1), arguments.toArray());
    }

    /** The sealed decision with its request and the latest decision row of the request, as they are now. */
    private Sealed sealed(String packageId) {
        String requestId = jdbc.get().query("select correlation_id from ctxa_sealed_evidence_package where"
                + " package_id = ?", (rs, row) -> rs.getString(1), packageId).stream().findFirst().orElse(null);
        String observation = requestId == null ? null : jdbc.get().query("select observation_id from"
                + " ctxa_ai_security_decision_observation where request_id = ? order by created_at desc limit 1",
                (rs, row) -> rs.getString(1), requestId).stream().findFirst().orElse(null);
        return new Sealed(packageId, requestId, observation);
    }

    private long insertTrial(String scope, String prompt, int candidate, int reference, int requested,
                             List<String> sealed, String actor) {
        String packages;
        try {
            packages = JSON.writeValueAsString(sealed);
        }
        catch (JsonProcessingException exception) {
            throw new IllegalStateException("The sealed decisions of a trial could not be written", exception);
        }
        KeyHolder key = new GeneratedKeyHolder();
        jdbc.get().update(connection -> {
            PreparedStatement statement = connection.prepareStatement("insert into ctxa_prompt_version_trial"
                    + " (registry_scope, prompt_key, candidate_number, reference_number, requested_count, actual_count,"
                    + " status, created_by, created_at, sealed_package_ids) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, scope);
            statement.setString(2, prompt);
            statement.setInt(3, candidate);
            statement.setInt(4, reference);
            statement.setInt(5, requested);
            statement.setInt(6, sealed.size());
            statement.setString(7, QUEUED);
            statement.setString(8, actor != null ? actor : "system");
            statement.setTimestamp(9, Timestamp.from(clock.instant()));
            statement.setString(10, packages);
            return statement;
        }, key);
        return ((Number) Objects.requireNonNull(key.getKeys()).get("id")).longValue();
    }

    /** Keeps one replay; a replay a server that lost the lock kept already is not kept twice. */
    private void insertCase(long id, Sealed decision, int number, Replayed replayed) {
        jdbc.get().update("insert into ctxa_prompt_version_trial_case (trial_id, sealed_package_id, observation_id,"
                + " version_number, action, format_error, decision_ms, answer_tokens, reason, final_action) values"
                + " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) on conflict (trial_id, sealed_package_id, version_number) do nothing",
                id, decision.packageId(), decision.observationId(), number, replayed.action(), replayed.formatError(),
                replayed.decisionMs(), replayed.answerTokens(),
                truncate(replayed.reason() != null ? replayed.reason() : replayed.failure(), 2000),
                truncate(replayed.finalAction(), 16));
    }

    // ----- the result -----

    private Result result(Trial trial, List<Case> cases) {
        Map<String, Map<Integer, Case>> byPackage = new LinkedHashMap<>();
        for (Case one : cases) {
            byPackage.computeIfAbsent(one.packageId(), key -> new LinkedHashMap<>()).put(one.number(), one);
        }
        int pairs = 0;
        int same = 0;
        List<Case> changedCandidates = new ArrayList<>();
        Map<String, Case> referenceOf = new LinkedHashMap<>();
        for (Map.Entry<String, Map<Integer, Case>> entry : byPackage.entrySet()) {
            Case candidate = entry.getValue().get(trial.candidate());
            Case reference = entry.getValue().get(trial.reference());
            if (candidate == null || reference == null) {
                continue;
            }
            pairs++;
            if (candidate.action() != null && candidate.action().equals(reference.action())) {
                same++;
            }
            else if (candidate.action() != null && reference.action() != null) {
                changedCandidates.add(candidate);
                referenceOf.put(entry.getKey(), reference);
            }
        }
        List<Changed> changed = changed(changedCandidates.stream().limit(CHANGED_LIMIT).toList(), referenceOf);
        return new Result(trial, pairs, same, side(trial.candidate(), cases), side(trial.reference(), cases), changed);
    }

    private static Side side(int number, List<Case> cases) {
        List<Case> mine = cases.stream().filter(one -> one.number() == number).toList();
        Map<String, Long> actions = new LinkedHashMap<>();
        Map<String, Long> finalActions = new LinkedHashMap<>();
        ACTIONS.forEach(action -> {
            actions.put(action, 0L);
            finalActions.put(action, 0L);
        });
        long answered = 0;
        long finalAnswered = 0;
        long totalMs = 0;
        long timed = 0;
        long totalTokens = 0;
        long counted = 0;
        long formatErrors = 0;
        for (Case one : mine) {
            if (one.formatError()) {
                formatErrors++;
            }
            if (one.action() != null) {
                answered++;
                actions.merge(one.action(), 1L, Long::sum);
            }
            if (one.finalAction() != null) {
                finalAnswered++;
                finalActions.merge(one.finalAction(), 1L, Long::sum);
            }
            if (one.decisionMs() != null) {
                totalMs += one.decisionMs();
                timed++;
            }
            if (one.answerTokens() != null) {
                totalTokens += one.answerTokens();
                counted++;
            }
        }
        return new Side(number, PromptVersionNames.name(number), answered, mine.size() - answered, formatErrors,
                timed > 0 ? Math.round((double) totalMs / timed) : null,
                counted > 0 ? Math.round((double) totalTokens / counted) : null, actions, finalAnswered, finalActions);
    }

    private List<Changed> changed(List<Case> candidates, Map<String, Case> referenceOf) {
        List<Changed> changed = new ArrayList<>();
        for (Case candidate : candidates) {
            Case reference = referenceOf.get(candidate.packageId());
            Object[] request = candidate.observationId() == null ? null : jdbc.get().query("select request_id, created_at,"
                    + " user_id, http_method, request_path from ctxa_ai_security_decision_observation where"
                    + " observation_id = ?", (rs, row) -> new Object[] {rs.getString(1),
                    rs.getTimestamp(2) != null ? rs.getTimestamp(2).toInstant() : null, rs.getString(3),
                    rs.getString(4), rs.getString(5)}, candidate.observationId()).stream().findFirst().orElse(null);
            String requestId = request != null ? (String) request[0] : jdbc.get().query("select correlation_id from"
                    + " ctxa_sealed_evidence_package where package_id = ?", (rs, row) -> rs.getString(1),
                    candidate.packageId()).stream().findFirst().orElse(null);
            changed.add(new Changed(requestId, candidate.observationId(), request != null ? (Instant) request[1] : null,
                    request != null ? (String) request[2] : null, request != null ? (String) request[3] : null,
                    request != null ? (String) request[4] : null, reference.action(), candidate.action(),
                    candidate.reason()));
        }
        return changed;
    }

    private boolean shown(String scope, String prompt, int number) {
        return versions.find(scope, prompt, number).filter(record -> !record.hidden()).isPresent();
    }

    private static String scopeOf(String scope) {
        return scope != null && !scope.isBlank() ? scope.trim() : PromptVersionService.PLATFORM_SCOPE;
    }

    private static String truncate(String value, int length) {
        return value == null || value.length() <= length ? value : value.substring(0, length);
    }

    private static final String TRIAL_SQL = "select t.id, t.registry_scope, t.prompt_key, t.candidate_number,"
            + " t.reference_number, t.requested_count, t.actual_count, t.status, t.started_at, t.finished_at, t.failure,"
            + " t.created_by, t.created_at, (select count(*) from ctxa_prompt_version_trial_case c where c.trial_id ="
            + " t.id) as replayed from ctxa_prompt_version_trial t";

    private static final RowMapper<Trial> TRIAL_ROW = (rs, row) -> new Trial(rs.getLong("id"),
            rs.getString("registry_scope"), rs.getString("prompt_key"), rs.getInt("candidate_number"),
            rs.getInt("reference_number"), rs.getInt("requested_count"), (Integer) rs.getObject("actual_count"),
            rs.getString("status"), instant(rs.getTimestamp("started_at")), instant(rs.getTimestamp("finished_at")),
            rs.getString("failure"), rs.getString("created_by"), instant(rs.getTimestamp("created_at")),
            rs.getInt("replayed"));

    private static final RowMapper<Case> CASE_ROW = (rs, row) -> new Case(rs.getString("sealed_package_id"),
            rs.getString("observation_id"), rs.getInt("version_number"), rs.getString("action"),
            rs.getBoolean("format_error"), (Long) rs.getObject("decision_ms"), (Integer) rs.getObject("answer_tokens"),
            rs.getString("reason"), rs.getString("final_action"));

    private static Instant instant(Timestamp timestamp) {
        return timestamp != null ? timestamp.toInstant() : null;
    }
}
