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
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexacore.std.llm.gate.ModelCallTimer;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionV1OutputInspector;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
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
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * The trial of a prompt version (plan 3.10 (4), 6-5): the latest sealed decisions, up to the count asked for, decided
 * again with the version and with the version it is compared with. Nothing is applied: each answer is kept in the
 * trial's tables and the trial shows how the two versions answered. A trial runs one at a time per prompt, on a thread
 * of its own, and its model calls wait behind the decisions at the model server's gate; it can be cancelled.
 */
public class PromptVersionTrials implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(PromptVersionTrials.class);

    /** How many sealed decisions a trial may ask for. */
    public static final List<Integer> COUNTS = List.of(20, 50, 100);
    public static final String QUEUED = "QUEUED";
    public static final String RUNNING = "RUNNING";
    public static final String DONE = "DONE";
    public static final String FAILED = "FAILED";
    public static final String CANCELLED = "CANCELLED";
    /** The actions a decision may answer, in the order the screen shows them. */
    public static final List<String> ACTIONS = List.of("ALLOW", "CHALLENGE", "ESCALATE", "BLOCK");
    /** How many decisions that changed a trial lists. */
    static final int CHANGED_LIMIT = 100;
    /** The longest one replay may take: a call and its retry, each within the first layer's limit. */
    private static final long REPLAY_LIMIT_MS = TimeUnit.MINUTES.toMillis(6);

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
     * @param action       the action the answer gave; null when the replay gave no usable answer
     * @param reason       the answer's reason
     * @param formatError  the first answer broke the output contract, or no usable answer came
     * @param decisionMs   how long the replay took
     * @param answerTokens the tokens of the answer, when the model counted them
     * @param failure      why the replay gave no answer; null otherwise
     */
    public record Replayed(String action, String reason, boolean formatError, Long decisionMs, Integer answerTokens,
                           String failure) {
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

    /** How one version answered in a trial. */
    public record Side(int number, String name, long answered, long noAnswer, long formatErrors, Long averageMs,
                       Long averageAnswerTokens, Map<String, Long> actions) {
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
                        Long decisionMs, Integer answerTokens, String reason) {
    }

    private final Supplier<JdbcTemplate> jdbc;
    private final PromptVersionService versions;
    private final Replayer replayer;
    private final ExecutorService executor;
    private final PromptVersionAudit audit;
    private final Clock clock;
    private final Set<Long> cancelled = ConcurrentHashMap.newKeySet();

    /**
     * @param executor the one thread trials run on, closed with this service
     */
    public PromptVersionTrials(Supplier<JdbcTemplate> jdbc, PromptVersionService versions, Replayer replayer,
                               ExecutorService executor, PromptVersionAudit audit, Clock clock) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.versions = Objects.requireNonNull(versions, "versions");
        this.replayer = Objects.requireNonNull(replayer, "replayer");
        this.executor = Objects.requireNonNull(executor, "executor");
        this.audit = audit != null ? audit : PromptVersionAudit.none();
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /** Whether trials can be run for the prompt: only the security decision has sealed decisions (plan 3.11). */
    public static boolean offeredFor(String prompt) {
        return SecurityDecisionPromptDocument.PROMPT.equals(prompt);
    }

    /**
     * Starts a trial of the candidate against the reference with the latest sealed decisions, as many as there are up
     * to the count; returns its id.
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
        List<Sealed> sealed = latestSealed(scopeName, count);
        if (sealed.isEmpty()) {
            throw new RefusedException(Refusal.NO_SEALED_DECISIONS);
        }
        long id = insertTrial(scopeName, prompt, candidate, reference, count, sealed.size(), actor);
        audit.record(PromptVersionAudit.TRIAL_STARTED, scopeName, prompt, PromptVersionNames.name(candidate), actor,
                PromptVersionNames.name(reference) + " " + sealed.size() + "/" + count);
        try {
            executor.execute(() -> run(id, actor, candidate, reference, sealed));
        }
        catch (RejectedExecutionException closed) {
            finish(id, FAILED, "The trial could not be run: the service is closing");
        }
        return id;
    }

    /** Cancels a trial that has not finished; returns whether it was. */
    public boolean cancel(long id, String actor) {
        Optional<Trial> trial = find(id);
        if (trial.isEmpty() || !(QUEUED.equals(trial.get().status()) || RUNNING.equals(trial.get().status()))) {
            return false;
        }
        cancelled.add(id);
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
                + " format_error, decision_ms, answer_tokens, reason from ctxa_prompt_version_trial_case where trial_id = ?"
                + " order by id", CASE_ROW, id);
        return Optional.of(result(trial.get(), cases));
    }

    /**
     * A trial a server left unfinished when it stopped is marked failed when the service starts again: its thread is
     * gone. Returns how many were.
     */
    public int closeInterrupted() {
        int updated = jdbc.get().update("update ctxa_prompt_version_trial set status = ?, finished_at = ?, failure = ?"
                + " where status in (?, ?)", FAILED, Timestamp.from(clock.instant()),
                "The server stopped before the trial finished", QUEUED, RUNNING);
        if (updated > 0) {
            log.warn("[PromptVersionTrial] {} trials left unfinished by a stop were marked failed", updated);
        }
        return updated;
    }

    @Override
    public void close() {
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

    /** A replay of the sealed decision replay as the trial keeps it: its action, reason, format, time and tokens. */
    public static Replayed replayed(SealedDecisionReplayService.Result result) {
        Map<String, Object> telemetry = result.telemetry() != null ? result.telemetry() : Map.of();
        Object tokens = telemetry.get("actualCompletionTokens");
        return new Replayed(result.action(), result.reason(),
                formatError(result.action(), result.failure(), telemetry), result.elapsedMs(),
                tokens instanceof Number number && number.intValue() > 0 ? number.intValue() : null, result.failure());
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

    private void run(long id, String actor, int candidate, int reference, List<Sealed> sealed) {
        try {
            if (cancelled.contains(id) || jdbc.get().update("update ctxa_prompt_version_trial set status = ?,"
                    + " started_at = ? where id = ? and status = ?", RUNNING, Timestamp.from(clock.instant()), id,
                    QUEUED) != 1) {
                return;
            }
            for (Sealed decision : sealed) {
                for (int number : List.of(candidate, reference)) {
                    if (cancelled.contains(id) || Thread.currentThread().isInterrupted()) {
                        return;
                    }
                    Replayed replayed = behindTheDecisions(actor, decision.packageId(), PromptVersionNames.name(number));
                    insertCase(id, decision, number, replayed);
                }
            }
            finish(id, DONE, null);
        }
        catch (RuntimeException failure) {
            log.error("[PromptVersionTrial] Trial {} failed", id, failure);
            finish(id, FAILED, failure.getClass().getSimpleName() + ": " + failure.getMessage());
        }
        finally {
            cancelled.remove(id);
        }
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

    private List<Sealed> latestSealed(String scope, int count) {
        boolean platform = PromptVersionService.PLATFORM_SCOPE.equals(scope);
        List<Object> arguments = new ArrayList<>();
        if (!platform) {
            arguments.add(scope);
        }
        arguments.add(count);
        List<Sealed> found = jdbc.get().query("select p.package_id, p.correlation_id from ctxa_sealed_evidence_package p"
                + " where p.seal_state = 'SEALED' and coalesce(contexa_safe_jsonb(p.decision_json) ->>"
                + " 'decisionAppliedStage', '') <> 'SHADOW'" + (platform ? "" : " and p.tenant_id = ?")
                + " order by p.captured_at desc limit ?", (rs, row) -> new Sealed(rs.getString(1), rs.getString(2),
                null), arguments.toArray());
        List<Sealed> withObservation = new ArrayList<>();
        for (Sealed decision : found) {
            String observation = decision.requestId() == null ? null : jdbc.get().query("select observation_id from"
                    + " ctxa_ai_security_decision_observation where request_id = ? order by created_at desc limit 1",
                    (rs, row) -> rs.getString(1), decision.requestId()).stream().findFirst().orElse(null);
            withObservation.add(new Sealed(decision.packageId(), decision.requestId(), observation));
        }
        return withObservation;
    }

    private long insertTrial(String scope, String prompt, int candidate, int reference, int requested, int actual,
                             String actor) {
        KeyHolder key = new GeneratedKeyHolder();
        jdbc.get().update(connection -> {
            PreparedStatement statement = connection.prepareStatement("insert into ctxa_prompt_version_trial"
                    + " (registry_scope, prompt_key, candidate_number, reference_number, requested_count, actual_count,"
                    + " status, created_by, created_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, scope);
            statement.setString(2, prompt);
            statement.setInt(3, candidate);
            statement.setInt(4, reference);
            statement.setInt(5, requested);
            statement.setInt(6, actual);
            statement.setString(7, QUEUED);
            statement.setString(8, actor != null ? actor : "system");
            statement.setTimestamp(9, Timestamp.from(clock.instant()));
            return statement;
        }, key);
        return ((Number) Objects.requireNonNull(key.getKeys()).get("id")).longValue();
    }

    private void insertCase(long id, Sealed decision, int number, Replayed replayed) {
        jdbc.get().update("insert into ctxa_prompt_version_trial_case (trial_id, sealed_package_id, observation_id,"
                + " version_number, action, format_error, decision_ms, answer_tokens, reason) values"
                + " (?, ?, ?, ?, ?, ?, ?, ?, ?)", id, decision.packageId(), decision.observationId(), number,
                replayed.action(), replayed.formatError(), replayed.decisionMs(), replayed.answerTokens(),
                truncate(replayed.reason() != null ? replayed.reason() : replayed.failure(), 2000));
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
        ACTIONS.forEach(action -> actions.put(action, 0L));
        long answered = 0;
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
                counted > 0 ? Math.round((double) totalTokens / counted) : null, actions);
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
            rs.getString("reason"));

    private static Instant instant(Timestamp timestamp) {
        return timestamp != null ? timestamp.toInstant() : null;
    }
}
