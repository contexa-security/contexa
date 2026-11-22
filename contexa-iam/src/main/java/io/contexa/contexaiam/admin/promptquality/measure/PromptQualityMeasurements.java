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
package io.contexa.contexaiam.admin.promptquality.measure;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionCitationCheck;
import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityActionBasis;
import io.contexa.contexacore.std.components.prompt.quality.QualityAnswer;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityClosingRules;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurement;
import io.contexa.contexacore.std.components.prompt.quality.QualityScore;
import io.contexa.contexacore.std.components.prompt.quality.QualityScorer;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexacore.std.llm.gate.ModelCallTimer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCaseSealedForm;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * The measurements of the prompt quality (quality plan 3.3): a prompt version, under the model setting of the server,
 * on a published case set, each case run a number of times. Every answer is the replay of the case's input built in
 * memory in the sealed form, with its baselines and its context format, through the engine's pipeline; after a first
 * answer of ESCALATE the second pass is asked with the server's second-layer model, and the closing rules give the
 * final action from the server's settings (the overload protection is not replayed, and the result says so).
 *
 * <p>A measurement waits in the line of this server with the trials of prompt versions, and its model calls wait
 * behind the decisions at the model server's gate, as many at once as set. One server at a time runs measurements:
 * it holds a lock of the database and keeps a heartbeat on the measurement; a server that stops lets both run out,
 * and any server resumes the measurement where it stopped, case by case and run by run. A cancellation is written to
 * the database, so the server running the measurement stops at its next answer.</p>
 *
 * <p>An answer kept for the same case content, version, model setting and run is used again, not measured again. A
 * model server too busy to answer is asked again; an answer that still did not come, or a replay that could not read
 * its case, is kept as a failure of the measurement, which the scoring leaves out as incomplete. The model calls a
 * measurement makes are counted, and it stops at the limit set. Nothing a measurement does is a decision: no decision
 * record, seal, outcome or learning is written.</p>
 */
public class PromptQualityMeasurements implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(PromptQualityMeasurements.class);

    public static final String QUEUED = "QUEUED";
    public static final String RUNNING = "RUNNING";
    public static final String DONE = "DONE";
    public static final String FAILED = "FAILED";
    public static final String CANCELLED = "CANCELLED";
    /** The name of the lock that lets one server at a time run measurements. */
    public static final String LOCK_NAME = "contexaPromptQualityMeasurement";
    /** The most runs a measurement may ask for. */
    public static final int MAX_REPEATS = 10;
    /** The model calls one answer may take at most: the first pass and its retry, the second pass and its retry. */
    public static final int MAX_CALLS_PER_ATTEMPT = 4;
    /** The longest one replay may take: a call and its retry, each within the first layer's limit, then the second. */
    private static final long REPLAY_LIMIT_MS = TimeUnit.MINUTES.toMillis(12);

    /**
     * How measurements run.
     *
     * @param repeats     how many times each case is run when the start asks for no number
     * @param concurrency how many replays run at once
     * @param retries     how many more times a replay the model server did not answer is asked
     * @param retryDelay  the wait before the first retry; it grows with each
     * @param callLimit   the most model calls one measurement makes; 0 for no limit
     * @param heartbeat   how often the running server renews its lock and heartbeat, and the others look for work
     */
    public record Settings(int repeats, int concurrency, int retries, Duration retryDelay, int callLimit,
                           Duration heartbeat) {

        public static final Settings DEFAULTS = new Settings(3, 1, 2, Duration.ofSeconds(15), 3000,
                Duration.ofSeconds(30));

        public Settings {
            if (repeats < 1 || repeats > MAX_REPEATS) {
                throw new IllegalArgumentException("A measurement runs each case from 1 to " + MAX_REPEATS + " times");
            }
            if (concurrency < 1) {
                throw new IllegalArgumentException("A measurement runs at least one replay at a time");
            }
            if (retries < 0) {
                throw new IllegalArgumentException("The retries of a measurement are not negative");
            }
            if (callLimit < 0) {
                throw new IllegalArgumentException("The call limit of a measurement is not negative");
            }
            retryDelay = retryDelay != null && !retryDelay.isNegative() ? retryDelay : Duration.ZERO;
            if (heartbeat == null || heartbeat.compareTo(Duration.ofMillis(100)) < 0) {
                throw new IllegalArgumentException("The heartbeat of a measurement is at least 100 ms");
            }
        }

        /** How long the lock is held without a heartbeat: four of them, so one missed renewal loses nothing. */
        public Duration lockFor() {
            return heartbeat.multipliedBy(4);
        }
    }

    /** Why a measurement cannot start. */
    public enum Refusal {
        /** Only the security decision has labelled cases. */
        PROMPT,
        /** There is no such version, or it is hidden. */
        VERSION,
        /** No case set is published, or the one named is not of the prompt and scope. */
        NO_CASE_SET,
        /** The number of runs is not one a measurement takes. */
        REPEATS,
        /** The model calls the measurement makes at least exceed the limit. */
        CALL_LIMIT,
        /** The same measurement has not finished. */
        RUNNING
    }

    /** A measurement that cannot start, and why. */
    public static class RefusedException extends RuntimeException {

        private final Refusal refusal;

        public RefusedException(Refusal refusal, String message) {
            super(message);
            this.refusal = refusal;
        }

        public Refusal refusal() {
            return refusal;
        }
    }

    /**
     * Replays a case built in the sealed form with a version: the sealed decision replay of a decision given in
     * memory, with the baselines given and the second pass asked with the server's second-layer model after an
     * ESCALATE.
     */
    @FunctionalInterface
    public interface Replayer {

        SealedDecisionReplayService.Result replay(String actor, SealedEvidencePackage given, String contextFormatVersion,
                                                  String version, @Nullable JsonNode userBaseline,
                                                  @Nullable JsonNode organizationBaseline);
    }

    /**
     * What a measurement takes before it starts: the answers it needs, how many of them are kept already and used
     * again, and the model calls the others make, at least one each and at most {@link #MAX_CALLS_PER_ATTEMPT} for
     * each attempt.
     */
    public record Estimate(int cases, int repeats, int answers, int reusable, int replays, int minimumCalls,
                           int maximumCalls, int callLimit) {

        /** Whether the calls the measurement makes at least are within the limit. */
        public boolean withinLimit() {
            return callLimit == 0 || minimumCalls <= callLimit;
        }
    }

    /** A measurement as its row keeps it, with how many answers it has. */
    public record Measure(long id, String scope, String prompt, int versionNumber, String versionContentHash,
                          long caseSetId, String caseSetVersion, int repeats, String settingsHash,
                          @Nullable String modelSetting, String closingRules, String status, @Nullable String failure,
                          int plannedAnswers, int reusableAnswers, int expectedMinCalls, int expectedMaxCalls,
                          int callLimit, int modelCalls, @Nullable String runnerId, @Nullable Instant heartbeatAt,
                          String createdBy, Instant createdAt, @Nullable Instant startedAt,
                          @Nullable Instant finishedAt, int answered) {

        public String versionName() {
            return PromptVersionNames.name(versionNumber);
        }

        /** The model setting the measurement names: the one it found, or while it runs the settings it started with. */
        public String modelSettingOrSettings() {
            return modelSetting != null ? modelSetting : QualityModelSetting.fingerprint(settingsHash, List.of());
        }
    }

    /**
     * What a measurement found: its answers as the scoring reads them, and the metrics on both bases over the cases of
     * its set that can be read now.
     *
     * @param missingCases the cases of the set that cannot be read any more, and so are not scored
     */
    public record Result(Measure measure, QualityMeasurement measurement, QualityScore firstAnswer,
                         QualityScore finalAction, List<String> missingCases) {
    }

    private record Work(QualityCase item, int run) {
    }

    private final Supplier<JdbcTemplate> jdbc;
    private final PromptVersionService versions;
    private final PromptQualityCases cases;
    private final Replayer replayer;
    private final PromptQualityRunLine line;
    private final QualityMeasureLock lock;
    private final Supplier<Map<String, String>> modelSettings;
    private final Supplier<QualityClosingRules> closingRules;
    private final Settings settings;
    private final ObjectMapper json;
    private final Clock clock;
    private final String serverId;
    private final ExecutorService workers;
    private final ScheduledExecutorService timer;
    private final AtomicBoolean drainWaiting = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile ScheduledFuture<?> sweep;

    /**
     * @param line          the line of this server the trials wait in too
     * @param lock          the lock the servers of the database share, or the lock of this server alone
     * @param modelSettings the server settings that change an answer ({@link QualityModelSetting#settings})
     * @param closingRules  the closing rules the server's settings give
     * @param serverId      the name of this server in the heartbeat of a measurement it runs
     */
    public PromptQualityMeasurements(Supplier<JdbcTemplate> jdbc, PromptVersionService versions,
                                     PromptQualityCases cases, Replayer replayer, PromptQualityRunLine line,
                                     QualityMeasureLock lock, Supplier<Map<String, String>> modelSettings,
                                     Supplier<QualityClosingRules> closingRules, Settings settings, ObjectMapper json,
                                     @Nullable Clock clock, String serverId) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.versions = Objects.requireNonNull(versions, "versions");
        this.cases = Objects.requireNonNull(cases, "cases");
        this.replayer = Objects.requireNonNull(replayer, "replayer");
        this.line = Objects.requireNonNull(line, "line");
        this.lock = Objects.requireNonNull(lock, "lock");
        this.modelSettings = Objects.requireNonNull(modelSettings, "modelSettings");
        this.closingRules = closingRules != null ? closingRules : () -> QualityClosingRules.DEFAULTS;
        this.settings = settings != null ? settings : Settings.DEFAULTS;
        this.json = Objects.requireNonNull(json, "json");
        this.clock = clock != null ? clock : Clock.systemUTC();
        this.serverId = serverId != null && !serverId.isBlank() ? serverId : "server";
        AtomicInteger threads = new AtomicInteger();
        this.workers = Executors.newFixedThreadPool(this.settings.concurrency(), work -> {
            Thread thread = new Thread(work, "contexa-prompt-quality-measure-" + threads.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
        this.timer = Executors.newSingleThreadScheduledExecutor(work -> {
            Thread thread = new Thread(work, "contexa-prompt-quality-heartbeat");
            thread.setDaemon(true);
            return thread;
        });
    }

    public Settings settings() {
        return settings;
    }

    /**
     * Quality plan 3.4: the hash of the server settings that change an answer, as this server runs now; a measurement
     * taken under another hash is stale here.
     */
    public String settingsHash() {
        return QualityModelSetting.hash(Map.copyOf(modelSettings.get()));
    }

    /**
     * Looks for measurements to run, or to resume after a server stopped, at every heartbeat from now on: a
     * measurement queued on a server that is busy, or that stopped, is run by whichever server takes the lock.
     */
    public void startLookingForWork() {
        if (sweep == null && !closed.get()) {
            long every = settings.heartbeat().toMillis();
            sweep = timer.scheduleWithFixedDelay(this::lookForWork, every, every, TimeUnit.MILLISECONDS);
        }
    }

    // ----- starting, cancelling, reading -----

    /**
     * What measuring the version on the published set would take: the answers it needs, those kept already for the
     * same case content, version, model setting and run, and the model calls of the others.
     *
     * @param caseSetId the published set, or null for the latest one
     * @param repeats   the runs, or null for the set number
     * @throws RefusedException when the version, the set or the runs are none a measurement takes
     */
    public Estimate estimate(String scope, String prompt, int version, @Nullable Long caseSetId,
                             @Nullable Integer repeats) {
        Planned planned = plan(scope, prompt, version, caseSetId, repeats);
        return planned.estimate();
    }

    private record Planned(String scope, PromptVersionRecord version, PromptQualityCases.PublishedSet set,
                           List<QualityCase> cases, int repeats, Map<String, String> settings, String settingsHash,
                           Estimate estimate) {
    }

    private Planned plan(String scope, String prompt, int version, @Nullable Long caseSetId,
                         @Nullable Integer repeats) {
        if (!PromptQualityCases.offeredFor(prompt)) {
            throw new RefusedException(Refusal.PROMPT, "Only the security decision has labelled cases");
        }
        String scopeName = scopeOf(scope);
        PromptVersionRecord record = versions.find(scopeName, prompt, version).filter(found -> !found.hidden())
                .orElseThrow(() -> new RefusedException(Refusal.VERSION, "There is no version " + version));
        int runs = repeats != null ? repeats : settings.repeats();
        if (runs < 1 || runs > MAX_REPEATS) {
            throw new RefusedException(Refusal.REPEATS, "A measurement runs each case from 1 to " + MAX_REPEATS
                    + " times");
        }
        PromptQualityCases.PublishedSet set = (caseSetId != null ? cases.published(caseSetId)
                : cases.latestPublished(scopeName, prompt))
                .filter(found -> found.scope().equals(scopeName) && found.prompt().equals(prompt))
                .orElseThrow(() -> new RefusedException(Refusal.NO_CASE_SET, "No case set is published"));
        List<QualityCase> items = cases.read(set).cases().cases();
        Map<String, String> now = Map.copyOf(modelSettings.get());
        String hash = QualityModelSetting.hash(now);
        int answers = items.size() * runs;
        int reusable = 0;
        for (QualityCase item : items) {
            Integer kept = jdbc.get().queryForObject("select count(distinct run_number) from"
                    + " ctxa_prompt_version_measure_answer where registry_scope = ? and case_content_hash = ? and"
                    + " version_number = ? and version_content_hash = ? and settings_hash = ? and run_number <= ?"
                    + " and measurement_failed = false", Integer.class, scopeName, item.contentHash(),
                    record.number(), record.contentHash(), hash, runs);
            reusable += kept != null ? kept : 0;
        }
        int replays = answers - reusable;
        Estimate estimate = new Estimate(items.size(), runs, answers, reusable, replays, replays,
                replays * MAX_CALLS_PER_ATTEMPT * (1 + settings.retries()), settings.callLimit());
        return new Planned(scopeName, record, set, items, runs, now, hash, estimate);
    }

    /**
     * Starts measuring the version on the published set; returns the measurement's id. It waits in this server's
     * line, or is run by the server that holds the lock.
     *
     * @param caseSetId the published set, or null for the latest one
     * @param repeats   the runs, or null for the set number
     * @throws RefusedException when it cannot start
     */
    public long start(String scope, String prompt, int version, @Nullable Long caseSetId, @Nullable Integer repeats,
                      String actor) {
        Planned planned = plan(scope, prompt, version, caseSetId, repeats);
        Estimate estimate = planned.estimate();
        if (!estimate.withinLimit()) {
            throw new RefusedException(Refusal.CALL_LIMIT, "The measurement makes at least "
                    + estimate.minimumCalls() + " model calls, more than the limit of " + estimate.callLimit());
        }
        Integer open = jdbc.get().queryForObject("select count(*) from ctxa_prompt_version_measure where"
                + " registry_scope = ? and prompt_key = ? and version_number = ? and case_set_id = ? and repeats = ?"
                + " and status in (?, ?)", Integer.class, planned.scope(), prompt, version, planned.set().id(),
                planned.repeats(), QUEUED, RUNNING);
        if (open != null && open > 0) {
            throw new RefusedException(Refusal.RUNNING, "The same measurement has not finished");
        }
        QualityClosingRules rules = closingRules.get();
        Long id = jdbc.get().queryForObject("insert into ctxa_prompt_version_measure (registry_scope, prompt_key,"
                + " version_number, version_content_hash, case_set_id, case_set_version, repeats, settings_hash,"
                + " settings, closing_rules, status, planned_answers, reusable_answers, expected_min_calls,"
                + " expected_max_calls, call_limit, created_by, created_at) values"
                + " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) returning id", Long.class, planned.scope(),
                prompt, version, planned.version().contentHash(), planned.set().id(), planned.set().version(),
                planned.repeats(), planned.settingsHash(), write(planned.settings()), describe(rules), QUEUED,
                estimate.answers(), estimate.reusable(), estimate.minimumCalls(), estimate.maximumCalls(),
                estimate.callLimit(), actorOf(actor), Timestamp.from(clock.instant()));
        log.info("[PromptQualityMeasure] Measurement {} of {} {} on case set {} queued: {} answers, {} kept already",
                id, prompt, PromptVersionNames.name(version), planned.set().version(), estimate.answers(),
                estimate.reusable());
        submitDrain();
        return Objects.requireNonNull(id, "id");
    }

    /**
     * Cancels a measurement that has not finished, on whichever server runs it: the server stops at its next answer.
     * The answers taken are kept.
     */
    public boolean cancel(long id, String actor) {
        return jdbc.get().update("update ctxa_prompt_version_measure set status = ?, finished_at = ?, cancelled_by = ?"
                + " where id = ? and status in (?, ?)", CANCELLED, Timestamp.from(clock.instant()), actorOf(actor), id,
                QUEUED, RUNNING) == 1;
    }

    public Optional<Measure> find(long id) {
        return jdbc.get().query(MEASURE_SQL + " where m.id = ?", MEASURE_ROW, id).stream().findFirst();
    }

    /** The latest measurements of the version, newest first. */
    public List<Measure> recent(String scope, String prompt, int version, int limit) {
        return jdbc.get().query(MEASURE_SQL + " where m.registry_scope = ? and m.prompt_key = ? and m.version_number = ?"
                + " order by m.created_at desc, m.id desc limit ?", MEASURE_ROW, scopeOf(scope), prompt, version,
                Math.max(1, limit));
    }

    /** Quality plan 3.8: how many measurements the prompt has in the scope, of every version and state. */
    public long count(String scope, String prompt) {
        Long count = jdbc.get().queryForObject("select count(*) from ctxa_prompt_version_measure where registry_scope = ?"
                + " and prompt_key = ?", Long.class, scopeOf(scope), prompt);
        return count != null ? count : 0L;
    }

    /**
     * Quality plan 3.8: the measurements of the prompt in the scope, of every version and state, newest first, a page
     * of them for the list of the screen.
     */
    public List<Measure> list(String scope, String prompt, int offset, int limit) {
        return jdbc.get().query(MEASURE_SQL + " where m.registry_scope = ? and m.prompt_key = ?"
                + " order by m.created_at desc, m.id desc offset ? limit ?", MEASURE_ROW, scopeOf(scope), prompt,
                Math.max(0, offset), Math.max(1, limit));
    }

    /** Quality plan 3.8: the settings of this server that change an answer, by their stable names, as it runs now. */
    public Map<String, String> modelSettings() {
        return Map.copyOf(modelSettings.get());
    }

    /**
     * One answer to a case in a measurement as the screens show it beside the other version's.
     *
     * @param citationFindings the facts the answer cited and what each came to, as kept (JSON); null when not checked
     */
    public record CaseAnswer(int run, @Nullable QualityAction firstAction, @Nullable QualityAction finalAction,
                             boolean measurementFailed, @Nullable String citationFindings) {
    }

    /** Quality plan 3.8: the answers to the case in the measurement, run by run. */
    public List<CaseAnswer> caseAnswers(long measureId, String caseKey) {
        return jdbc.get().query("select run_number, first_action, final_action, measurement_failed, citation_findings"
                + " from ctxa_prompt_version_measure_answer where measure_id = ? and case_key = ? order by run_number",
                (rs, row) -> new CaseAnswer(rs.getInt(1), QualityAction.parse(rs.getString(2)),
                        QualityAction.parse(rs.getString(3)), rs.getBoolean(4), rs.getString(5)), measureId, caseKey);
    }

    /** The measurements that answered a case, with the answers to it in each. */
    public record CaseHistory(Measure measure, List<QualityAnswer> answers) {
    }

    /**
     * Quality plan 3.2, 3.8: the latest measurements of the prompt in the scope that answered the case, newest first,
     * each with its answers to the case, for the history of the case and what a change of its answer did.
     */
    public List<CaseHistory> caseHistory(String scope, String prompt, String caseKey, int limit) {
        List<Measure> measures = jdbc.get().query(MEASURE_SQL + " where m.registry_scope = ? and m.prompt_key = ? and"
                + " exists (select 1 from ctxa_prompt_version_measure_answer a where a.measure_id = m.id and"
                + " a.case_key = ?) order by m.created_at desc, m.id desc limit ?", MEASURE_ROW, scopeOf(scope), prompt,
                caseKey, Math.max(1, limit));
        List<CaseHistory> history = new ArrayList<>();
        for (Measure measure : measures) {
            history.add(new CaseHistory(measure, jdbc.get().query("select case_key, run_number, first_action,"
                    + " final_action, reasked, decided_without_model, cited_facts, accurate_cited_facts, decision_ms,"
                    + " answer_tokens, measurement_failed, failure_reason from ctxa_prompt_version_measure_answer where"
                    + " measure_id = ? and case_key = ? order by run_number", ANSWER_ROW, measure.id(), caseKey)));
        }
        return history;
    }

    /** The answers of the measurement as the scoring reads them, in the order they were kept. */
    public List<QualityAnswer> answers(long id) {
        return jdbc.get().query("select case_key, run_number, first_action, final_action, reasked, decided_without_model,"
                + " cited_facts, accurate_cited_facts, decision_ms, answer_tokens, measurement_failed, failure_reason"
                + " from ctxa_prompt_version_measure_answer where measure_id = ? order by id", ANSWER_ROW, id);
    }

    /** The measurement, its answers and its metrics on both bases. */
    public Optional<Result> result(long id) {
        Optional<Measure> found = find(id);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        Measure measure = found.get();
        PromptQualityCases.PublishedSet set = cases.published(measure.caseSetId()).orElseThrow();
        PromptQualityCases.ReadSet read = cases.read(set);
        List<QualityAnswer> answers = answers(id);
        QualityMeasurement measurement = new QualityMeasurement(measure.versionName(),
                measure.modelSettingOrSettings(), measure.caseSetVersion(), measure.repeats(), answers);
        List<QualityCase> items = read.cases().cases();
        return Optional.of(new Result(measure, measurement,
                QualityScorer.score(items, answers, QualityActionBasis.FIRST_ANSWER),
                QualityScorer.score(items, answers, QualityActionBasis.FINAL), read.missing()));
    }

    @Override
    public void close() {
        closed.set(true);
        timer.shutdownNow();
        workers.shutdownNow();
    }

    // ----- the run -----

    private void lookForWork() {
        try {
            Integer waiting = jdbc.get().queryForObject("select count(*) from ctxa_prompt_version_measure where"
                    + " status = ? or (status = ? and (heartbeat_at is null or heartbeat_at < ?))", Integer.class,
                    QUEUED, RUNNING, Timestamp.from(clock.instant().minus(settings.lockFor())));
            if (waiting != null && waiting > 0) {
                submitDrain();
            }
        }
        catch (RuntimeException failure) {
            log.error("[PromptQualityMeasure] Looking for measurements to run failed", failure);
        }
    }

    private void submitDrain() {
        if (closed.get() || !drainWaiting.compareAndSet(false, true)) {
            return;
        }
        try {
            line.executor().execute(() -> {
                drainWaiting.set(false);
                drain();
            });
        }
        catch (RejectedExecutionException closing) {
            drainWaiting.set(false);
            log.info("[PromptQualityMeasure] The line is closing; the measurements wait for another server");
        }
    }

    /** Runs the measurements that wait, while this server holds the lock. */
    void drain() {
        if (closed.get()) {
            return;
        }
        Optional<QualityMeasureLock.Held> held;
        try {
            held = lock.acquire(settings.lockFor());
        }
        catch (RuntimeException failure) {
            log.error("[PromptQualityMeasure] The lock of the measurements could not be taken", failure);
            return;
        }
        if (held.isEmpty()) {
            log.debug("[PromptQualityMeasure] Another server runs the measurements");
            return;
        }
        try {
            Set<Long> tried = new HashSet<>();
            while (!closed.get() && !Thread.currentThread().isInterrupted()) {
                Optional<Measure> next = next(tried);
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

    /**
     * The next measurement to run: one this server left, or one whose server's heartbeat ran out, before the ones
     * queued, the oldest first.
     */
    private Optional<Measure> next(Set<Long> tried) {
        List<Measure> waiting = jdbc.get().query(MEASURE_SQL + " where m.status = ? and (m.runner_id = ? or"
                + " m.heartbeat_at is null or m.heartbeat_at < ?) or m.status = ? order by case when m.status = ?"
                + " then 0 else 1 end, m.created_at, m.id limit 20", MEASURE_ROW, RUNNING, serverId,
                Timestamp.from(clock.instant().minus(settings.lockFor())), QUEUED, RUNNING);
        return waiting.stream().filter(measure -> !tried.contains(measure.id())).findFirst();
    }

    /** What stops a running measurement before its last answer. */
    private static final class Stop {

        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final AtomicBoolean lockLost = new AtomicBoolean();
        private final AtomicBoolean limitReached = new AtomicBoolean();

        boolean any() {
            return cancelled.get() || lockLost.get() || limitReached.get();
        }
    }

    /** Runs the measurement; returns whether the lock is still held. */
    private boolean run(Measure measure, QualityMeasureLock.Held held) {
        long id = measure.id();
        int claimed = jdbc.get().update("update ctxa_prompt_version_measure set status = ?, runner_id = ?,"
                + " heartbeat_at = ?, started_at = coalesce(started_at, ?) where id = ? and status in (?, ?)", RUNNING,
                serverId, Timestamp.from(clock.instant()), Timestamp.from(clock.instant()), id, QUEUED, RUNNING);
        if (claimed != 1) {
            return true;
        }
        Stop stop = new Stop();
        AtomicInteger calls = new AtomicInteger(measure.modelCalls());
        ScheduledFuture<?> heartbeat = timer.scheduleAtFixedRate(() -> beat(id, held, stop),
                settings.heartbeat().toMillis(), settings.heartbeat().toMillis(), TimeUnit.MILLISECONDS);
        try {
            Map<String, String> now = Map.copyOf(modelSettings.get());
            if (!QualityModelSetting.hash(now).equals(measure.settingsHash())) {
                // The answers of one measurement are of one model setting; a server set otherwise does not go on.
                finish(id, FAILED, "MODEL_SETTINGS_CHANGED: the server's settings that change an answer are not the"
                        + " ones the measurement started with: " + write(now));
                return true;
            }
            PromptQualityCases.PublishedSet set = cases.published(measure.caseSetId()).orElseThrow(() ->
                    new IllegalStateException("The case set " + measure.caseSetVersion() + " is gone"));
            List<QualityCase> items = cases.read(set).cases().cases();
            if (items.isEmpty()) {
                finish(id, FAILED, "NO_CASES: no case of the set can be read");
                return true;
            }
            log.info("[PromptQualityMeasure] Measurement {} runs on {}: {} cases, {} runs", id, serverId,
                    items.size(), measure.repeats());
            Set<String> done = new HashSet<>(jdbc.get().queryForList("select case_key || '#' || run_number from"
                    + " ctxa_prompt_version_measure_answer where measure_id = ?", String.class, id));
            List<Work> work = new ArrayList<>();
            for (int run = 1; run <= measure.repeats(); run++) {
                for (QualityCase item : items) {
                    if (!done.contains(item.key() + "#" + run)) {
                        work.add(new Work(item, run));
                    }
                }
            }
            Semaphore slots = new Semaphore(settings.concurrency());
            List<Future<?>> running = new ArrayList<>();
            for (Work next : work) {
                if (stop.any() || closed.get()) {
                    break;
                }
                if (reuse(measure, next)) {
                    continue;
                }
                if (settings.callLimit() > 0 && calls.get() >= settings.callLimit()) {
                    stop.limitReached.set(true);
                    break;
                }
                slots.acquire();
                if (stop.any() || closed.get()) {
                    slots.release();
                    break;
                }
                running.add(workers.submit(() -> {
                    try {
                        answer(measure, next, stop, calls);
                    }
                    finally {
                        slots.release();
                    }
                }));
            }
            for (Future<?> one : running) {
                one.get();
            }
            if (closed.get() || stop.lockLost.get()) {
                // Left as it is: another server resumes it once the lock and the heartbeat run out.
                log.warn("[PromptQualityMeasure] Measurement {} stopped on {} before its end; it is resumed later", id,
                        serverId);
                return !stop.lockLost.get();
            }
            if (stop.cancelled.get() || CANCELLED.equals(status(id))) {
                log.info("[PromptQualityMeasure] Measurement {} was cancelled", id);
                return true;
            }
            if (stop.limitReached.get() && answered(id) < measure.plannedAnswers()) {
                finish(id, FAILED, "CALL_LIMIT_REACHED: " + calls.get() + " model calls, the limit is "
                        + settings.callLimit());
                return true;
            }
            finishDone(id, measure.settingsHash());
            return true;
        }
        catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
        catch (ExecutionException | RuntimeException failure) {
            Throwable cause = failure instanceof ExecutionException && failure.getCause() != null
                    ? failure.getCause() : failure;
            log.error("[PromptQualityMeasure] Measurement {} failed", id, cause);
            finish(id, FAILED, cause.getClass().getSimpleName() + ": " + cause.getMessage());
            return true;
        }
        finally {
            heartbeat.cancel(false);
        }
    }

    /** The heartbeat of a running measurement: the lock and the row renewed, and a cancellation read. */
    private void beat(long id, QualityMeasureLock.Held held, Stop stop) {
        try {
            if (!held.extend(settings.lockFor())) {
                stop.lockLost.set(true);
                log.warn("[PromptQualityMeasure] The lock of measurement {} ran out on {}; it stops here", id,
                        serverId);
                return;
            }
            jdbc.get().update("update ctxa_prompt_version_measure set heartbeat_at = ? where id = ? and runner_id = ?",
                    Timestamp.from(clock.instant()), id, serverId);
            if (CANCELLED.equals(status(id))) {
                stop.cancelled.set(true);
            }
        }
        catch (RuntimeException failure) {
            log.error("[PromptQualityMeasure] The heartbeat of measurement {} failed", id, failure);
        }
    }

    /** Uses an answer kept for the same case content, version, model setting and run; returns whether there was one. */
    private boolean reuse(Measure measure, Work work) {
        int copied = jdbc.get().update("insert into ctxa_prompt_version_measure_answer (measure_id, registry_scope,"
                + " case_key, case_content_hash, version_number, version_content_hash, settings_hash, run_number,"
                + " outcome, first_action, model_action, final_action, second_pass_action, second_pass_outcome,"
                + " second_pass_failure, reasked, decided_without_model, citation_state, cited_facts, present_facts,"
                + " flagged_facts, accurate_cited_facts, citation_findings, model_calls, decision_ms, answer_tokens,"
                + " answered_model, second_pass_model, system_prompt_hash, user_prompt_hash, measurement_failed,"
                + " failure_reason, attempts, reused_from_answer_id, created_at)"
                + " select ?, a.registry_scope, ?, a.case_content_hash, a.version_number, a.version_content_hash,"
                + " a.settings_hash, a.run_number, a.outcome, a.first_action, a.model_action, a.final_action,"
                + " a.second_pass_action, a.second_pass_outcome, a.second_pass_failure, a.reasked,"
                + " a.decided_without_model, a.citation_state, a.cited_facts, a.present_facts, a.flagged_facts,"
                + " a.accurate_cited_facts, a.citation_findings, a.model_calls, a.decision_ms, a.answer_tokens,"
                + " a.answered_model, a.second_pass_model, a.system_prompt_hash, a.user_prompt_hash,"
                + " a.measurement_failed, a.failure_reason, a.attempts, coalesce(a.reused_from_answer_id, a.id), ?"
                + " from ctxa_prompt_version_measure_answer a where a.registry_scope = ? and a.case_content_hash = ?"
                + " and a.version_number = ? and a.version_content_hash = ? and a.settings_hash = ? and"
                + " a.run_number = ? and a.measurement_failed = false and a.measure_id <> ?"
                + " order by a.id limit 1 on conflict (measure_id, case_key, run_number) do nothing", measure.id(),
                work.item().key(), Timestamp.from(clock.instant()), measure.scope(), work.item().contentHash(),
                measure.versionNumber(), measure.versionContentHash(), measure.settingsHash(), work.run(),
                measure.id());
        return copied == 1;
    }

    /** One answer: the replay, asked again while the model server gave none, kept with what it found. */
    private void answer(Measure measure, Work work, Stop stop, AtomicInteger calls) {
        QualityCase item = work.item();
        SealedEvidencePackage given = QualityCaseSealedForm.sealed(item);
        SealedDecisionReplayService.Result result = null;
        int attempts = 0;
        while (true) {
            attempts++;
            result = behindTheDecisions(measure, item, given);
            calls.addAndGet(callsOf(result));
            jdbc.get().update("update ctxa_prompt_version_measure set model_calls = ?, heartbeat_at = ? where id = ?",
                    calls.get(), Timestamp.from(clock.instant()), measure.id());
            boolean busy = result.outcome() == SealedDecisionReplayService.Outcome.INFRASTRUCTURE_FAILURE
                    || secondPassBusy(result);
            if (!busy || attempts > settings.retries() || stop.any() || closed.get()
                    || (settings.callLimit() > 0 && calls.get() >= settings.callLimit())) {
                break;
            }
            if (!pause(settings.retryDelay().multipliedBy(attempts))) {
                break;
            }
        }
        keep(measure, work, result, attempts);
    }

    private SealedDecisionReplayService.Result behindTheDecisions(Measure measure, QualityCase item,
                                                                  SealedEvidencePackage given) {
        ModelCallTimer callTimer = ModelCallTimer.start(REPLAY_LIMIT_MS).behindDecisions(true);
        try {
            return callTimer.bind(() -> replayer.replay(measure.createdBy(), given,
                    item.environment().contextFormatVersion(), measure.versionName(), item.input().personalBaseline(),
                    item.input().organizationBaseline())).call();
        }
        catch (RuntimeException failure) {
            throw failure;
        }
        catch (Exception failure) {
            throw new IllegalStateException("The replay of case " + item.key() + " failed: " + failure.getMessage(),
                    failure);
        }
    }

    private void keep(Measure measure, Work work, SealedDecisionReplayService.Result result, int attempts) {
        SealedDecisionReplayService.Outcome outcome = result.outcome();
        boolean answered = outcome == SealedDecisionReplayService.Outcome.ANSWERED
                || outcome == SealedDecisionReplayService.Outcome.MODEL_ANSWER_UNUSABLE;
        SealedDecisionReplayService.SecondPass second = configuredSecondPass(result);
        boolean secondAnswered = second != null && answeredOutcome(second.outcome());
        QualityAction first = answered ? QualityAction.parse(result.action()) : null;
        QualityAction last = answered
                ? closingRules.get().finalAction(result.action(), secondAnswered, second != null ? second.action() : null)
                : null;
        SecurityDecisionCitationCheck check = result.citationCheck();
        boolean checked = check != null && check.state() == SecurityDecisionCitationCheck.State.CHECKED;
        int cited = answered && checked ? check.cited() : 0;
        int accurate = answered && checked
                ? Math.max(0, Math.min(cited, value(check.present()) - value(check.flagged()))) : 0;
        Map<String, Object> telemetry = result.telemetry() != null ? result.telemetry() : Map.of();
        String systemHash = keepPrompt(measure.scope(), result.systemPrompt());
        String userHash = keepPrompt(measure.scope(), result.userPrompt());
        String failure = answered ? null : truncate(outcome + ": " + result.failure(), 2000);
        jdbc.get().update("insert into ctxa_prompt_version_measure_answer (measure_id, registry_scope, case_key,"
                + " case_content_hash, version_number, version_content_hash, settings_hash, run_number, outcome,"
                + " first_action, model_action, final_action, second_pass_action, second_pass_outcome,"
                + " second_pass_failure, reasked, decided_without_model, citation_state, cited_facts, present_facts,"
                + " flagged_facts, accurate_cited_facts, citation_findings, model_calls, decision_ms, answer_tokens,"
                + " answered_model, second_pass_model, system_prompt_hash, user_prompt_hash, measurement_failed,"
                + " failure_reason, attempts, created_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                + " ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) on conflict (measure_id, case_key, run_number)"
                + " do nothing", measure.id(), measure.scope(), work.item().key(), work.item().contentHash(),
                measure.versionNumber(), measure.versionContentHash(), measure.settingsHash(), work.run(),
                outcome != null ? outcome.name() : null, name(first), truncate(result.modelAction(), 16), name(last),
                second != null ? truncate(second.action(), 16) : null,
                second != null && second.outcome() != null ? second.outcome().name() : null,
                second != null ? truncate(second.failure(), 512) : null,
                answered && PromptVersionTrials.askedAgainForTheContract(telemetry),
                outcome == SealedDecisionReplayService.Outcome.MODEL_ANSWER_UNUSABLE,
                check != null ? check.state().name() : null, cited, check != null ? check.present() : null,
                check != null ? check.flagged() : null, accurate,
                check != null ? write(check.findings()) : null, write(calls(result)), result.elapsedMs(),
                tokens(telemetry), truncate(model(telemetry), 256),
                second != null ? truncate(model(second.telemetry()), 256) : null, systemHash, userHash, !answered,
                failure, attempts, Timestamp.from(clock.instant()));
    }

    /** Keeps the prompt once by its content hash; returns the hash, or null for no prompt. */
    @Nullable
    private String keepPrompt(String scope, @Nullable String prompt) {
        if (prompt == null) {
            return null;
        }
        String hash = QualityModelSetting.sha256(prompt);
        jdbc.get().update("insert into ctxa_prompt_version_measure_prompt (registry_scope, prompt_hash, prompt_text,"
                + " created_at) values (?, ?, ?, ?) on conflict (registry_scope, prompt_hash) do nothing", scope, hash,
                prompt, Timestamp.from(clock.instant()));
        return hash;
    }

    private void finish(long id, String status, @Nullable String failure) {
        jdbc.get().update("update ctxa_prompt_version_measure set status = ?, finished_at = ?, failure = ? where id = ?"
                + " and status in (?, ?)", status, Timestamp.from(clock.instant()), truncate(failure, 2000), id, QUEUED,
                RUNNING);
        if (FAILED.equals(status)) {
            log.warn("[PromptQualityMeasure] Measurement {} ended without its answers: {}", id, failure);
        }
    }

    /** Ends the measurement with the model setting it found: its settings and the models that answered it. */
    private void finishDone(long id, String settingsHash) {
        List<String> models = jdbc.get().queryForList("select distinct m from (select answered_model as m from"
                + " ctxa_prompt_version_measure_answer where measure_id = ? union select second_pass_model from"
                + " ctxa_prompt_version_measure_answer where measure_id = ?) found where m is not null", String.class,
                id, id);
        String fingerprint = truncate(QualityModelSetting.fingerprint(settingsHash, models), 1024);
        int updated = jdbc.get().update("update ctxa_prompt_version_measure set status = ?, finished_at = ?,"
                + " model_setting = ? where id = ? and status = ?", DONE, Timestamp.from(clock.instant()), fingerprint,
                id, RUNNING);
        if (updated == 1) {
            log.info("[PromptQualityMeasure] Measurement {} done under {}", id, fingerprint);
        }
    }

    @Nullable
    private String status(long id) {
        return jdbc.get().query("select status from ctxa_prompt_version_measure where id = ?",
                (rs, row) -> rs.getString(1), id).stream().findFirst().orElse(null);
    }

    private int answered(long id) {
        Integer count = jdbc.get().queryForObject("select count(*) from ctxa_prompt_version_measure_answer where"
                + " measure_id = ?", Integer.class, id);
        return count != null ? count : 0;
    }

    private boolean pause(Duration wait) {
        if (wait.isZero()) {
            return true;
        }
        try {
            Thread.sleep(wait.toMillis());
            return true;
        }
        catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    // ----- reading a replay -----

    /** The second pass asked with the server's second-layer model, the one asked under no name. */
    @Nullable
    private static SealedDecisionReplayService.SecondPass configuredSecondPass(SealedDecisionReplayService.Result result) {
        if (result.secondPasses() == null) {
            return null;
        }
        return result.secondPasses().stream().filter(pass -> pass.requestedModel() == null).findFirst().orElse(null);
    }

    private static boolean secondPassBusy(SealedDecisionReplayService.Result result) {
        SealedDecisionReplayService.SecondPass second = configuredSecondPass(result);
        return second != null && second.outcome() == SealedDecisionReplayService.Outcome.INFRASTRUCTURE_FAILURE;
    }

    private static boolean answeredOutcome(@Nullable SealedDecisionReplayService.Outcome outcome) {
        return outcome == SealedDecisionReplayService.Outcome.ANSWERED
                || outcome == SealedDecisionReplayService.Outcome.MODEL_ANSWER_UNUSABLE;
    }

    /** The model calls a replay made: those it kept, and one for a pass that called the model but kept none. */
    static int callsOf(SealedDecisionReplayService.Result result) {
        int calls = passCalls(result.outcome(), result.modelCalls());
        if (result.secondPasses() != null) {
            for (SealedDecisionReplayService.SecondPass pass : result.secondPasses()) {
                calls += passCalls(pass.outcome(), pass.modelCalls());
            }
        }
        return calls;
    }

    private static int passCalls(@Nullable SealedDecisionReplayService.Outcome outcome,
                                 @Nullable List<SealedDecisionReplayService.ModelCall> kept) {
        if (kept != null && !kept.isEmpty()) {
            return kept.size();
        }
        return answeredOutcome(outcome) || outcome == SealedDecisionReplayService.Outcome.INFRASTRUCTURE_FAILURE
                ? 1 : 0;
    }

    /** The calls of each pass with their times, the first pass numbered 1 and the second 2. */
    private static List<Map<String, Object>> calls(SealedDecisionReplayService.Result result) {
        List<Map<String, Object>> calls = new ArrayList<>();
        addCalls(calls, 1, result.modelCalls());
        SealedDecisionReplayService.SecondPass second = configuredSecondPass(result);
        if (second != null) {
            addCalls(calls, 2, second.modelCalls());
        }
        return calls;
    }

    private static void addCalls(List<Map<String, Object>> calls, int pass,
                                 @Nullable List<SealedDecisionReplayService.ModelCall> kept) {
        if (kept == null) {
            return;
        }
        for (SealedDecisionReplayService.ModelCall call : kept) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("pass", pass);
            entry.put("callMs", call.callMs());
            entry.put("gateWaitMs", call.gateWaitMs());
            entry.put("timeoutMs", call.timeoutMs());
            entry.put("failed", call.failed());
            calls.add(entry);
        }
    }

    @Nullable
    private static Integer tokens(Map<String, Object> telemetry) {
        Object tokens = telemetry.get("actualCompletionTokens");
        return tokens instanceof Number number && number.intValue() > 0 ? number.intValue() : null;
    }

    /** The model that answered, as the call's telemetry names it. */
    @Nullable
    private static String model(@Nullable Map<String, Object> telemetry) {
        if (telemetry == null) {
            return null;
        }
        for (String key : List.of("runtimeModelId", "selectedModelId", "providerResponseModel")) {
            Object value = telemetry.get(key);
            if (value != null && !String.valueOf(value).isBlank()) {
                return String.valueOf(value).trim();
            }
        }
        return null;
    }

    private static String describe(QualityClosingRules rules) {
        return "ESCALATE after the second pass -> " + (rules.escalateTerminalAction() != null
                ? rules.escalateTerminalAction().name() : "ESCALATE") + "; unusable action -> "
                + QualityClosingRules.UNUSABLE_ACTION_REPLACEMENT.name() + "; "
                + QualityClosingRules.OVERLOAD_PROTECTION_LEFT_OUT;
    }

    private String write(Object value) {
        try {
            return json.writeValueAsString(value);
        }
        catch (JsonProcessingException exception) {
            throw new IllegalStateException("A value of a measurement could not be written: "
                    + exception.getOriginalMessage(), exception);
        }
    }

    private static int value(@Nullable Integer number) {
        return number != null ? number : 0;
    }

    @Nullable
    private static String name(@Nullable QualityAction action) {
        return action != null ? action.name() : null;
    }

    @Nullable
    private static String truncate(@Nullable String value, int length) {
        return value == null || value.length() <= length ? value : value.substring(0, length);
    }

    private static String scopeOf(String scope) {
        return scope != null && !scope.isBlank() ? scope.trim() : PromptVersionService.PLATFORM_SCOPE;
    }

    private static String actorOf(String actor) {
        return actor != null && !actor.isBlank() ? actor.trim() : "system";
    }

    private static final String MEASURE_SQL = "select m.id, m.registry_scope, m.prompt_key, m.version_number,"
            + " m.version_content_hash, m.case_set_id, m.case_set_version, m.repeats, m.settings_hash, m.model_setting,"
            + " m.closing_rules, m.status, m.failure, m.planned_answers, m.reusable_answers, m.expected_min_calls,"
            + " m.expected_max_calls, m.call_limit, m.model_calls, m.runner_id, m.heartbeat_at, m.created_by,"
            + " m.created_at, m.started_at, m.finished_at, (select count(*) from ctxa_prompt_version_measure_answer a"
            + " where a.measure_id = m.id) as answered from ctxa_prompt_version_measure m";

    private static final RowMapper<Measure> MEASURE_ROW = PromptQualityMeasurements::measure;

    private static final RowMapper<QualityAnswer> ANSWER_ROW = (rs, row) -> new QualityAnswer(rs.getString(1),
            rs.getInt(2), QualityAction.parse(rs.getString(3)), QualityAction.parse(rs.getString(4)), rs.getBoolean(5),
            rs.getBoolean(6), rs.getInt(7), rs.getInt(8), (Long) rs.getObject(9), (Integer) rs.getObject(10),
            rs.getBoolean(11), rs.getString(12));

    private static Measure measure(ResultSet rs, int row) throws SQLException {
        return new Measure(rs.getLong("id"), rs.getString("registry_scope"), rs.getString("prompt_key"),
                rs.getInt("version_number"), rs.getString("version_content_hash"), rs.getLong("case_set_id"),
                rs.getString("case_set_version"), rs.getInt("repeats"), rs.getString("settings_hash"),
                rs.getString("model_setting"), rs.getString("closing_rules"), rs.getString("status"),
                rs.getString("failure"), rs.getInt("planned_answers"), rs.getInt("reusable_answers"),
                rs.getInt("expected_min_calls"), rs.getInt("expected_max_calls"), rs.getInt("call_limit"),
                rs.getInt("model_calls"), rs.getString("runner_id"), instant(rs.getTimestamp("heartbeat_at")),
                rs.getString("created_by"), instant(rs.getTimestamp("created_at")),
                instant(rs.getTimestamp("started_at")), instant(rs.getTimestamp("finished_at")), rs.getInt("answered"));
    }

    @Nullable
    private static Instant instant(@Nullable Timestamp timestamp) {
        return timestamp != null ? timestamp.toInstant() : null;
    }
}
