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

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.llm.gate.ModelCallTimer;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.QualityMeasureLock;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plan 6-5 on a database with the schema of a new installation: a trial decides the latest sealed decisions again with
 * the version tried and the version it is compared with, as many as there are up to the count, behind the decisions at
 * the model server's gate; it counts the same actions, the format errors, the time and the answer length of each, lists
 * the decisions that changed, refuses what it cannot run, and can be cancelled. Quality plan 3.3: the servers of one
 * database run the trials one at a time under the lock of the measurements, and a trial a stopped server left is
 * resumed by another; quality plan 3.10: each replay keeps its final action beside its first.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptVersionTrialsPostgresTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final Instant NOW = Instant.parse("2026-11-17T09:00:00Z");
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private final List<String> audited = new CopyOnWriteArrayList<>();
    private final List<Boolean> behind = new CopyOnWriteArrayList<>();
    /** The sealed decision and the version of each replay asked, in order. */
    private final List<String> asked = new CopyOnWriteArrayList<>();
    private final List<PromptVersionTrials> servers = new CopyOnWriteArrayList<>();
    private final Map<String, PromptVersionTrials.Replayed> answers = new ConcurrentHashMap<>();
    private ExecutorService executor;
    private PromptVersionService versions;
    private PromptVersionTrials trials;
    private volatile CountDownLatch gate;
    private volatile CountDownLatch entered;

    @BeforeAll
    static void aDatabaseWithTheSchema() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        String schema = new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        try (Connection connection = database.dataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.setEscapeProcessing(false);
            statement.execute(schema);
        }
    }

    @AfterAll
    static void close() {
        if (database != null) {
            database.close();
        }
    }

    @BeforeEach
    void twoVersions() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_part, ctxa_prompt_version_trial_case, ctxa_prompt_version_trial,"
                + " ctxa_prompt_version, ctxa_prompt_governance_registry, ctxa_sealed_evidence_package,"
                + " ctxa_ai_security_decision_observation, ctxa_shedlock CASCADE");
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        versions = new PromptVersionService(() -> jdbc, SecurityDecisionPromptDocument.productReleases(), Map.of(),
                PromptVersionAudit.none(), clock);
        versions.registerProducts(null);
        versions.create(null, """
                prompt: cortex.security-decision
                basedOn: v1.0
                title: Finance closing
                system:
                  - key: how-to-judge
                    text: |
                      1. Weigh the duty roster first.
                """, PromptVersionRecord.SCREEN, null, "admin", null);
        executor = Executors.newSingleThreadExecutor();
        trials = new PromptVersionTrials(() -> jdbc, versions, replayer(), executor,
                (action, scope, prompt, version, actor, detail) -> audited.add(action + " " + version), clock);
    }

    @AfterEach
    void stop() {
        trials.close();
        servers.forEach(PromptVersionTrials::close);
    }

    /** The stand-in of the replay: the answers set for the sealed decision and version, held while a gate is set. */
    private PromptVersionTrials.Replayer replayer() {
        return (actor, packageId, version) -> {
            ModelCallTimer timer = ModelCallTimer.current();
            behind.add(timer != null && timer.behindDecisions());
            asked.add(packageId + "|" + version);
            CountDownLatch waitFor = gate;
            if (waitFor != null) {
                entered.countDown();
                try {
                    waitFor.await(10, TimeUnit.SECONDS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
            }
            return Optional.ofNullable(answers.get(packageId + "|" + version));
        };
    }

    private static QualityMeasureLock sharedLock() {
        return QualityMeasureLock.shedLock(new JdbcTemplateLockProvider(jdbc, "ctxa_shedlock"),
                PromptQualityMeasurements.LOCK_NAME, Clock.systemUTC());
    }

    /** The trials of another server of the database: its own line, the lock of the measurements, a short heartbeat. */
    private PromptVersionTrials server(String name) {
        return server(name, Executors.newSingleThreadExecutor());
    }

    private PromptVersionTrials server(String name, ExecutorService line) {
        PromptVersionTrials server = new PromptVersionTrials(() -> jdbc, versions, replayer(), line,
                PromptVersionAudit.none(), Clock.systemUTC(), sharedLock(), Duration.ofMillis(200), name);
        servers.add(server);
        return server;
    }

    /** A trial of the security decision that a server runs, with the sealed decisions it chose. */
    private static long runningTrial(String scope, String server, Instant heartbeat, String... packages) {
        return jdbc.queryForObject("insert into ctxa_prompt_version_trial (registry_scope, prompt_key,"
                + " candidate_number, reference_number, requested_count, actual_count, status, created_by, started_at,"
                + " runner_id, heartbeat_at, sealed_package_ids) values (?, ?, 2, 1, 20, ?, 'RUNNING', 'admin', ?, ?, ?,"
                + " ?) returning id", Long.class, scope, PROMPT, packages.length, Timestamp.from(Instant.now()), server,
                Timestamp.from(heartbeat), Arrays.stream(packages).map(id -> '"' + id + '"')
                        .collect(Collectors.joining(",", "[", "]")));
    }

    private static void keptReplay(long trial, String packageId, int version, String action) {
        jdbc.update("insert into ctxa_prompt_version_trial_case (trial_id, sealed_package_id, observation_id,"
                + " version_number, action, format_error, final_action) values (?, ?, ?, ?, ?, false, ?)", trial,
                packageId, "obs-" + packageId, version, action, action);
    }

    private static int count(String sql, Object... arguments) {
        Integer count = jdbc.queryForObject(sql, Integer.class, arguments);
        return count != null ? count : 0;
    }

    private static void sealed(String packageId, String requestId, String stage, int minutesAgo, String user,
                               String path) {
        jdbc.update("insert into ctxa_sealed_evidence_package (package_id, correlation_id, captured_at, seal_state,"
                + " package_hash, decision_json) values (?, ?, ?, 'SEALED', ?, ?)", packageId, requestId,
                Timestamp.from(NOW.minusSeconds(60L * minutesAgo)), "hash-" + packageId,
                stage == null ? "{\"action\":\"ALLOW\"}" : "{\"action\":\"ALLOW\",\"decisionAppliedStage\":\"" + stage + "\"}");
        if (stage == null) {
            jdbc.update("insert into ctxa_ai_security_decision_observation (observation_id, request_id, user_id,"
                    + " http_method, request_path, created_at) values (?, ?, ?, 'POST', ?, ?)", "obs-" + packageId,
                    requestId, user, path, Timestamp.from(NOW.minusSeconds(60L * minutesAgo)));
        }
    }

    private void answer(String packageId, String version, String action, boolean formatError, long ms, Integer tokens) {
        answers.put(packageId + "|" + version, new PromptVersionTrials.Replayed(action, action + " because", formatError,
                ms, tokens, action == null ? "TIMEOUT" : null));
    }

    private PromptVersionTrials.Trial awaitEnd(long id) throws InterruptedException {
        for (int i = 0; i < 200; i++) {
            PromptVersionTrials.Trial trial = trials.find(id).orElseThrow();
            if (!PromptVersionTrials.QUEUED.equals(trial.status()) && !PromptVersionTrials.RUNNING.equals(trial.status())) {
                return trial;
            }
            Thread.sleep(50);
        }
        throw new AssertionError("The trial did not end");
    }

    @Test
    void aTrialDecidesTheLatestSealedDecisionsAgainWithBothVersionsBehindTheDecisions() throws Exception {
        sealed("p1", "req-1", null, 3, "kim.dev", "/api/customers/export");
        sealed("p2", "req-2", null, 2, "lee.fin", "/api/payments");
        sealed("p3", "req-3", null, 1, "svc-report", "/api/reports/export");
        // A shadow run is no decision: it is not decided again.
        sealed("p4", "req-1", "SHADOW", 0, null, null);
        answer("p1", "v2.0", "CHALLENGE", false, 5_200L, 120);
        answer("p1", "v1.0", "ALLOW", false, 5_000L, 110);
        answer("p2", "v2.0", "ALLOW", true, 5_400L, 130);
        answer("p2", "v1.0", "ALLOW", false, 4_800L, 100);
        answer("p3", "v2.0", "BLOCK", false, 5_000L, null);
        answer("p3", "v1.0", "BLOCK", false, 5_200L, 120);

        long id = trials.start(null, PROMPT, 2, 1, 20, "admin");
        PromptVersionTrials.Trial trial = awaitEnd(id);

        assertThat(trial.status()).isEqualTo(PromptVersionTrials.DONE);
        // Fewer sealed decisions than asked: as many as there are, and how many.
        assertThat(trial.requested()).isEqualTo(20);
        assertThat(trial.actual()).isEqualTo(3);
        assertThat(trial.replayed()).isEqualTo(6);
        assertThat(behind).hasSize(6).containsOnly(true);
        assertThat(audited).containsExactly("PROMPT_VERSION_TRIAL_STARTED v2.0");

        PromptVersionTrials.Result result = trials.result(id).orElseThrow();
        assertThat(result.pairs()).isEqualTo(3);
        assertThat(result.sameAction()).isEqualTo(2);
        assertThat(result.candidate().formatErrors()).isEqualTo(1);
        assertThat(result.reference().formatErrors()).isZero();
        assertThat(result.candidate().averageMs()).isEqualTo(5_200L);
        assertThat(result.reference().averageMs()).isEqualTo(5_000L);
        // An answer the model did not count leaves the average of those it did.
        assertThat(result.candidate().averageAnswerTokens()).isEqualTo(125L);
        assertThat(result.candidate().actions()).containsEntry("ALLOW", 1L).containsEntry("CHALLENGE", 1L)
                .containsEntry("BLOCK", 1L).containsEntry("ESCALATE", 0L);
        assertThat(result.changed()).singleElement().satisfies(changed -> {
            assertThat(changed.requestId()).isEqualTo("req-1");
            assertThat(changed.observationId()).isEqualTo("obs-p1");
            assertThat(changed.userId()).isEqualTo("kim.dev");
            assertThat(changed.path()).isEqualTo("/api/customers/export");
            assertThat(changed.referenceAction()).isEqualTo("ALLOW");
            assertThat(changed.candidateAction()).isEqualTo("CHALLENGE");
            assertThat(changed.candidateReason()).isEqualTo("CHALLENGE because");
        });
        assertThat(trials.latestDone(null, PROMPT, 2)).map(PromptVersionTrials.Trial::id).contains(id);
    }

    @Test
    void aReplayWithoutAnAnswerIsNoAnswerAndAFormatError() throws Exception {
        sealed("p1", "req-1", null, 1, "kim.dev", "/api/x");
        answer("p1", "v2.0", null, true, 180_000L, null);
        answer("p1", "v1.0", "ALLOW", false, 5_000L, 100);

        PromptVersionTrials.Result result = trials.result(awaitEnd(trials.start(null, PROMPT, 2, 1, 20, "admin")).id())
                .orElseThrow();

        assertThat(result.pairs()).isEqualTo(1);
        assertThat(result.sameAction()).isZero();
        assertThat(result.candidate().noAnswer()).isEqualTo(1);
        assertThat(result.candidate().formatErrors()).isEqualTo(1);
        // No answer is no changed action: it is counted, not listed.
        assertThat(result.changed()).isEmpty();
    }

    @Test
    void aTrialThatCannotRunIsRefusedWithWhy() {
        assertThatThrownBy(() -> trials.start(null, PROMPT, 2, 1, 30, "admin"))
                .isInstanceOfSatisfying(PromptVersionTrials.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptVersionTrials.Refusal.COUNT));
        assertThatThrownBy(() -> trials.start(null, PROMPT, 2, 2, 20, "admin"))
                .isInstanceOfSatisfying(PromptVersionTrials.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptVersionTrials.Refusal.VERSION));
        assertThatThrownBy(() -> trials.start(null, PROMPT, 9, 1, 20, "admin"))
                .isInstanceOfSatisfying(PromptVersionTrials.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptVersionTrials.Refusal.VERSION));
        assertThatThrownBy(() -> trials.start(null, "cortex.policy-generation", 2, 1, 20, "admin"))
                .isInstanceOfSatisfying(PromptVersionTrials.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptVersionTrials.Refusal.PROMPT));
        assertThatThrownBy(() -> trials.start(null, PROMPT, 2, 1, 20, "admin"))
                .isInstanceOfSatisfying(PromptVersionTrials.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptVersionTrials.Refusal.NO_SEALED_DECISIONS));
        versions.hide(null, PROMPT, 2, "admin");
        assertThatThrownBy(() -> trials.start(null, PROMPT, 2, 1, 20, "admin"))
                .isInstanceOfSatisfying(PromptVersionTrials.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptVersionTrials.Refusal.VERSION));
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_trial", Integer.class)).isZero();
    }

    @Test
    void aTrialCanBeCancelledAndAnotherCannotStartWhileItRuns() throws Exception {
        sealed("p1", "req-1", null, 2, "kim.dev", "/api/x");
        sealed("p2", "req-2", null, 1, "lee.fin", "/api/y");
        answer("p1", "v2.0", "ALLOW", false, 1L, 1);
        answer("p1", "v1.0", "ALLOW", false, 1L, 1);
        gate = new CountDownLatch(1);
        entered = new CountDownLatch(1);

        long id = trials.start(null, PROMPT, 2, 1, 20, "admin");
        assertThat(entered.await(10, TimeUnit.SECONDS)).isTrue();
        assertThatThrownBy(() -> trials.start(null, PROMPT, 2, 1, 50, "admin"))
                .isInstanceOfSatisfying(PromptVersionTrials.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptVersionTrials.Refusal.RUNNING));
        assertThat(trials.cancel(id, "admin")).isTrue();
        gate.countDown();
        gate = null;
        executor.shutdown();
        assertThat(executor.awaitTermination(10, TimeUnit.SECONDS)).isTrue();

        PromptVersionTrials.Trial trial = trials.find(id).orElseThrow();
        assertThat(trial.status()).isEqualTo(PromptVersionTrials.CANCELLED);
        // The replay in flight ends; none starts after the cancel.
        assertThat(trial.replayed()).isLessThanOrEqualTo(1);
        assertThat(behind).hasSize(1);
        assertThat(audited).contains("PROMPT_VERSION_TRIAL_CANCELLED v2.0");
        assertThat(trials.cancel(id, "admin")).isFalse();
    }

    @Test
    void aTrialAStopLeftUnfinishedIsMarkedFailedWhenTheServiceStartsAgain() {
        jdbc.update("insert into ctxa_prompt_version_trial (registry_scope, prompt_key, candidate_number,"
                + " reference_number, requested_count, actual_count, status, created_by) values"
                + " ('PLATFORM_GLOBAL', ?, 2, 1, 20, 20, 'RUNNING', 'admin')", PROMPT);

        assertThat(trials.closeInterrupted()).isEqualTo(1);
        assertThat(trials.recent(null, PROMPT, 5)).singleElement().satisfies(trial -> {
            assertThat(trial.status()).isEqualTo(PromptVersionTrials.FAILED);
            assertThat(trial.failure()).contains("stopped");
        });
        assertThat(trials.closeInterrupted()).isZero();
    }

    /**
     * Quality plan 3.3 (supplement U2): a trial a stopped server left is resumed by the server that takes the lock,
     * from the replays it kept; a trial whose server is alive is left to it, and only a trial of a release before,
     * which keeps no list of its sealed decisions, is marked failed when a server starts.
     */
    @Test
    void aTrialAStoppedServerLeftIsResumedFromTheReplaysItKept() {
        sealed("p1", "req-1", null, 3, "kim.dev", "/api/a");
        sealed("p2", "req-2", null, 2, "lee.fin", "/api/b");
        answer("p1", "v2.0", "ALLOW", false, 1L, 1);
        answer("p1", "v1.0", "ALLOW", false, 1L, 1);
        answer("p2", "v2.0", "BLOCK", false, 1L, 1);
        answer("p2", "v1.0", "ALLOW", false, 1L, 1);
        long left = runningTrial("PLATFORM_GLOBAL", "server-gone", Instant.now().minus(Duration.ofMinutes(5)), "p2",
                "p1");
        keptReplay(left, "p2", 2, "BLOCK");
        long alive = runningTrial("tenant-alive", "server-alive", Instant.now().plus(Duration.ofMinutes(5)), "p1");
        jdbc.update("insert into ctxa_prompt_version_trial (registry_scope, prompt_key, candidate_number,"
                + " reference_number, requested_count, actual_count, status, created_by) values"
                + " ('tenant-old', ?, 2, 1, 20, 20, 'RUNNING', 'admin')", PROMPT);

        PromptVersionTrials resumer = server("server-b");
        assertThat(resumer.closeInterrupted()).isEqualTo(1);
        resumer.drain();

        PromptVersionTrials.Trial resumed = resumer.find(left).orElseThrow();
        assertThat(resumed.status()).isEqualTo(PromptVersionTrials.DONE);
        assertThat(resumed.replayed()).isEqualTo(4);
        // Only the replays it did not keep are asked, each once.
        assertThat(asked).containsExactly("p2|v1.0", "p1|v2.0", "p1|v1.0");
        assertThat(count("select count(*) from ctxa_prompt_version_trial where id = ? and runner_id = 'server-b'",
                left)).isEqualTo(1);
        assertThat(count("select count(distinct sealed_package_id || '#' || version_number) from"
                + " ctxa_prompt_version_trial_case where trial_id = ?", left)).isEqualTo(4);
        PromptVersionTrials.Result result = resumer.result(left).orElseThrow();
        assertThat(result.pairs()).isEqualTo(2);
        assertThat(result.changed()).singleElement().satisfies(changed -> {
            assertThat(changed.requestId()).isEqualTo("req-2");
            assertThat(changed.candidateAction()).isEqualTo("BLOCK");
        });
        PromptVersionTrials.Trial untouched = resumer.find(alive).orElseThrow();
        assertThat(untouched.status()).isEqualTo(PromptVersionTrials.RUNNING);
        assertThat(untouched.replayed()).isZero();
        assertThat(count("select count(*) from ctxa_prompt_version_trial where registry_scope = 'tenant-old' and"
                + " status = 'FAILED'")).isEqualTo(1);
    }

    /**
     * Quality plan 3.3, 9 (supplement U2): a trial waits while another server holds the lock of the measurements, the
     * server that takes the lock next runs it, and a cancellation on another server stops it before its next replay.
     */
    @Test
    void aTrialWaitsForTheLockOfTheMeasurementsAndACancellationElsewhereStopsIt() throws Exception {
        sealed("p1", "req-1", null, 3, "kim.dev", "/api/a");
        sealed("p2", "req-2", null, 2, "lee.fin", "/api/b");
        sealed("p3", "req-3", null, 1, "svc-report", "/api/c");
        for (String packageId : List.of("p1", "p2", "p3")) {
            answer(packageId, "v2.0", "ALLOW", false, 1L, 1);
            answer(packageId, "v1.0", "ALLOW", false, 1L, 1);
        }
        // Another server measures: it holds the lock the trials share.
        QualityMeasureLock.Held measuring = sharedLock().acquire(Duration.ofMinutes(1)).orElseThrow();
        // The line of B is closing: what B queues waits for a server, and B runs it only when asked here.
        ExecutorService closing = Executors.newSingleThreadExecutor();
        closing.shutdown();
        PromptVersionTrials serverB = server("server-b", closing);
        long queued = serverB.start(null, PROMPT, 2, 1, 20, "admin-b");
        serverB.drain();
        assertThat(serverB.find(queued).orElseThrow().status()).isEqualTo(PromptVersionTrials.QUEUED);
        assertThat(asked).isEmpty();

        measuring.release();
        gate = new CountDownLatch(1);
        entered = new CountDownLatch(1);
        PromptVersionTrials serverA = server("server-a");
        serverA.startLookingForWork();
        assertThat(entered.await(10, TimeUnit.SECONDS)).isTrue();
        assertThat(count("select count(*) from ctxa_prompt_version_trial where id = ? and status = 'RUNNING' and"
                + " runner_id = 'server-a'", queued)).isEqualTo(1);

        assertThat(serverB.cancel(queued, "admin-b")).isTrue();
        gate.countDown();
        gate = null;
        Thread.sleep(1_000);

        PromptVersionTrials.Trial cancelled = serverA.find(queued).orElseThrow();
        assertThat(cancelled.status()).isEqualTo(PromptVersionTrials.CANCELLED);
        // The replay in flight ends; none starts after the cancel, and the lock is free again.
        assertThat(asked).hasSize(1);
        assertThat(cancelled.replayed()).isLessThanOrEqualTo(1);
        QualityMeasureLock.Held free = sharedLock().acquire(Duration.ofSeconds(10)).orElse(null);
        assertThat(free).isNotNull();
        free.release();
    }

    /**
     * Quality plan 3.10 (supplement P-9): each replay keeps the action it ends in under the closing rules beside its
     * first answer, each side counts both, and the two versions are compared on their first answers as before.
     */
    @Test
    void aTrialKeepsTheFinalActionBesideTheFirstAnswer() throws Exception {
        sealed("p1", "req-1", null, 2, "kim.dev", "/api/a");
        sealed("p2", "req-2", null, 1, "lee.fin", "/api/b");
        answers.put("p1|v2.0", new PromptVersionTrials.Replayed("ESCALATE", "defers", false, 9_000L, 200, null,
                "CHALLENGE"));
        // The second pass gave no answer: no final action.
        answers.put("p1|v1.0", new PromptVersionTrials.Replayed("ESCALATE", "defers", false, 9_000L, 200, null,
                null));
        answers.put("p2|v2.0", new PromptVersionTrials.Replayed("BLOCK", "stops", false, 5_000L, 100, null, "BLOCK"));
        answers.put("p2|v1.0", new PromptVersionTrials.Replayed("BLOCK", "stops", false, 5_000L, 100, null, "BLOCK"));

        PromptVersionTrials.Result result = trials.result(awaitEnd(trials.start(null, PROMPT, 2, 1, 20, "admin")).id())
                .orElseThrow();

        assertThat(result.sameAction()).isEqualTo(2);
        assertThat(result.candidate().actions()).containsEntry("ESCALATE", 1L).containsEntry("BLOCK", 1L);
        assertThat(result.candidate().finalAnswered()).isEqualTo(2);
        assertThat(result.candidate().finalActions()).containsEntry("CHALLENGE", 1L).containsEntry("BLOCK", 1L)
                .containsEntry("ESCALATE", 0L).containsEntry("ALLOW", 0L);
        assertThat(result.reference().finalAnswered()).isEqualTo(1);
        assertThat(result.reference().finalActions()).containsEntry("BLOCK", 1L).containsEntry("CHALLENGE", 0L);
        assertThat(jdbc.queryForMap("select action, final_action from ctxa_prompt_version_trial_case where"
                + " sealed_package_id = 'p1' and version_number = 2")).containsEntry("action", "ESCALATE")
                .containsEntry("final_action", "CHALLENGE");
    }

    /**
     * Quality plan 3.3, 3.10: a database installed before the trials were resumed gains their columns and the
     * uniqueness of their replays from the idempotent statements of the schema, which the start replays; its trial
     * left unfinished keeps no list and is marked failed.
     */
    @Test
    void aDatabaseInstalledBeforeGainsTheColumnsOfTheTrialsFromTheSchema() throws Exception {
        jdbc.execute("drop index if exists ctxa_uq_prompt_version_trial_case_pair");
        jdbc.execute("alter table ctxa_prompt_version_trial_case drop column final_action");
        jdbc.execute("alter table ctxa_prompt_version_trial drop column runner_id, drop column heartbeat_at,"
                + " drop column sealed_package_ids");
        jdbc.update("insert into ctxa_prompt_version_trial (registry_scope, prompt_key, candidate_number,"
                + " reference_number, requested_count, actual_count, status, created_by) values"
                + " ('PLATFORM_GLOBAL', ?, 2, 1, 20, 20, 'RUNNING', 'admin')", PROMPT);
        String schema = new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        List<String> maintenance = Arrays.stream(schema.split(";"))
                .map(statement -> statement.replaceAll("(?m)--.*$", " ").replaceAll("\\s+", " ").trim())
                .filter(statement -> {
                    String normal = statement.toLowerCase(Locale.ROOT);
                    return normal.matches("^alter table ctxa_prompt_version_trial(_case)? .*add column if not exists.*")
                            || normal.startsWith("create unique index if not exists ctxa_uq_prompt_version_trial_");
                }).toList();
        assertThat(maintenance).hasSize(3);

        maintenance.forEach(jdbc::execute);

        assertThat(count("select count(*) from information_schema.columns where table_schema = current_schema() and"
                + " ((table_name = 'ctxa_prompt_version_trial' and column_name in ('runner_id', 'heartbeat_at',"
                + " 'sealed_package_ids')) or (table_name = 'ctxa_prompt_version_trial_case' and column_name ="
                + " 'final_action'))")).isEqualTo(4);
        assertThat(count("select count(*) from pg_indexes where indexname = 'ctxa_uq_prompt_version_trial_case_pair'"))
                .isEqualTo(1);
        assertThat(trials.closeInterrupted()).isEqualTo(1);
    }
}
