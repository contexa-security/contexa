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
package io.contexa.contexaiam.admin.web.zerotrust;

import io.contexa.contexacore.monitoring.ai.DecisionRiskSignals;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustReviewSampler;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterAll;
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
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Quality plan 3.6 on a database with the schema of a new installation: the review sample draws the stopped decisions,
 * the allowed decisions by risk and the allowed decisions at random, from the sealed decisions while the capture runs.
 * The signs of risk read from the decision rows are the same as the sealing reads from a decision's columns.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class ZeroTrustRiskReviewSamplePostgresTest {

    private static final LocalDate DAY = LocalDate.parse("2026-11-20");
    private static final Instant NOON = DAY.atTime(12, 0).toInstant(ZoneOffset.UTC);
    private static final Clock CLOCK = Clock.fixed(DAY.plusDays(1).atTime(0, 7).toInstant(ZoneOffset.UTC),
            ZoneOffset.UTC);
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private final SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();

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
    void noDecisions() {
        jdbc.execute("TRUNCATE ctxa_ai_security_decision_observation, ctxa_zt_decision_outcome, ctxa_zt_review_queue,"
                + " ctxa_sealed_evidence_package CASCADE");
    }

    /**
     * Every combination of the columns the signs read, written as decision rows: the SQL of each sign says what the
     * Java definition says of the same values, so the review sample and the sealing choose by one rule.
     */
    @Test
    void theSqlOfEachSignIsTheJavaDefinitionOverEveryCombinationOfItsColumns() {
        String[] hypotheses = {null, "", "H1", "h1", "H3"};
        String[] depths = {null, "1", "2"};
        String[] stages = {null, "LAYER1", "LAYER2", "ESCALATE_PROTECTION"};
        Integer[] calls = {null, 1, 2, 3};
        Integer[] unknown = {null, 2, 3};
        String[] baselines = {null, "ESTABLISHED", "PROVISIONAL", "NONE"};
        String[] actions = {"ALLOW", "BLOCK"};
        Map<String, Set<DecisionRiskSignals.Signal>> expected = new HashMap<>();
        List<Object[]> rows = new ArrayList<>();
        int id = 0;
        for (String hypothesis : hypotheses) {
            for (String depth : depths) {
                for (String stage : stages) {
                    for (Integer call : calls) {
                        for (Integer facts : unknown) {
                            for (String baseline : baselines) {
                                for (String action : actions) {
                                    String observation = "c-" + id++;
                                    expected.put(observation, DecisionRiskSignals.of(action, hypothesis,
                                            DecisionRiskSignals.secondAnalysis(depth),
                                            DecisionRiskSignals.askedAgain(call, stage), facts, baseline, 3));
                                    rows.add(new Object[] {observation, action, hypothesis, depth, stage, call, facts,
                                            baseline, Timestamp.from(NOON)});
                                }
                            }
                        }
                    }
                }
            }
        }
        jdbc.batchUpdate("INSERT INTO ctxa_ai_security_decision_observation (observation_id, final_action,"
                + " most_likely_hypothesis, analysis_depth, decision_stage, model_call_count, unknown_fact_count,"
                + " baseline_status, created_at, attempt_kind, success) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'FIRST', TRUE)",
                rows);
        StringBuilder columns = new StringBuilder("SELECT o.observation_id, o.final_action");
        for (DecisionRiskSignals.Signal signal : DecisionRiskSignals.Signal.values()) {
            columns.append(", CASE WHEN o.final_action = 'ALLOW' AND ")
                    .append(DecisionRiskSignals.sqlCondition(signal, "o", 3)).append(" THEN 1 ELSE 0 END");
        }
        columns.append(", CASE WHEN ").append(DecisionRiskSignals.sqlCondition("o", 3)).append(" THEN 1 ELSE 0 END")
                .append(", CASE WHEN NOT ").append(DecisionRiskSignals.sqlCondition("o", 3))
                .append(" THEN 1 ELSE 0 END, ").append(DecisionRiskSignals.sqlCount("o", 3))
                .append(" FROM ctxa_ai_security_decision_observation o");
        Map<String, Set<DecisionRiskSignals.Signal>> read = new HashMap<>();
        List<String> disagreements = new ArrayList<>();
        jdbc.query(columns.toString(), rs -> {
            String observation = rs.getString(1);
            boolean allowed = "ALLOW".equals(rs.getString(2));
            Set<DecisionRiskSignals.Signal> signals = EnumSet.noneOf(DecisionRiskSignals.Signal.class);
            DecisionRiskSignals.Signal[] all = DecisionRiskSignals.Signal.values();
            for (int index = 0; index < all.length; index++) {
                if (rs.getInt(3 + index) == 1) {
                    signals.add(all[index]);
                }
            }
            read.put(observation, signals);
            boolean any = rs.getInt(3 + all.length) == 1;
            boolean none = rs.getInt(4 + all.length) == 1;
            Set<DecisionRiskSignals.Signal> java = expected.get(observation);
            if (any != !java.isEmpty() || none == any) {
                disagreements.add(observation + " any=" + any + " none=" + none + " java=" + java);
            }
            // The count reads the signs whatever the action; for an allowed decision it is their number.
            if (allowed && rs.getInt(5 + all.length) != java.size()) {
                disagreements.add(observation + " count=" + rs.getInt(5 + all.length) + " java=" + java);
            }
        });

        assertThat(read).hasSize(rows.size()).isEqualTo(expected);
        assertThat(disagreements).isEmpty();
        assertThat(rows).hasSize(5 * 3 * 4 * 4 * 3 * 4 * 2);
    }

    /**
     * While the capture runs, every part of the sample is drawn from the sealed decisions: the stopped ones at random,
     * the allowed ones with a sign, and the allowed ones without a sign at random.
     */
    @Test
    void theSampleIsDrawnFromTheSealedDecisionsOnly() {
        for (int i = 0; i < 4; i++) {
            decision("stopped-sealed-" + i, "BLOCK", Map.of(), NOON, true);
            decision("stopped-unsealed-" + i, "CHALLENGE", Map.of(), NOON, false);
            decision("risky-sealed-" + i, "ALLOW", Map.of("most_likely_hypothesis", "H3"), NOON, true);
            decision("risky-unsealed-" + i, "ALLOW", Map.of("most_likely_hypothesis", "H3"), NOON, false);
            decision("ordinary-sealed-" + i, "ALLOW", ordinary(), NOON, true);
            decision("ordinary-unsealed-" + i, "ALLOW", ordinary(), NOON, false);
        }
        // A package that failed to seal is no sealed decision.
        decision("stopped-failed-seal", "BLOCK", Map.of(), NOON, true);
        jdbc.update("UPDATE ctxa_sealed_evidence_package SET seal_state = 'FAILED' WHERE idempotency_key = ?",
                "key-stopped-failed-seal");

        int added = sampler(true, 20, 10, 10).sample(DAY);

        assertThat(added).isEqualTo(12);
        assertThat(queued()).containsOnlyKeys(prefixed("stopped-sealed-", "risky-sealed-", "ordinary-sealed-"));
        assertThat(queued().values()).containsOnly(ZeroTrustReviewSampler.SAMPLE);
        // Without the capture every decision is drawn as it is.
        noDecisions();
        for (int i = 0; i < 3; i++) {
            decision("stopped-" + i, "BLOCK", Map.of(), NOON, false);
            decision("ordinary-" + i, "ALLOW", ordinary(), NOON, false);
        }
        assertThat(sampler(false, 20, 10, 10).sample(DAY)).isEqualTo(6);
    }

    /**
     * Each sign alone makes an allowed decision risky; an allowed decision without one is ordinary, and goes to the
     * random part only. The risky part takes the decisions with more signs first.
     */
    @Test
    void eachSignAloneMakesAnAllowedDecisionRiskyAndTheOrdinaryOnesAreDrawnAtRandom() {
        Map<String, Map<String, Object>> signs = new LinkedHashMap<>();
        signs.put("hypothesis", Map.of("most_likely_hypothesis", "H2"));
        signs.put("second", Map.of("analysis_depth", "2", "decision_stage", "LAYER2", "model_call_count", 2));
        signs.put("again", Map.of("analysis_depth", "1", "decision_stage", "LAYER1", "model_call_count", 2));
        signs.put("unknown", Map.of("unknown_fact_count", 3));
        signs.put("baseline", Map.of("baseline_status", "PROVISIONAL"));
        signs.forEach((name, columns) -> {
            Map<String, Object> row = new HashMap<>(ordinary());
            row.putAll(columns);
            decision("risky-" + name, "ALLOW", row, NOON, true);
        });
        Map<String, Object> many = new HashMap<>(ordinary());
        many.putAll(Map.of("most_likely_hypothesis", "H4", "unknown_fact_count", 5, "baseline_status", "NONE"));
        decision("risky-many", "ALLOW", many, NOON, true);
        Map<String, Object> belowThreshold = new HashMap<>(ordinary());
        belowThreshold.put("unknown_fact_count", 2);
        decision("ordinary-below-threshold", "ALLOW", belowThreshold, NOON, true);
        for (int i = 0; i < 3; i++) {
            decision("ordinary-" + i, "ALLOW", ordinary(), NOON, true);
        }
        // A decision of another day and a test run are not drawn.
        decision("risky-other-day", "ALLOW", Map.of("most_likely_hypothesis", "H3"), NOON.minusSeconds(86_400), true);
        Map<String, Object> tested = new HashMap<>(Map.of("most_likely_hypothesis", "H3", "test_run_id", "run-1"));
        decision("risky-test-run", "ALLOW", tested, NOON, true);

        assertThat(sampler(true, 20, 1, 0).sample(DAY)).as("the most signs first").isEqualTo(1);
        assertThat(queued()).containsOnlyKeys("risky-many");

        noQueue();
        assertThat(sampler(true, 20, 10, 2).sample(DAY)).isEqualTo(8);
        Map<String, String> queued = queued();
        assertThat(queued).containsKeys("risky-hypothesis", "risky-second", "risky-again", "risky-unknown",
                "risky-baseline", "risky-many");
        assertThat(queued.keySet().stream().filter(key -> key.startsWith("ordinary-"))).hasSize(2);
        assertThat(queued).doesNotContainKeys("risky-other-day", "risky-test-run");
        // The allowed decisions of a day are drawn once.
        assertThat(sampler(true, 20, 10, 2).sample(DAY)).isZero();
    }

    /**
     * The allowed decisions of a user blocked in the day are looked back for, from the block, within the lookback:
     * taken first, whatever their signs. A block an administrator released or judged wrong is not looked back from,
     * and an allowed decision after the block is no decision before it.
     */
    @Test
    void theAllowedDecisionsBeforeABlockOfTheirUserAreTakenFirstLookingBack() {
        Instant block = NOON.plusSeconds(3_600);
        decision("block-mallory", "BLOCK", Map.of("user_id", "mallory"), block, true);
        decision("allow-mallory-day", "ALLOW", user("mallory"), NOON, true);
        decision("allow-mallory-earlier", "ALLOW", user("mallory"), NOON.minusSeconds(3 * 86_400), true);
        decision("allow-mallory-too-early", "ALLOW", user("mallory"), NOON.minusSeconds(9 * 86_400), true);
        decision("allow-mallory-after", "ALLOW", user("mallory"), block.plusSeconds(60), true);
        decision("allow-mallory-unsealed", "ALLOW", user("mallory"), NOON.minusSeconds(86_400), false);
        // Trudy's block was released by an administrator, Oscar's judged wrong: neither looks back.
        decision("block-trudy", "BLOCK", Map.of("user_id", "trudy"), block, true);
        decision("allow-trudy", "ALLOW", user("trudy"), NOON, true);
        outcome("block-trudy", "ADMIN_RELEASED");
        decision("block-oscar", "BLOCK", Map.of("user_id", "oscar"), block, true);
        decision("allow-oscar", "ALLOW", user("oscar"), NOON.minusSeconds(86_400), true);
        outcome("block-oscar", "EVALUATED_INVALID");
        // A block in another tenant of a user of the same name is not this user's.
        Map<String, Object> elsewhere = new HashMap<>(user("alice"));
        elsewhere.put("tenant_id", "tenant-b");
        decision("block-alice-b", "BLOCK", Map.of("user_id", "alice", "tenant_id", "tenant-a"), block, true);
        decision("allow-alice-b", "ALLOW", elsewhere, NOON.minusSeconds(86_400), true);
        // A risky decision of the day competes for the same places.
        decision("risky-bob", "ALLOW", Map.of("user_id", "bob", "most_likely_hypothesis", "H3",
                "unknown_fact_count", 4), NOON, true);

        assertThat(sampler(true, 0, 2, 0).sample(DAY)).isEqualTo(2);
        assertThat(queued()).containsOnlyKeys("allow-mallory-day", "allow-mallory-earlier");

        noQueue();
        assertThat(sampler(true, 0, 10, 10).sample(DAY)).isEqualTo(5);
        assertThat(queued()).containsOnlyKeys("allow-mallory-day", "allow-mallory-earlier", "risky-bob",
                "allow-mallory-after", "allow-trudy");
        assertThat(queued()).doesNotContainKeys("allow-mallory-too-early", "allow-mallory-unsealed", "allow-oscar",
                "allow-alice-b");
    }

    /** The stopped part keeps its daily number and is drawn up to it again; the queue holds a decision once. */
    @Test
    void theStoppedPartKeepsItsNumberApartFromTheAllowedParts() {
        for (int i = 0; i < 6; i++) {
            decision("stopped-" + i, i % 2 == 0 ? "CHALLENGE" : "ESCALATE", Map.of(), NOON, true);
            decision("ordinary-" + i, "ALLOW", ordinary(), NOON, true);
        }
        assertThat(sampler(true, 3, 0, 4).sample(DAY)).isEqualTo(7);
        assertThat(sampler(true, 5, 0, 4).sample(DAY)).as("two more stopped, the allowed drawn once").isEqualTo(2);
        assertThat(queued().keySet().stream().filter(key -> key.startsWith("stopped-"))).hasSize(5);
        assertThat(queued().keySet().stream().filter(key -> key.startsWith("ordinary-"))).hasSize(4);
    }

    // ----- fixtures -----

    private ZeroTrustReviewSampler sampler(boolean sealedOnly, int stopped, int risky, int ordinary) {
        properties.getConsole().setReviewDailySample(stopped);
        properties.getConsole().setReviewRiskSample(risky);
        properties.getConsole().setReviewAllowedSample(ordinary);
        return new ZeroTrustReviewSampler(() -> jdbc, properties, CLOCK, 3, () -> sealedOnly);
    }

    /** The columns of an allowed decision without a sign. */
    private static Map<String, Object> ordinary() {
        return Map.of("most_likely_hypothesis", "H1", "analysis_depth", "1", "decision_stage", "LAYER1",
                "model_call_count", 1, "unknown_fact_count", 1, "baseline_status", "ESTABLISHED");
    }

    private static Map<String, Object> user(String user) {
        Map<String, Object> row = new HashMap<>(ordinary());
        row.put("user_id", user);
        return row;
    }

    private static void decision(String observationId, String action, Map<String, Object> columns, Instant at,
                                 boolean sealed) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("observation_id", observationId);
        row.put("idempotency_key", "key-" + observationId);
        row.put("request_id", "request-" + observationId);
        row.put("user_id", "alice");
        row.put("tenant_id", "tenant-a");
        row.put("final_action", action);
        row.put("attempt_kind", "FIRST");
        row.put("success", true);
        row.put("created_at", Timestamp.from(at));
        row.putAll(columns);
        String names = String.join(", ", row.keySet());
        String marks = String.join(", ", row.keySet().stream().map(name -> "?").toList());
        jdbc.update("INSERT INTO ctxa_ai_security_decision_observation (" + names + ") VALUES (" + marks + ")",
                row.values().toArray());
        if (sealed) {
            jdbc.update("INSERT INTO ctxa_sealed_evidence_package (package_id, correlation_id, idempotency_key, user_id,"
                    + " captured_at, package_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", "package-" + observationId,
                    "request-" + observationId, "key-" + observationId, row.get("user_id"), Timestamp.from(at),
                    "hash-" + observationId, Timestamp.from(at));
        }
    }

    private static void outcome(String observationId, String kind) {
        jdbc.update("INSERT INTO ctxa_zt_decision_outcome (outcome_id, observation_id, request_id, outcome_kind,"
                + " occurred_at) VALUES (?, ?, ?, ?, ?)", "outcome-" + observationId, observationId,
                "request-" + observationId, kind, Timestamp.from(NOON));
    }

    private static Map<String, String> queued() {
        Map<String, String> queued = new LinkedHashMap<>();
        jdbc.query("SELECT observation_id, review_reason FROM ctxa_zt_review_queue ORDER BY observation_id",
                rs -> {
                    queued.put(rs.getString(1), rs.getString(2));
                });
        return queued;
    }

    private static void noQueue() {
        jdbc.execute("TRUNCATE ctxa_zt_review_queue");
    }

    private static String[] prefixed(String... prefixes) {
        List<String> keys = new ArrayList<>();
        for (String prefix : prefixes) {
            for (int i = 0; i < 4; i++) {
                keys.add(prefix + i);
            }
        }
        return keys.toArray(String[]::new);
    }
}
