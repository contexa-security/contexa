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
package io.contexa.contexaiam.admin.promptquality.evidence;

import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
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
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The retention of sealed packages on PostgreSQL, with the schema of a new installation: one period for every package,
 * whatever a prompt inspection found in it, and the expired packages a prompt version trial or an administrator's
 * evaluation still stands on are left until nothing names them.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class SealedEvidenceRetentionPostgresTest {

    private static final Instant NOW = Instant.parse("2026-11-22T03:30:00Z");

    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private JdbcSealedEvidencePackageRepository repository;
    private ZeroTrustDecisionOutcomes outcomes;

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
    void noPackages() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_trial_case, ctxa_prompt_version_trial, ctxa_zt_decision_outcome,"
                + " ctxa_sealed_evidence_package CASCADE");
        repository = new JdbcSealedEvidencePackageRepository(jdbc);
        outcomes = new ZeroTrustDecisionOutcomes(() -> jdbc);
    }

    @Test
    void anExpiredPackageATrialOrAnEvaluationStandsOnIsLeft() {
        seal("expired", "request-expired", NOW.minus(Duration.ofDays(91)), NOW.minusSeconds(1));
        seal("expired-in-trial", "request-trial", NOW.minus(Duration.ofDays(200)), NOW.minus(Duration.ofDays(110)));
        seal("expired-evaluated-valid", "request-valid", NOW.minus(Duration.ofDays(95)), NOW.minus(Duration.ofDays(5)));
        seal("expired-evaluated-invalid", "request-invalid", NOW.minus(Duration.ofDays(95)),
                NOW.minus(Duration.ofDays(5)));
        seal("expired-other-outcome", "request-passed", NOW.minus(Duration.ofDays(95)), NOW.minus(Duration.ofDays(5)));
        seal("not-expired", "request-live", NOW.minus(Duration.ofDays(89)), NOW.plusSeconds(1));
        seal("without-expiry", "request-none", NOW.minus(Duration.ofDays(400)), null);
        trialCase(trial(), "expired-in-trial");
        outcomes.evaluate("observation-valid", "request-valid", "alice", "tenant-a", true, null, "admin", null);
        outcomes.evaluate("observation-invalid", "request-invalid", "alice", "tenant-a", false,
                ZeroTrustDecisionOutcomes.EvaluationReason.MISSED_SIGNAL, "admin", "missed");
        // An outcome that is no evaluation holds nothing: the challenge was passed, nobody judged the decision.
        outcomes.record("request-passed", "alice", "tenant-a", ZeroTrustDecisionOutcomes.Kind.CHALLENGE_PASSED,
                "alice", null);

        assertThat(repository.deleteByExpiresAtBefore(NOW)).isEqualTo(2);

        assertThat(packages()).containsExactlyInAnyOrder("expired-evaluated-invalid", "expired-evaluated-valid",
                "expired-in-trial", "not-expired", "without-expiry");
        // What is left reads as before, and a second run removes nothing more.
        assertThat(repository.findByPackageId("expired-in-trial")).isPresent();
        assertThat(repository.findByCorrelationId("request-valid")).isPresent();
        assertThat(repository.deleteByExpiresAtBefore(NOW)).isZero();
    }

    @Test
    void aPackageGoesOnceNothingStandsOnItAnyMore() {
        seal("in-trial", "request-trial", NOW.minus(Duration.ofDays(120)), NOW.minus(Duration.ofDays(30)));
        seal("evaluated", "request-evaluated", NOW.minus(Duration.ofDays(120)), NOW.minus(Duration.ofDays(30)));
        long trial = trial();
        trialCase(trial, "in-trial");
        outcomes.evaluate("observation-1", "request-evaluated", "alice", "tenant-a", true, null, "admin", null);
        assertThat(repository.deleteByExpiresAtBefore(NOW)).isZero();

        jdbc.update("delete from ctxa_prompt_version_trial_case where trial_id = ?", trial);
        assertThat(repository.deleteByExpiresAtBefore(NOW)).isEqualTo(1);
        assertThat(packages()).containsExactlyInAnyOrder("evaluated");

        jdbc.update("delete from ctxa_zt_decision_outcome where request_id = ?", "request-evaluated");
        assertThat(repository.deleteByExpiresAtBefore(NOW)).isEqualTo(1);
        assertThat(packages()).isEmpty();
    }

    /** Both versions of a trial name the package they decided again; either one holds it. */
    @Test
    void aPackageNamedByBothVersionsOfATrialIsRemovedOnce() {
        seal("in-trial", "request-trial", NOW.minus(Duration.ofDays(120)), NOW.minus(Duration.ofDays(30)));
        long trial = trial();
        trialCase(trial, "in-trial");
        jdbc.update("insert into ctxa_prompt_version_trial_case (trial_id, sealed_package_id, version_number) "
                + "values (?, ?, ?)", trial, "in-trial", 2);
        assertThat(repository.deleteByExpiresAtBefore(NOW)).isZero();

        jdbc.update("delete from ctxa_prompt_version_trial_case where trial_id = ?", trial);
        assertThat(repository.deleteByExpiresAtBefore(NOW)).isEqualTo(1);
    }

    /**
     * What a prompt inspection found plays no part: a package the inspection passed long ago stays until its expiry,
     * and an expired one goes with its result whatever the result says.
     */
    @Test
    void theInspectionsVerdictChangesNothing() {
        seal("passed-long-ago", "request-1", NOW.minus(Duration.ofDays(60)), NOW.plus(Duration.ofDays(30)));
        seal("failed-long-ago", "request-2", NOW.minus(Duration.ofDays(60)), NOW.plus(Duration.ofDays(30)));
        seal("passed-expired", "request-3", NOW.minus(Duration.ofDays(91)), NOW.minus(Duration.ofDays(1)));
        seal("failed-expired", "request-4", NOW.minus(Duration.ofDays(91)), NOW.minus(Duration.ofDays(1)));
        inspected("passed-long-ago", "PASS");
        inspected("failed-long-ago", "FAIL");
        inspected("passed-expired", "PASS");
        inspected("failed-expired", "FAIL");

        assertThat(repository.deleteByExpiresAtBefore(NOW)).isEqualTo(2);

        assertThat(packages()).containsExactlyInAnyOrder("failed-long-ago", "passed-long-ago");
        assertThat(jdbc.queryForList("select package_id from ctxa_prompt_inspection_result order by package_id",
                String.class)).containsExactlyInAnyOrder("failed-long-ago", "passed-long-ago");
    }

    private List<String> packages() {
        return jdbc.queryForList("select package_id from ctxa_sealed_evidence_package order by package_id", String.class);
    }

    private void seal(String packageId, String requestId, Instant capturedAt, Instant expiresAt) {
        jdbc.update("insert into ctxa_sealed_evidence_package (package_id, correlation_id, captured_at, package_hash, "
                        + "expires_at) values (?, ?, ?, ?, ?)", packageId, requestId, Timestamp.from(capturedAt), "hash",
                expiresAt != null ? Timestamp.from(expiresAt) : null);
    }

    private long trial() {
        Long id = jdbc.queryForObject("insert into ctxa_prompt_version_trial (registry_scope, prompt_key, "
                + "candidate_number, reference_number, requested_count, status, created_by) "
                + "values ('platform', 'cortex.security-decision', 2, 1, 20, 'FINISHED', 'admin') returning id", Long.class);
        return id == null ? 0L : id;
    }

    private void trialCase(long trial, String packageId) {
        jdbc.update("insert into ctxa_prompt_version_trial_case (trial_id, sealed_package_id, version_number) "
                + "values (?, ?, ?)", trial, packageId, 1);
    }

    private void inspected(String packageId, String verdict) {
        jdbc.update("insert into ctxa_prompt_inspection_result (package_id, inspector_version, verdict, checked_count, "
                + "mismatch_count, unverifiable_count, check_counts_json, inspection_trigger, inspected_at) "
                + "values (?, 'prompt-inspector/1', ?, 10, 0, 0, '[]', 'AUTO', ?)", packageId, verdict,
                Timestamp.from(NOW.minus(Duration.ofDays(59))));
    }
}
