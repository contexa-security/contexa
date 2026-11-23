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
package io.contexa.contexaiam.admin.promptquality.screen;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.evidence.JdbcSealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityRunLine;
import io.contexa.contexaiam.admin.promptquality.measure.QualityMeasureLock;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens.Count;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
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
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Quality plan 3.8 on a database with the schema of a new installation: the counts of the menu bar, read by the
 * services of the screens, are the cases of the default set and those kept in the scope, waiting or not; the
 * measurements on the labelled cases and the trials of the scope, of every state; the versions of the scope the version
 * list shows; and the decisions sealed in the last seven days. Another scope's rows, another prompt's and older seals
 * are not counted.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptQualityNavCountsPostgresTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final String PLATFORM = PromptVersionService.PLATFORM_SCOPE;
    private static final String TENANT = "tenant-a";
    private static final Instant NOW = Instant.parse("2026-11-22T12:00:00Z");
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private PromptVersionService versions;
    private PromptQualityCases cases;
    private PromptQualityMeasurements measurements;
    private PromptVersionTrials trials;
    private ExecutorService trialThread;
    private PromptQualityNavCounts counts;

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
    void theServicesOfTheScreens() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_measure, ctxa_prompt_version_case_set, ctxa_prompt_version_case,"
                + " ctxa_prompt_version_trial, ctxa_prompt_version_part, ctxa_prompt_version, ctxa_sealed_evidence_package"
                + " CASCADE");
        versions = new PromptVersionService(() -> jdbc, SecurityDecisionPromptDocument.productReleases(), Map.of(),
                PromptVersionAudit.none(), Clock.systemUTC());
        cases = new PromptQualityCases(() -> jdbc, JSON, true, null, null, null, null);
        measurements = new PromptQualityMeasurements(() -> jdbc, versions, cases,
                mock(PromptQualityMeasurements.Replayer.class), new PromptQualityRunLine(), QualityMeasureLock.local(),
                Map::of, null, null, JSON, null, "server-a");
        trialThread = Executors.newSingleThreadExecutor();
        trials = new PromptVersionTrials(() -> jdbc, versions, mock(PromptVersionTrials.Replayer.class), trialThread,
                null, null);
        JdbcSealedEvidencePackageRepository sealed = new JdbcSealedEvidencePackageRepository(jdbc);
        counts = new PromptQualityNavCounts(() -> cases, () -> measurements, () -> trials, () -> versions,
                () -> sealed, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @AfterEach
    void closeTheServices() {
        measurements.close();
        trials.close();
        trialThread.shutdownNow();
    }

    @Test
    void theCasesAreTheDefaultSetsAndThoseKeptInTheScopeWaitingOrNot() {
        int shipped = cases.defaultSet().cases().size();
        keptCase(PLATFORM, PROMPT, "ours-1", PromptQualityCases.CONFIRMED);
        keptCase(PLATFORM, PROMPT, "ours-2", PromptQualityCases.PENDING);
        keptCase(PLATFORM, PROMPT, "ours-3", PromptQualityCases.PENDING);
        keptCase(TENANT, PROMPT, "theirs-1", PromptQualityCases.CONFIRMED);
        keptCase(PLATFORM, "cortex.other-prompt", "other-1", PromptQualityCases.CONFIRMED);

        assertThat(shipped).isEqualTo(70);
        assertThat(counts.count(Count.CASES, null)).isEqualTo(shipped + 3L);
        assertThat(counts.count(Count.CASES, PLATFORM)).isEqualTo(shipped + 3L);
        assertThat(counts.count(Count.CASES, TENANT)).isEqualTo(shipped + 1L);
        assertThat(cases.count(PLATFORM, "cortex.other-prompt")).isZero();
    }

    @Test
    void theMeasurementsAreThoseOnTheCasesAndTheTrialsOfTheScopeOfEveryState() {
        long set = caseSet(PLATFORM);
        measure(PLATFORM, PROMPT, set, PromptQualityMeasurements.DONE);
        measure(PLATFORM, PROMPT, set, PromptQualityMeasurements.RUNNING);
        measure(PLATFORM, PROMPT, set, PromptQualityMeasurements.CANCELLED);
        measure(TENANT, PROMPT, caseSet(TENANT), PromptQualityMeasurements.DONE);
        trial(PLATFORM, PROMPT, PromptVersionTrials.DONE);
        trial(PLATFORM, PROMPT, PromptVersionTrials.FAILED);
        trial(TENANT, PROMPT, PromptVersionTrials.DONE);
        trial(PLATFORM, "cortex.other-prompt", PromptVersionTrials.DONE);

        assertThat(measurements.count(PLATFORM, PROMPT)).isEqualTo(3L);
        assertThat(trials.count(PLATFORM, PROMPT)).isEqualTo(2L);
        assertThat(counts.count(Count.MEASUREMENTS, null)).isEqualTo(5L);
        assertThat(counts.count(Count.MEASUREMENTS, TENANT)).isEqualTo(2L);
        assertThat(counts.count(Count.MEASUREMENTS, "tenant-without-any")).isZero();
    }

    @Test
    void theVersionsAreThoseTheVersionListShowsTheHiddenOnesLeftOut() {
        versions.registerProducts(null);
        versions.registerProducts(TENANT);
        int added = versions.create(null, """
                prompt: cortex.security-decision
                basedOn: v1.0
                title: Finance closing
                system:
                  - key: how-to-judge
                    text: |
                      1. Weigh the duty roster first.
                """, PromptVersionRecord.SCREEN, null, "admin", null).number();
        long shown = versions.list(PLATFORM, PROMPT, false).size();

        assertThat(counts.count(Count.VERSIONS, null)).isEqualTo(shown).isGreaterThanOrEqualTo(2L);
        assertThat(counts.count(Count.VERSIONS, TENANT)).isEqualTo(versions.list(TENANT, PROMPT, false).size());

        jdbc.update("update ctxa_prompt_version set hidden = true where registry_scope = ? and prompt_key = ?"
                + " and version_number = ?", PLATFORM, PROMPT, added);

        assertThat(counts.count(Count.VERSIONS, null)).isEqualTo(shown - 1);
    }

    @Test
    void theSealedDecisionsAreThoseOfTheLastSevenDays() {
        sealed("p-1", NOW.minus(Duration.ofHours(1)));
        sealed("p-2", NOW.minus(Duration.ofDays(7)));
        sealed("p-3", NOW.minus(Duration.ofDays(7)).minusSeconds(1));
        sealed("p-4", NOW.minus(Duration.ofDays(30)));

        assertThat(counts.count(Count.SEALED, null)).isEqualTo(2L);
    }

    private static void keptCase(String scope, String prompt, String key, String status) {
        jdbc.update("insert into ctxa_prompt_version_case (registry_scope, prompt_key, case_key, origin, grade,"
                        + " classification, case_kind, content_hash, case_input, expectation, time_zone,"
                        + " context_format_version, status, submitted_by, submitted_at, labelled_by, labelled_at)"
                        + " values (?, ?, ?, 'MADE', 'NORMAL', 'THREAT', 'INSIDER', 'hash', '{}', '{}', 'UTC', '1', ?,"
                        + " 'admin', current_timestamp, 'admin', current_timestamp)",
                scope, prompt, key, status);
    }

    private static long caseSet(String scope) {
        Long id = jdbc.queryForObject("insert into ctxa_prompt_version_case_set (registry_scope, prompt_key, set_version,"
                + " name, case_count, default_case_count, published_by, published_at) values (?, ?, 'v1', 'v1', 70, 70,"
                + " 'admin', current_timestamp) returning id", Long.class, scope, PROMPT);
        return id != null ? id : 0L;
    }

    private static void measure(String scope, String prompt, long caseSet, String status) {
        jdbc.update("insert into ctxa_prompt_version_measure (registry_scope, prompt_key, version_number,"
                        + " version_content_hash, case_set_id, case_set_version, repeats, settings_hash, settings,"
                        + " closing_rules, status, planned_answers, reusable_answers, expected_min_calls,"
                        + " expected_max_calls, call_limit, created_by, created_at) values (?, ?, 1, 'hash', ?, 'v1', 1,"
                        + " 'settings', '{}', 'rules', ?, 70, 0, 70, 280, 1000, 'admin', current_timestamp)",
                scope, prompt, caseSet, status);
    }

    private static void trial(String scope, String prompt, String status) {
        jdbc.update("insert into ctxa_prompt_version_trial (registry_scope, prompt_key, candidate_number,"
                + " reference_number, requested_count, status, created_by) values (?, ?, 2, 1, 20, ?, 'admin')",
                scope, prompt, status);
    }

    private static void sealed(String packageId, Instant capturedAt) {
        jdbc.update("insert into ctxa_sealed_evidence_package (package_id, correlation_id, captured_at, package_hash)"
                + " values (?, ?, ?, 'hash')", packageId, "request-" + packageId, Timestamp.from(capturedAt));
    }
}
