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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionTrigger;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries.EvidenceFilter;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries.EvidencePage;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries.EvidenceRow;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionResultStore;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionConsole;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Quality plan 3.7, 3.8 on a database with the schema of a new installation: the sealed evidence lists the sealed
 * decisions of a period newest first with the action and the version of the decision and the result of the three
 * checks of the evidence audit by the latest inspection, the totals of the period and its versions, filtered and paged;
 * one sealed decision reads what it was made from, what went into it and its replays from the audit log.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class SealedEvidencePostgresTest {

    private static final Instant FROM = Instant.parse("2026-11-15T00:00:00Z");
    private static final Instant TO = Instant.parse("2026-11-22T00:00:00Z");
    private static final Instant T0 = Instant.parse("2026-11-20T10:00:00Z");
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private JdbcSealedEvidencePackageRepository packages;
    private JdbcPromptInspectionResultStore results;
    private JdbcPromptInspectionQueries queries;

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
    void theSealedDecisionsOfAWeek() {
        jdbc.execute("TRUNCATE ctxa_prompt_inspection_result, ctxa_sealed_evidence_package, ctxa_audit_log CASCADE");
        packages = new JdbcSealedEvidencePackageRepository(jdbc);
        results = new JdbcPromptInspectionResultStore(jdbc,
                new TransactionTemplate(new DataSourceTransactionManager(database.dataSource())), JSON);
        queries = new JdbcPromptInspectionQueries(jdbc);

        seal("e1", T0, "alice", "POST", "/api/projects/GB-500/exports", "BLOCK", "v1.0", null);
        seal("e2", T0.plusSeconds(3600), "bob", "GET", "/api/documents/50%_off", "ALLOW", "v1.0", null);
        seal("e3", T0.plusSeconds(7200), "alice", "GET", "/api/customers/C-1", "CHALLENGE", "v2.0", null);
        seal("e4", T0.plusSeconds(10800), "carol", "GET", "/x", "ESCALATE", null, "v0.9");
        seal("e5", T0.plusSeconds(14400), "dave", "GET", "/y", "ALLOW", "v1.0", null);
        seal("outside", Instant.parse("2026-11-25T00:00:00Z"), "erin", "GET", "/z", "BLOCK", "v1.0", null);
        inspected("e1", PromptInspectionVerdict.FAIL, null, finding("SEAL_INTEGRITY", PromptInspectionOutcome.MISMATCH,
                null, null), finding("SOURCE_TRUTH", PromptInspectionOutcome.MISMATCH, "IDENTITY", "department"));
        inspected("e2", PromptInspectionVerdict.PASS, null);
        inspected("e3", PromptInspectionVerdict.INCOMPLETE, null, finding("BUNDLE_TRACE",
                PromptInspectionOutcome.UNVERIFIABLE, null, "promptVersion"));
        inspected("e5", PromptInspectionVerdict.ERROR, "check SOURCE_TRUTH failed");
    }

    @Test
    void theSealedDecisionsOfThePeriodAreListedNewestFirstWithTheThreeChecks() {
        EvidencePage page = queries.evidence(filter(null, null, null, null, null), 0, 20);

        assertThat(page.total()).isEqualTo(5);
        assertThat(page.rows()).extracting(EvidenceRow::packageId).containsExactly("e5", "e4", "e3", "e2", "e1");
        assertThat(page.rows()).extracting(row -> row.integrity() + " " + row.trace() + " " + row.source())
                .containsExactly("UNCHECKED UNCHECKED UNCHECKED", "UNCHECKED UNCHECKED UNCHECKED",
                        "OK UNCHECKED OK", "OK OK OK", "MISMATCH OK MISMATCH");
        EvidenceRow first = page.rows().get(4);
        assertThat(first.userId()).isEqualTo("alice");
        assertThat(first.httpMethod()).isEqualTo("POST");
        assertThat(first.requestPath()).isEqualTo("/api/projects/GB-500/exports");
        assertThat(first.action()).isEqualTo("BLOCK");
        assertThat(first.version()).isEqualTo("v1.0");
        assertThat(first.capturedAt()).isEqualTo(T0);
        assertThat(page.rows().get(1).version()).as("the bundle of the governance descriptor").isEqualTo("v0.9");
        assertThat(page.totals()).isEqualTo(new JdbcPromptInspectionQueries.EvidenceTotals(5, 3, 2, 1, 0, 1));
        // As the sealed prompt list showed them: the latest result's verdict, its counts, its inspector and time.
        assertThat(page.rows()).extracting(EvidenceRow::verdict).containsExactly("ERROR",
                JdbcPromptInspectionQueries.NOT_INSPECTED, "INCOMPLETE", "PASS", "FAIL");
        assertThat(page.rows()).extracting(row -> row.mismatchCount() + "/" + row.unverifiableCount())
                .containsExactly("0/0", "null/null", "0/1", "0/0", "2/0");
        assertThat(page.rows()).extracting(EvidenceRow::inspectorVersion).containsExactly("prompt-inspector/31", null,
                "prompt-inspector/31", "prompt-inspector/31", "prompt-inspector/31");
        assertThat(first.inspectedAt()).isEqualTo(T0.plusSeconds(20_000));
        assertThat(page.rows().get(1).inspectedAt()).isNull();
        assertThat(page.versions()).containsExactly("v0.9", "v1.0", "v2.0");
    }

    @Test
    void theListIsFilteredByActionVersionResultUserPathAndFindingAndPaged() {
        assertThat(ids(filter("BLOCK", null, null, null, null))).containsExactly("e1");
        assertThat(ids(filter(null, "v2.0", null, null, null))).containsExactly("e3");
        assertThat(ids(filter(null, null, "PROBLEM", null, null))).containsExactly("e1");
        assertThat(ids(filter(null, null, "INTEGRITY", null, null))).containsExactly("e1");
        assertThat(ids(filter(null, null, "TRACE", null, null))).isEmpty();
        assertThat(ids(filter(null, null, "SOURCE", null, null))).containsExactly("e1");
        assertThat(ids(filter(null, null, "UNCHECKED", null, null))).containsExactly("e5", "e4", "e3");
        assertThat(ids(filter(null, null, "WHOLE", null, null))).containsExactly("e2");
        assertThat(ids(filter(null, null, null, "alice", null))).containsExactly("e3", "e1");
        assertThat(ids(filter(null, null, null, null, "documents"))).containsExactly("e2");
        assertThat(ids(filter(null, null, null, null, "_"))).as("a wildcard is written as it is").containsExactly("e2");
        assertThat(ids(filter(null, null, null, null, "0%_O"))).as("any case").containsExactly("e2");
        assertThat(ids(new EvidenceFilter(FROM, TO, null, null, null, null, null, "IDENTITY", null, null, null)))
                .containsExactly("e1");
        assertThat(ids(new EvidenceFilter(FROM, TO, null, null, null, null, null, null, "department", null, null)))
                .containsExactly("e1");
        // The sealed prompt list's filters: by the latest result's verdict, none being not inspected, and by a check
        // with a finding of either outcome.
        assertThat(ids(byInspection("FAIL", null))).containsExactly("e1");
        assertThat(ids(byInspection("error", null))).containsExactly("e5");
        assertThat(ids(byInspection(JdbcPromptInspectionQueries.NOT_INSPECTED, null))).containsExactly("e4");
        assertThat(ids(byInspection(null, "BUNDLE_TRACE"))).containsExactly("e3");
        assertThat(ids(byInspection(null, "SOURCE_TRUTH"))).containsExactly("e1");
        assertThat(ids(byInspection("PASS", "SOURCE_TRUTH"))).isEmpty();

        EvidencePage second = queries.evidence(filter(null, null, null, null, null), 1, 2);
        assertThat(second.total()).isEqualTo(5);
        assertThat(second.rows()).extracting(EvidenceRow::packageId).containsExactly("e3", "e2");
        assertThat(second.totals().sealed()).as("the totals are the period's, whatever the filter").isEqualTo(5);
        assertThatThrownBy(() -> queries.evidence(filter(null, null, "BROKEN", null, null), 0, 20))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /**
     * One sealed decision: what it was made from read from its sealed sections, the audit inspected again, the facts
     * of its user prompt with the findings on their lines, and its replays from the audit log, newest first.
     */
    @Test
    void aSealedDecisionReadsWhatItWasMadeFromWhatWentIntoItAndItsReplays() {
        SealedEvidencePackage sealed = packages.findByPackageId("e1").orElseThrow();
        sealed.setUserPromptText("=== REQUEST ===\n[R1] Target: /api/projects/GB-500/exports\n"
                + "[R3] Network: 203.0.113.77\nNote: no fact id here\n");
        sealed.setSystemPromptText("You are the analyst.");
        sealed.setDecisionJson("{\"action\":\"BLOCK\",\"reasoning\":\"engine words\",\"llmReasoning\":\"model words\","
                + "\"reasonCodes\":[{\"code\":\"NET\",\"fact\":\"R3\"},{\"code\":\"TGT\",\"fact\":\"R1\"},"
                + "{\"code\":\"NET2\",\"fact\":\"R3\"}],\"hypotheses\":[{\"id\":\"H1\",\"assessment\":\"UNLIKELY\"},"
                + "{\"id\":\"H2\",\"assessment\":\"MOST_LIKELY\"}],\"decisionAppliedStage\":\"SHADOW\"}");
        sealed.setPromptExecutionMetadataJson("{\"promptVersionName\":\"v1.0\",\"runtimeModelId\":\"qwen3:8b\"}");
        jdbc.update("update ctxa_sealed_evidence_package set user_prompt_text = ?, system_prompt_text = ?,"
                + " decision_json = ?, prompt_execution_metadata_json = ? where package_id = 'e1'",
                sealed.getUserPromptText(), sealed.getSystemPromptText(), sealed.getDecisionJson(),
                sealed.getPromptExecutionMetadataJson());
        replayed("correlation-e1", "e1", "BLOCK", 7836, T0.plusSeconds(600));
        replayed("correlation-e1", "e1", "ALLOW", null, T0.plusSeconds(300));
        replayed("correlation-e1", "another-package", "ALLOW", 10, T0.plusSeconds(900));
        jdbc.update("insert into ctxa_audit_log (timestamp, principal_name, resource_identifier, action, decision,"
                + " details) values (?, 'admin-a', 'correlation-e1', 'PROMPT_VERSION_USED', 'RECORDED', '{}')",
                Timestamp.from(T0.plusSeconds(950)));
        PromptInspector inspector = mock(PromptInspector.class);
        PromptInspectionFinding onLine = PromptInspectionFinding.builder("SOURCE_TRUTH",
                PromptInspectionOutcome.UNVERIFIABLE).block("REQUEST").entry("Network").factId("R3").lineNumber(3)
                .reason("no source").build();
        PromptInspectionFinding unplaced = PromptInspectionFinding.builder("SEAL_INTEGRITY",
                PromptInspectionOutcome.MISMATCH).reason("changed after sealing").build();
        when(inspector.inspect(any(SealedEvidencePackage.class))).thenReturn(new PromptInspectionResult("e1",
                "prompt-inspector/31", "dictionary-v1", "v1-layout", PromptInspectionVerdict.FAIL, List.of(
                new PromptInspectionCheckResult("SEAL_INTEGRITY", 5, 1, 0, List.of(unplaced)),
                new PromptInspectionCheckResult("SOURCE_TRUTH", 3, 0, 1, List.of(onLine))), null));
        SealedEvidenceDetails details = new SealedEvidenceDetails(packages,
                new PromptInspectionConsole(packages, inspector, results, JSON), () -> jdbc, JSON);

        SealedEvidenceDetails.Detail detail = details.detail("e1").orElseThrow();

        assertThat(detail.requestId()).isEqualTo("correlation-e1");
        assertThat(detail.userId()).isEqualTo("alice");
        assertThat(detail.httpMethod() + " " + detail.requestPath()).isEqualTo("POST /api/projects/GB-500/exports");
        assertThat(detail.action()).isEqualTo("BLOCK");
        assertThat(detail.stage()).isEqualTo("SHADOW");
        assertThat(detail.version()).isEqualTo("v1.0");
        assertThat(detail.model()).isEqualTo("qwen3:8b");
        assertThat(detail.reason()).as("the model's words before the engine's").isEqualTo("model words");
        assertThat(detail.hypothesis()).isEqualTo("H2");
        assertThat(detail.citedFacts()).containsExactly("R3", "R1");
        assertThat(detail.systemPrompt()).isEqualTo("You are the analyst.");
        assertThat(detail.facts()).extracting(fact -> fact.id() + " " + fact.line() + " " + fact.block() + " "
                + fact.label() + "=" + fact.value() + " " + fact.findings().size())
                .containsExactly("R1 2 REQUEST Target=/api/projects/GB-500/exports 0", "R3 3 REQUEST Network=203.0.113.77 1");
        assertThat(detail.checks()).extracting(check -> check.code() + " " + check.result() + " " + check.matched() + "/"
                + check.mismatched() + "/" + check.unverifiable() + " " + check.findings().size())
                .containsExactly("SEAL_INTEGRITY MISMATCH 5/1/0 1", "BUNDLE_TRACE UNCHECKED 0/0/0 0",
                        "SOURCE_TRUTH UNCHECKED 3/0/1 1");
        assertThat(detail.inspection().verdict()).isEqualTo("FAIL");
        assertThat(detail.inspection().stored()).as("the stored result of the fixture").isNotNull();
        assertThat(detail.replays()).extracting(replay -> replay.action() + " " + replay.same() + " "
                + replay.elapsedMs() + " " + replay.actor())
                .containsExactly("BLOCK true 7836 admin-a", "ALLOW false null admin-a");
        assertThat(detail.replays().get(0).at()).isEqualTo(T0.plusSeconds(600));
        assertThat(details.detail("nowhere")).isEmpty();
    }

    /** An inspection that failed checked nothing: the three checks read as not checked. */
    @Test
    void aFailedInspectionChecksNothing() {
        PromptInspector inspector = mock(PromptInspector.class);
        when(inspector.inspect(any(SealedEvidencePackage.class))).thenReturn(new PromptInspectionResult("e5",
                "prompt-inspector/31", null, null, PromptInspectionVerdict.ERROR, List.of(
                new PromptInspectionCheckResult("SEAL_INTEGRITY", 4, 0, 0, List.of())), "check SOURCE_TRUTH failed"));
        SealedEvidenceDetails details = new SealedEvidenceDetails(packages,
                new PromptInspectionConsole(packages, inspector, results, JSON), () -> null, JSON);

        SealedEvidenceDetails.Detail detail = details.detail("e5").orElseThrow();

        assertThat(detail.checks()).extracting(SealedEvidenceDetails.Check::result)
                .containsOnly(JdbcPromptInspectionQueries.RESULT_UNCHECKED);
        assertThat(detail.inspection().errorReason()).isEqualTo("check SOURCE_TRUTH failed");
        assertThat(detail.replays()).as("no audit log to read").isEmpty();
        assertThat(detail.stage()).isEqualTo("DECISION");
    }

    private void seal(String packageId, Instant capturedAt, String user, String method, String path, String action,
                      String versionName, String bundle) {
        String facts = "{\"httpMethod\":\"" + method + "\",\"requestPath\":\"" + path + "\",\"resourceId\":\"r-"
                + packageId + "\"}";
        String metadata = versionName != null ? "{\"promptVersionName\":\"" + versionName + "\"}"
                : "{\"governanceDescriptor\":{\"promptBundleVersion\":\"" + bundle + "\"}}";
        packages.save(SealedEvidencePackage.builder().packageId(packageId).correlationId("correlation-" + packageId)
                .idempotencyKey("key-" + packageId).tenantId("default").userId(user).capturedAt(capturedAt)
                .requestFactsJson(facts).decisionJson("{\"action\":\"" + action + "\"}")
                .promptExecutionMetadataJson(metadata).systemPromptText("system").userPromptText("user")
                .packageHash("hash-" + packageId).expiresAt(capturedAt.plusSeconds(86_400 * 30L)).build());
    }

    private void inspected(String packageId, PromptInspectionVerdict verdict, String error,
                           PromptInspectionFinding... findings) {
        List<PromptInspectionCheckResult> checks = List.of(findings).stream().map(finding ->
                new PromptInspectionCheckResult(finding.checkCode(), 2,
                        finding.outcome() == PromptInspectionOutcome.MISMATCH ? 1 : 0,
                        finding.outcome() == PromptInspectionOutcome.UNVERIFIABLE ? 1 : 0, List.of(finding))).toList();
        results.save(new PromptInspectionResult(packageId, "prompt-inspector/31", "dictionary-v1", "v1-layout", verdict,
                checks, error), PromptInspectionTrigger.AUTO, T0.plusSeconds(20_000));
    }

    private static PromptInspectionFinding finding(String check, PromptInspectionOutcome outcome, String block,
                                                   String entry) {
        return PromptInspectionFinding.builder(check, outcome).block(block).entry(entry).reason("found").build();
    }

    private static void replayed(String requestId, String packageId, String action, Integer elapsedMs, Instant at) {
        String details = "{\"requestId\":\"" + requestId + "\",\"packageId\":\"" + packageId
                + "\",\"bundleVersion\":\"v1.0\",\"baselines\":\"SEALED\",\"integrity\":\"VERIFIED\","
                + "\"outcome\":\"ANSWERED\",\"action\":\"" + action + "\""
                + (elapsedMs != null ? ",\"elapsedMs\":" + elapsedMs : "") + "}";
        jdbc.update("insert into ctxa_audit_log (timestamp, principal_name, resource_identifier, action, decision,"
                + " details, outcome) values (?, 'admin-a', ?, 'SEALED_DECISION_REPLAYED', 'RECORDED', ?, 'ANSWERED')",
                Timestamp.from(at), requestId, details);
    }

    private List<String> ids(EvidenceFilter filter) {
        return queries.evidence(filter, 0, 20).rows().stream().map(EvidenceRow::packageId).toList();
    }

    private static EvidenceFilter filter(String action, String version, String result, String user, String path) {
        return new EvidenceFilter(FROM, TO, action, version, result, user, path, null, null, null, null);
    }

    private static EvidenceFilter byInspection(String verdict, String checkCode) {
        return new EvidenceFilter(FROM, TO, null, null, null, null, null, null, null, verdict, checkCode);
    }
}
