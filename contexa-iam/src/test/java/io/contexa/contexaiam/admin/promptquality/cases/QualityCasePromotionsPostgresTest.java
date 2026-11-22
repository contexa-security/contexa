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
package io.contexa.contexaiam.admin.promptquality.cases;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustDecisionOutcomes;
import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseClass;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseKind;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseRationale;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.evidence.JdbcSealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.BreachConfirmed;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Evaluation;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustDecisionRecords;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
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
import java.sql.Date;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Quality plan 3.6 on a database with the schema of a new installation: a decision of the operation is made a case
 * from the decision detail with its evaluation, or from a trial whose two versions decided it differently; a decision
 * that is not sealed is refused as such; a case promoted from the second analysis is marked and counted apart; and an
 * allowed decision is confirmed a breach.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class QualityCasePromotionsPostgresTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final String SCOPE = PromptVersionService.PLATFORM_SCOPE;
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static final Instant AT = Instant.parse("2026-11-21T10:00:00Z");
    private static final Clock CLOCK = Clock.fixed(AT.plusSeconds(3_600), ZoneOffset.UTC);
    private static final Map<String, PromptVersionService.RegistryTarget> TARGETS = Map.of(PROMPT,
            new PromptVersionService.RegistryTarget("SecurityDecisionStandard", "CORTEX_PROMPT_CONTRACT_V5",
                    "SecurityDecisionStandardPromptTemplate", "contexa-cortex-core"));
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;
    private static QualityCase threat;

    private ExecutorService executor;
    private PromptQualityCases cases;
    private ZeroTrustDecisionRecords records;
    private QualityCasePromotions promotions;

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
        threat = QualityCaseSetReader.contexaDefault().cases().stream().filter(QualityCase::shouldStop).findFirst()
                .orElseThrow();
    }

    @AfterAll
    static void close() {
        if (database != null) {
            database.close();
        }
    }

    @BeforeEach
    void noDecisionsNorCases() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_case_cause, ctxa_prompt_version_measure_answer,"
                + " ctxa_prompt_version_measure, ctxa_prompt_version_case_set_member, ctxa_prompt_version_case_set,"
                + " ctxa_prompt_version_case_change, ctxa_prompt_version_case, ctxa_prompt_version_trial_case,"
                + " ctxa_prompt_version_trial, ctxa_sealed_evidence_package, ctxa_ai_security_decision_observation,"
                + " ctxa_zt_decision_outcome, ctxa_zt_review_queue CASCADE");
        QualityCaseSet shipped = new QualityCaseSet("test", List.of(threat));
        cases = new PromptQualityCases(() -> jdbc, JSON, true, PromptVersionAudit.none(), CLOCK, null, () -> shipped);
        records = new ZeroTrustDecisionRecords(() -> jdbc, new ZeroTrustDecisionOutcomes(() -> jdbc, CLOCK), null,
                JSON, CLOCK);
        executor = Executors.newSingleThreadExecutor();
        PromptVersionService versions = new PromptVersionService(() -> jdbc,
                SecurityDecisionPromptDocument.productReleases(), TARGETS, PromptVersionAudit.none(), CLOCK);
        PromptVersionTrials trials = new PromptVersionTrials(() -> jdbc, versions,
                (actor, packageId, version) -> Optional.empty(), executor, PromptVersionAudit.none(), CLOCK);
        promotions = new QualityCasePromotions(() -> jdbc, cases, new JdbcSealedEvidencePackageRepository(jdbc),
                records, () -> trials, new TransactionTemplate(new DataSourceTransactionManager(database.dataSource())));
    }

    @AfterEach
    void stop() {
        executor.shutdownNow();
    }

    /**
     * From the decision detail: the evaluation and the case are kept together; the case is the decision's sealed
     * input and names its package, and the review entry is closed.
     */
    @Test
    void anEvaluatedDecisionIsMadeACaseWithItsEvaluation() {
        decision("allowed-1", "ALLOW", "request-1");
        seal("allowed-1", "package-1", 1, "SEALED");
        jdbc.update("INSERT INTO ctxa_zt_review_queue (observation_id, sample_day, review_reason) VALUES (?, ?, ?)",
                "allowed-1", Date.valueOf("2026-11-21"), "SAMPLE");

        QualityCasePromotions.Promoted promoted = promotions.fromEvaluation(null, "allowed-1",
                new Evaluation(false, "missed_signal", "an outsider"), threatAnswer(), QualityCaseGrade.ORDINARY,
                "admin-a");

        assertThat(promoted.sealedPackageId()).isEqualTo("package-1");
        assertThat(promoted.observationId()).isEqualTo("allowed-1");
        assertThat(promoted.evaluation().kind()).isEqualTo("EVALUATED_INVALID");
        assertThat(promoted.kept().sealedPackageId()).isEqualTo("package-1");
        assertThat(promoted.kept().subjectUserId()).isEqualTo("alice");
        assertThat(promoted.kept().secondAnalysis()).isFalse();
        assertThat(promoted.kept().scope()).isEqualTo(SCOPE);
        assertThat(promoted.kept().item().input().canonicalContext()).isEqualTo(threat.input().canonicalContext());
        assertThat(jdbc.queryForMap("SELECT outcome_kind, evaluation_reason, actor, note FROM ctxa_zt_decision_outcome"
                + " WHERE observation_id = 'allowed-1'")).containsEntry("outcome_kind", "EVALUATED_INVALID")
                .containsEntry("evaluation_reason", "MISSED_SIGNAL").containsEntry("actor", "admin-a")
                .containsEntry("note", "an outsider");
        assertThat(jdbc.queryForObject("SELECT review_status FROM ctxa_zt_review_queue WHERE observation_id = ?",
                String.class, "allowed-1")).isEqualTo("REVIEWED");
    }

    /**
     * A decision without a sealed package, or whose seal did not hold, is refused as not sealed, and nothing of it is
     * kept; a decision that does not exist is refused as not found.
     */
    @Test
    void aDecisionThatIsNotSealedIsRefusedAndNothingIsKept() {
        decision("unsealed", "ALLOW", "request-u");
        decision("failed-seal", "BLOCK", "request-f");
        seal("failed-seal", "package-f", 1, "FAILED");

        for (String observation : List.of("unsealed", "failed-seal")) {
            assertThatThrownBy(() -> promotions.fromEvaluation(SCOPE, observation, new Evaluation(true, null, null),
                    threatAnswer(), QualityCaseGrade.ORDINARY, "admin-a"))
                    .isInstanceOfSatisfying(PromptQualityCases.RefusedException.class, refused -> {
                        assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.NOT_SEALED);
                        assertThat(refused.getMessage()).contains("is not sealed");
                    });
        }
        assertThatThrownBy(() -> promotions.fromEvaluation(SCOPE, "nobody", new Evaluation(true, null, null),
                threatAnswer(), QualityCaseGrade.ORDINARY, "admin-a"))
                .isInstanceOfSatisfying(PromptQualityCases.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.NOT_FOUND));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ctxa_zt_decision_outcome", Integer.class)).isZero();
        assertThat(cases.list(SCOPE, PROMPT)).isEmpty();
    }

    /** An answer the case cannot have refuses the case, and the evaluation made with it is not kept either. */
    @Test
    void anAnswerThatCannotBeACaseLeavesTheEvaluationUnkept() {
        decision("allowed-2", "ALLOW", "request-2");
        seal("allowed-2", "package-2", 1, "SEALED");
        QualityCaseExpectation allows = new QualityCaseExpectation(EnumSet.of(QualityAction.ALLOW), null,
                QualityCaseClass.THREAT, QualityCaseKind.OUTSIDER, new QualityCaseRationale("까닭", "why"), List.of());

        assertThatThrownBy(() -> promotions.fromEvaluation(SCOPE, "allowed-2", new Evaluation(true, null, null), allows,
                QualityCaseGrade.MUST_CATCH, "admin-a"))
                .isInstanceOfSatisfying(PromptQualityCases.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.INVALID));
        assertThatThrownBy(() -> promotions.fromEvaluation(SCOPE, "allowed-2", new Evaluation(null, null, null),
                threatAnswer(), QualityCaseGrade.ORDINARY, "admin-a")).isInstanceOf(IllegalArgumentException.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ctxa_zt_decision_outcome", Integer.class)).isZero();
        assertThat(cases.list(SCOPE, PROMPT)).isEmpty();
    }

    /**
     * A case promoted from a decision the second analysis decided is marked, and counted apart from the other cases of
     * the operation; a copy of it keeps the mark.
     */
    @Test
    void aCaseOfTheSecondAnalysisIsMarkedAndCountedApart() {
        decision("first-pass", "ALLOW", "request-a");
        seal("first-pass", "package-a", 1, "SEALED");
        decision("second-pass", "ALLOW", "request-b");
        seal("second-pass", "package-b", 2, "SEALED");

        PromptQualityCases.Kept first = promotions.fromEvaluation(SCOPE, "first-pass", new Evaluation(true, null, null),
                threatAnswer(), QualityCaseGrade.ORDINARY, "admin-a").kept();
        PromptQualityCases.Kept second = promotions.fromEvaluation(SCOPE, "second-pass",
                new Evaluation(false, "MISSED_SIGNAL", null), threatAnswer(), QualityCaseGrade.ORDINARY, "admin-a")
                .kept();
        PromptQualityCases.Kept copy = cases.copy(SCOPE, PROMPT, second.key(), null, threatAnswer(),
                QualityCaseGrade.ORDINARY, "admin-b");

        assertThat(first.secondAnalysis()).isFalse();
        assertThat(second.secondAnalysis()).isTrue();
        assertThat(copy.secondAnalysis()).isTrue();
        assertThat(cases.kept(SCOPE, PROMPT, second.key()).orElseThrow().secondAnalysis()).isTrue();
        assertThat(cases.counts(SCOPE, PROMPT)).isEqualTo(new PromptQualityCases.Counts(3, 2, 2, 3));
        assertThat(cases.counts("tenant-other", PROMPT)).isEqualTo(new PromptQualityCases.Counts(0, 0, 0, 0));
    }

    /**
     * From a trial: only a sealed decision the two versions decided with different actions is made a case, in the
     * trial's scope; the others are refused as not divergent, a package gone is refused as not sealed.
     */
    @Test
    void aDecisionTheTwoVersionsOfATrialDecidedDifferentlyIsMadeACase() {
        decision("diverged", "ALLOW", "request-d");
        seal("diverged", "package-d", 2, "SEALED");
        decision("same", "ALLOW", "request-s");
        seal("same", "package-s", 1, "SEALED");
        long trial = jdbc.queryForObject("INSERT INTO ctxa_prompt_version_trial (registry_scope, prompt_key,"
                + " candidate_number, reference_number, requested_count, actual_count, status, created_by, created_at)"
                + " VALUES ('tenant-a', ?, 2, 1, 20, 4, 'DONE', 'admin', ?) RETURNING id", Long.class, PROMPT,
                Timestamp.from(AT));
        trialCase(trial, "package-d", "diverged", 1, "ALLOW");
        trialCase(trial, "package-d", "diverged", 2, "BLOCK");
        trialCase(trial, "package-s", "same", 1, "ALLOW");
        trialCase(trial, "package-s", "same", 2, "ALLOW");
        trialCase(trial, "package-half", null, 1, "ALLOW");
        trialCase(trial, "package-half", null, 2, null);
        trialCase(trial, "package-gone", null, 1, "ALLOW");
        trialCase(trial, "package-gone", null, 2, "CHALLENGE");

        assertThat(promotions.divergent(trial)).extracting(QualityCasePromotions.Divergent::sealedPackageId)
                .containsExactly("package-d", "package-gone");
        assertThat(promotions.divergent(trial).get(0)).isEqualTo(new QualityCasePromotions.Divergent("package-d",
                "request-d", "diverged", "ALLOW", "BLOCK"));

        QualityCasePromotions.Promoted promoted = promotions.fromTrial(trial, "package-d", threatAnswer(),
                QualityCaseGrade.ORDINARY, "admin-a");
        assertThat(promoted.kept().scope()).isEqualTo("tenant-a");
        assertThat(promoted.kept().sealedPackageId()).isEqualTo("package-d");
        assertThat(promoted.kept().secondAnalysis()).isTrue();
        assertThat(promoted.evaluation()).isNull();
        assertThat(promoted.observationId()).isEqualTo("diverged");
        for (String packageId : List.of("package-s", "package-half")) {
            assertThatThrownBy(() -> promotions.fromTrial(trial, packageId, threatAnswer(), QualityCaseGrade.ORDINARY,
                    "admin-a")).isInstanceOfSatisfying(PromptQualityCases.RefusedException.class,
                    refused -> assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.NOT_DIVERGENT));
        }
        assertThatThrownBy(() -> promotions.fromTrial(trial, "package-gone", threatAnswer(), QualityCaseGrade.ORDINARY,
                "admin-a")).isInstanceOfSatisfying(PromptQualityCases.RefusedException.class,
                refused -> assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.NOT_SEALED));
        assertThatThrownBy(() -> promotions.fromTrial(trial + 99, "package-d", threatAnswer(),
                QualityCaseGrade.ORDINARY, "admin-a")).isInstanceOfSatisfying(PromptQualityCases.RefusedException.class,
                refused -> assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.NOT_FOUND));
        assertThat(cases.list("tenant-a", PROMPT)).hasSize(1);
    }

    /**
     * Quality plan 3.6: an allowed decision is confirmed a breach by its request, once; a decision that did not allow
     * is refused, and a request without a decision has none.
     */
    @Test
    void anAllowedDecisionIsConfirmedABreachOnceAndAStoppedOneIsRefused() {
        decision("allowed-breach", "ALLOW", "request-breach");
        decision("blocked", "BLOCK", "request-blocked");

        BreachConfirmed confirmed = records.confirmBreach("request-breach", " found by the audit ", "admin-a");
        BreachConfirmed again = records.confirmBreach("request-breach", "again", "admin-b");

        assertThat(confirmed.already()).isFalse();
        assertThat(confirmed.observationId()).isEqualTo("allowed-breach");
        assertThat(again.already()).isTrue();
        assertThat(again.outcomeId()).isEqualTo(confirmed.outcomeId());
        assertThat(jdbc.queryForList("SELECT outcome_kind, actor, note, request_id FROM ctxa_zt_decision_outcome"
                + " WHERE observation_id = 'allowed-breach'")).singleElement().satisfies(row -> assertThat(row)
                .containsEntry("outcome_kind", ZeroTrustDecisionOutcomes.Kind.ALLOWED_BREACH_CONFIRMED.name())
                .containsEntry("actor", "admin-a").containsEntry("note", "found by the audit")
                .containsEntry("request_id", "request-breach"));
        assertThatThrownBy(() -> records.confirmBreach("request-blocked", null, "admin-a"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("BLOCK");
        assertThatThrownBy(() -> records.confirmBreach(" ", null, "admin-a"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(records.confirmBreach("request-none", null, "admin-a")).isNull();
    }

    // ----- fixtures -----

    private static QualityCaseExpectation threatAnswer() {
        return new QualityCaseExpectation(EnumSet.of(QualityAction.BLOCK, QualityAction.CHALLENGE), null,
                QualityCaseClass.THREAT, QualityCaseKind.OUTSIDER, new QualityCaseRationale("정답인 까닭", "Why"),
                List.of());
    }

    private static void decision(String observationId, String action, String requestId) {
        jdbc.update("INSERT INTO ctxa_ai_security_decision_observation (observation_id, idempotency_key, request_id,"
                + " user_id, final_action, attempt_kind, success, created_at) VALUES (?, ?, ?, 'alice', ?, 'FIRST', TRUE,"
                + " ?)", observationId, "key-" + observationId, requestId, action, Timestamp.from(AT));
    }

    /** The default threat case sealed as the decision's package, with the analysis depth it was decided at. */
    private static void seal(String observationId, String packageId, int analysisLevel, String state) {
        SealedEvidencePackage sealed = QualityCaseSealedForm.sealed(threat);
        sealed.setPackageId(packageId);
        sealed.setCorrelationId(jdbc.queryForObject("SELECT request_id FROM ctxa_ai_security_decision_observation"
                + " WHERE observation_id = ?", String.class, observationId));
        sealed.setIdempotencyKey("key-" + observationId);
        sealed.setUserId("alice");
        ObjectNode facts = (ObjectNode) threat.input().requestFacts().deepCopy();
        facts.put("userId", "alice");
        sealed.setRequestFactsJson(facts.toString());
        sealed.setCapturedAt(AT);
        sealed.setPackageHash("hash-" + packageId);
        sealed.setSealState(state);
        sealed.setDecisionJson("{\"aiAnalysisLevel\":" + analysisLevel + ",\"action\":\"ALLOW\"}");
        new JdbcSealedEvidencePackageRepository(jdbc).save(sealed);
    }

    private static void trialCase(long trial, String packageId, String observationId, int version, String action) {
        jdbc.update("INSERT INTO ctxa_prompt_version_trial_case (trial_id, sealed_package_id, observation_id,"
                + " version_number, action) VALUES (?, ?, ?, ?, ?)", trial, packageId, observationId, version, action);
    }
}
