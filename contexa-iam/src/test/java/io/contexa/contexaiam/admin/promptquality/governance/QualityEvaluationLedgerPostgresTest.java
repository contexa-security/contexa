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
package io.contexa.contexaiam.admin.promptquality.governance;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceEvaluationRecord;
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.measure.QualityEvaluationLedger;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionResolver;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Quality plan 2.1, 3.9 (supplement U1): once a measurement of a version is done, the evaluation ledger row of that
 * version names it, through the JPA repository of the table: the reference of the measurement, the measurement as the
 * run and the content hash of the version as the bundle, in the state MEASURED. A later measurement writes the same row
 * over; a measurement that is not done leaves it as it is. The release gate of the version is what it was before: its
 * targets, blockers and warnings do not change, and its evidence shows the measurement.
 */
class QualityEvaluationLedgerPostgresTest {

    private static final String SCOPE = PromptVersionService.PLATFORM_SCOPE;
    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final Map<String, PromptVersionService.RegistryTarget> TARGETS = Map.of(PROMPT,
            new PromptVersionService.RegistryTarget("SecurityDecisionStandard", "CORTEX_PROMPT_CONTRACT_V5",
                    "SecurityDecisionStandardPromptTemplate", "contexa-cortex-core"));
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-23T09:00:00Z"), ZoneOffset.UTC);
    private static final ObjectMapper JSON = new ObjectMapper();
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;
    private static EntityManagerFactory entityManagerFactory;
    private static TransactionTemplate transaction;
    private static PromptGovernanceRegistryRepository registry;
    private static PromptGovernanceRollbackRecordRepository rollbackLedger;
    private static PromptGovernanceChangeRecordRepository changes;
    private static PromptGovernanceEvaluationRecordRepository evaluations;
    private static PromptGovernanceReleaseApprovalRepository approvals;
    private static PromptGovernanceReleaseWorkflowRepository workflows;
    private static PromptGovernanceModelCompatibilityRepository compatibility;
    private static PromptGovernanceBudgetProfileRepository budgets;

    private PromptVersionService versions;
    private PromptQualityCases cases;
    private PromptGovernanceReleaseGateService gate;

    @BeforeAll
    static void aDatabaseWithTheSchemaAndTheGovernanceEntities() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        String schema = new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        try (Connection connection = database.dataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.setEscapeProcessing(false);
            statement.execute(schema);
        }
        LocalContainerEntityManagerFactoryBean factory = new LocalContainerEntityManagerFactoryBean();
        factory.setDataSource(database.dataSource());
        factory.setPackagesToScan("io.contexa.contexacore.domain.entity.prompt");
        factory.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        factory.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto", "none",
                "hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect",
                "hibernate.physical_naming_strategy",
                "org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy"));
        factory.afterPropertiesSet();
        entityManagerFactory = factory.getObject();
        transaction = new TransactionTemplate(new JpaTransactionManager(entityManagerFactory));
        EntityManager shared = SharedEntityManagerCreator.createSharedEntityManager(entityManagerFactory);
        JpaRepositoryFactory repositories = new JpaRepositoryFactory(shared);
        registry = repositories.getRepository(PromptGovernanceRegistryRepository.class);
        rollbackLedger = repositories.getRepository(PromptGovernanceRollbackRecordRepository.class);
        changes = repositories.getRepository(PromptGovernanceChangeRecordRepository.class);
        evaluations = repositories.getRepository(PromptGovernanceEvaluationRecordRepository.class);
        approvals = repositories.getRepository(PromptGovernanceReleaseApprovalRepository.class);
        workflows = repositories.getRepository(PromptGovernanceReleaseWorkflowRepository.class);
        compatibility = repositories.getRepository(PromptGovernanceModelCompatibilityRepository.class);
        budgets = repositories.getRepository(PromptGovernanceBudgetProfileRepository.class);
    }

    @AfterAll
    static void close() {
        if (entityManagerFactory != null) {
            entityManagerFactory.close();
        }
        if (database != null) {
            database.close();
        }
    }

    /** v1.0 is the product version and used for decisions; v2.0 is an organization's version, not used. */
    @BeforeEach
    void twoVersionsAndAPublishedCaseSet() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_measure_answer, ctxa_prompt_version_measure,"
                + " ctxa_prompt_version_case_set_member, ctxa_prompt_version_case_set, ctxa_prompt_version_case_change,"
                + " ctxa_prompt_version_case, ctxa_prompt_version_part, ctxa_prompt_version_trial_case,"
                + " ctxa_prompt_version_trial, ctxa_prompt_version, ctxa_prompt_governance_registry,"
                + " ctxa_prompt_governance_eval_ledger, ctxa_prompt_governance_release_workflow,"
                + " ctxa_prompt_governance_release_ledger, ctxa_prompt_governance_rollback_ledger CASCADE");
        versions = new PromptVersionService(() -> jdbc, SecurityDecisionPromptDocument.productReleases(), TARGETS, null,
                CLOCK);
        versions.registerProducts(null);
        versions.create(null, "prompt: " + PROMPT + "\nbasedOn: v1.0\ntitle: Finance closing\nsystem:\n"
                + "  - key: how-to-judge\n    text: |\n      1. Weigh the duty roster first.\n",
                PromptVersionRecord.SCREEN, null, "admin", null);
        jdbc.update("update ctxa_prompt_governance_registry set release_status = 'ACTIVE', updated_at = ? where"
                + " prompt_version = 'v1.0'", Timestamp.from(CLOCK.instant()));
        QualityCaseSet all = QualityCaseSetReader.contexaDefault();
        List<QualityCase> some = new ArrayList<>(all.cases().stream().filter(QualityCase::shouldStop).limit(2).toList());
        some.addAll(all.cases().stream().filter(item -> !item.shouldStop()).limit(2).toList());
        QualityCaseSet shipped = new QualityCaseSet(all.name(), some);
        cases = new PromptQualityCases(() -> jdbc, JSON, false, PromptVersionAudit.none(), CLOCK, null, () -> shipped);
        PromptVersionResolver resolver = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc,
                JSON, 60_000L, 0L).registrySelector(), versions, () -> null, CLOCK);
        gate = new PromptGovernanceReleaseGateService(null, registry, changes, evaluations, approvals, rollbackLedger,
                workflows, compatibility, budgets, new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> resolver));
    }

    @Test
    void aDoneMeasurementIsNamedByTheLedgerRowOfItsVersionAndTheGateIsUnchanged() {
        PromptQualityCases.PublishedSet set = cases.publishDefault(SCOPE, PROMPT, "admin");
        String content = versions.find(SCOPE, PROMPT, 2).orElseThrow().contentHash();
        List<String> before = targets(assess());
        QualityEvaluationLedger ledger = new QualityEvaluationLedger(() -> jdbc, evaluations, CLOCK);

        long first = measure(set, content, PromptQualityMeasurements.DONE, "admin");
        assertThat(recorded(ledger, first)).isTrue();

        PromptGovernanceEvaluationRecord row = only();
        assertThat(row.getRegistryScope()).isEqualTo(SCOPE);
        assertThat(row.getPromptKey()).isEqualTo(PROMPT);
        assertThat(row.getEvaluationReference()).isEqualTo("ctxa_prompt_version_measure:" + first);
        assertThat(row.getRunReference()).isEqualTo(String.valueOf(first));
        assertThat(row.getBundleHash()).isEqualTo(content);
        assertThat(row.getEvaluationState()).isEqualTo(QualityEvaluationLedger.MEASURED);
        assertThat(row.getEvaluationMode()).isEqualTo(QualityEvaluationLedger.MODE);
        assertThat(row.getRegistrationSource()).isEqualTo(QualityEvaluationLedger.SOURCE);
        assertThat(row.getEvaluatedBy()).isEqualTo("admin");
        assertThat(row.getEvaluationSummary()).contains("Quality measurement " + first + " of v2.0 is done")
                .contains(set.version()).contains("3 runs");
        LocalDateTime created = row.getCreatedAt();

        PromptGovernanceReleaseGateService.ReleaseGateAssessment after = assess();
        assertThat(targets(after)).as("the gate of the version is what it was").isEqualTo(before);
        assertThat(after.evidence().evaluationReference()).isEqualTo("ctxa_prompt_version_measure:" + first);
        assertThat(after.evidence().evaluationState()).isEqualTo(QualityEvaluationLedger.MEASURED);

        // A later measurement writes the same row over; one that is not done leaves it as it is.
        long second = measure(set, content, PromptQualityMeasurements.DONE, "contexa-auto-measure");
        assertThat(recorded(ledger, second)).isTrue();
        long running = measure(set, content, PromptQualityMeasurements.RUNNING, "admin");
        assertThat(recorded(ledger, running)).isFalse();
        assertThat(recorded(ledger, 999_999L)).isFalse();

        PromptGovernanceEvaluationRecord over = only();
        assertThat(over.getId()).isEqualTo(row.getId());
        assertThat(over.getEvaluationReference()).isEqualTo("ctxa_prompt_version_measure:" + second);
        assertThat(over.getRunReference()).isEqualTo(String.valueOf(second));
        assertThat(over.getEvaluatedBy()).isEqualTo("contexa-auto-measure");
        assertThat(over.getCreatedAt()).isEqualTo(created);
        assertThat(targets(assess())).isEqualTo(before);
    }

    // ----- fixtures -----

    /** The ledger's write in a transaction of the JPA repository, as the application's repositories make one. */
    private static boolean recorded(QualityEvaluationLedger ledger, long measureId) {
        Boolean written = transaction.execute(status -> ledger.record(measureId));
        return Boolean.TRUE.equals(written);
    }

    private PromptGovernanceReleaseGateService.ReleaseGateAssessment assess() {
        return transaction.execute(status -> gate.assessPromptRelease(SCOPE, PROMPT, "v2.0"));
    }

    /** What the gate says of each target: its readiness, gate state, blockers and warnings. */
    private static List<String> targets(PromptGovernanceReleaseGateService.ReleaseGateAssessment assessment) {
        return assessment.targets().stream().map(target -> target.targetState() + " " + target.ready() + " "
                + target.gateState() + " " + target.blockers() + " " + target.warnings()).toList();
    }

    private static PromptGovernanceEvaluationRecord only() {
        List<PromptGovernanceEvaluationRecord> rows = evaluations.findAll().stream()
                .filter(row -> "v2.0".equals(row.getPromptVersion())).toList();
        assertThat(rows).hasSize(1);
        return rows.get(0);
    }

    private static long measure(PromptQualityCases.PublishedSet set, String content, String status, String by) {
        return jdbc.queryForObject("insert into ctxa_prompt_version_measure (registry_scope, prompt_key,"
                + " version_number, version_content_hash, case_set_id, case_set_version, repeats, settings_hash,"
                + " settings, model_setting, closing_rules, status, planned_answers, reusable_answers,"
                + " expected_min_calls, expected_max_calls, call_limit, created_by, created_at) values"
                + " (?, ?, 2, ?, ?, ?, 3, 'hash', '{}', 'settings=hash;models=model-a', 'test', ?, 12, 0, 12, 48, 0,"
                + " ?, ?) returning id", Long.class, SCOPE, PROMPT, content, set.id(), set.version(), status, by,
                Timestamp.from(CLOCK.instant()));
    }
}
