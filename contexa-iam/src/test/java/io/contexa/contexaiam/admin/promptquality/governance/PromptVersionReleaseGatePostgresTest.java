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
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentException;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionProblem;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsole;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Created;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.DraftForm;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.FormPart;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.UseCheck;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionResolver;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionTrials;
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
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Plan 3.9: the release ledgers, the transition flow and the rollback ledger run on the versions of the database, with
 * the registry's JPA entity and repositories on a database of its own. Using a version writes its workflow, approval
 * and rollback ledger rows and leaves the version used before AVAILABLE; a blocked transition is recorded and changes
 * nothing; the canary columns the screen writes are mapped and kept through the gate; the emergency rollback goes back
 * to the version used before through the JPA writer.
 */
class PromptVersionReleaseGatePostgresTest {

    private static final String SCOPE = "PLATFORM_GLOBAL";
    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final Map<String, PromptVersionService.RegistryTarget> TARGETS = Map.of(PROMPT,
            new PromptVersionService.RegistryTarget("SecurityDecisionStandard", "CORTEX_PROMPT_CONTRACT_V5",
                    "SecurityDecisionStandardPromptTemplate", "contexa-cortex-core"));
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-17T09:00:00Z"), ZoneOffset.UTC);
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
    private PromptVersionResolver resolver;
    private PromptGovernanceReleaseGateService gate;

    @BeforeAll
    static void aDatabaseWithTheSchemaAndTheRegistryEntities() throws Exception {
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
    void twoVersions() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_part, ctxa_prompt_version_trial_case, ctxa_prompt_version_trial,"
                + " ctxa_prompt_version, ctxa_prompt_governance_registry, ctxa_prompt_governance_release_workflow,"
                + " ctxa_prompt_governance_release_ledger, ctxa_prompt_governance_rollback_ledger,"
                + " ctxa_prompt_governance_rollback_execution, ctxa_prompt_governance_runtime_cache_invalidation CASCADE");
        versions = new PromptVersionService(() -> jdbc, SecurityDecisionPromptDocument.productReleases(), TARGETS, null,
                CLOCK);
        versions.registerProducts(null);
        versions.create(null, "prompt: " + PROMPT + "\nbasedOn: v1.0\ntitle: Finance closing\nsystem:\n"
                + "  - key: how-to-judge\n    text: |\n      1. Weigh the duty roster first.\n",
                PromptVersionRecord.SCREEN, null, "admin", null);
        state("v1.0", "ACTIVE");
        resolver = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc, new ObjectMapper(),
                60_000L, 0L).registrySelector(), versions, () -> null, CLOCK);
        gate = new PromptGovernanceReleaseGateService(null, registry, changes, evaluations, approvals, rollbackLedger,
                workflows, compatibility, budgets, new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> resolver));
    }

    @Test
    void usingAVersionWritesTheLedgersAndLeavesTheVersionUsedBeforeAvailable() {
        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transaction.execute(status ->
                gate.transitionPromptRelease(SCOPE, PROMPT, "v2.0", PromptBundleState.ACTIVE, "admin", "month end",
                        "PROMPT_VERSION_SCREEN"));

        assertThat(receipt.applied()).isTrue();
        assertThat(receipt.previousReleaseStatus()).isEqualTo("AVAILABLE");
        assertThat(receipt.warnings()).singleElement().asString()
                .startsWith(PromptGovernanceReleaseGateService.TRIAL_RECOMMENDED);
        assertThat(state("v2.0")).isEqualTo("ACTIVE");
        assertThat(state("v1.0")).isEqualTo("AVAILABLE");
        assertThat(jdbc.queryForList("select prompt_version || ' ' || target_release_status || ' ' || workflow_state"
                + " || ' ' || gate_state from ctxa_prompt_governance_release_workflow order by id", String.class))
                .containsExactly("v2.0 ACTIVE APPROVED_AND_APPLIED READY_FOR_PRODUCTION",
                        "v1.0 AVAILABLE APPROVED_AND_APPLIED SUPERSEDED");
        assertThat(jdbc.queryForList("select prompt_version || ' ' || approval_state || ' ' || approved_by from"
                + " ctxa_prompt_governance_release_ledger", String.class)).containsExactly("v2.0 APPROVED admin");
        assertThat(jdbc.queryForList("select prompt_version || ' ' || rollback_target_prompt_version || ' ' ||"
                + " rollback_readiness_state from ctxa_prompt_governance_rollback_ledger", String.class))
                .containsExactly("v2.0 v1.0 READY");
    }

    @Test
    void aBlockedTransitionIsRecordedAndChangesNothing() {
        versions.hide(null, PROMPT, 2, "admin");

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transaction.execute(status ->
                gate.transitionPromptRelease(SCOPE, PROMPT, "v2.0", PromptBundleState.ACTIVE, "admin", null,
                        "PROMPT_VERSION_SCREEN"));

        assertThat(receipt.applied()).isFalse();
        assertThat(receipt.blockers()).singleElement().asString().startsWith("ILLEGAL_STATE_TRANSITION");
        assertThat(state("v2.0")).isEqualTo("RETIRED");
        assertThat(state("v1.0")).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForList("select workflow_state || ' ' || blockers_json from"
                + " ctxa_prompt_governance_release_workflow", String.class)).singleElement().asString()
                .startsWith("BLOCKED").contains("ILLEGAL_STATE_TRANSITION");
    }

    /** A finished trial with the version takes the warning away. */
    @Test
    void aFinishedTrialTakesTheWarningAway() {
        jdbc.update("insert into ctxa_prompt_version_trial (registry_scope, prompt_key, candidate_number,"
                + " reference_number, requested_count, status, created_by, created_at) values (?, ?, 2, 1, 20, ?,"
                + " 'admin', ?)", SCOPE, PROMPT, PromptVersionTrials.DONE, Timestamp.from(CLOCK.instant()));

        PromptGovernanceReleaseGateService.ReleaseGateAssessment assessment = transaction.execute(status ->
                gate.assessPromptRelease(SCOPE, PROMPT, "v2.0"));

        assertThat(assessment.targets()).filteredOn(target -> "ACTIVE".equals(target.targetState())).singleElement()
                .satisfies(target -> {
                    assertThat(target.ready()).isTrue();
                    assertThat(target.warnings()).isEmpty();
                });
    }

    /** Plan 3.9: the canary columns the screen writes are mapped on the registry entity and kept through the gate. */
    @Test
    void theCanaryColumnsAreMappedAndKeptThroughTheGate() {
        jdbc.update("update ctxa_prompt_governance_registry set canary_percent = 25, canary_tenants = 'tenant-a',"
                + " canary_resource_families = '/api/documents/' where prompt_version = 'v2.0'");

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transaction.execute(status ->
                gate.transitionPromptRelease(SCOPE, PROMPT, "v2.0", PromptBundleState.CANARY, "admin", null,
                        "PROMPT_VERSION_SCREEN"));

        assertThat(receipt.applied()).isTrue();
        PromptGovernanceRegistryRecord read = transaction.execute(status -> registry
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, PROMPT, "v2.0")
                .orElseThrow());
        assertThat(read.getReleaseStatus()).isEqualTo("CANARY");
        assertThat(read.getCanaryPercent()).isEqualTo(25);
        assertThat(read.getCanaryTenants()).isEqualTo("tenant-a");
        assertThat(read.getCanaryResourceFamilies()).isEqualTo("/api/documents/");

        transaction.executeWithoutResult(status -> {
            PromptGovernanceRegistryRecord record = registry
                    .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, PROMPT, "v2.0")
                    .orElseThrow();
            record.setCanaryPercent(50);
            record.setCanaryTenants(null);
            registry.saveAndFlush(record);
        });
        assertThat(jdbc.queryForMap("select canary_percent, canary_tenants, canary_resource_families from"
                + " ctxa_prompt_governance_registry where prompt_version = 'v2.0'"))
                .containsEntry("canary_percent", 50).containsEntry("canary_tenants", null)
                .containsEntry("canary_resource_families", "/api/documents/");
    }

    /** The emergency rollback goes back to the version used before through the JPA writer of the registry. */
    @Test
    void theEmergencyRollbackGoesBackToTheVersionUsedBefore() {
        transaction.execute(status -> gate.transitionPromptRelease(SCOPE, PROMPT, "v2.0", PromptBundleState.ACTIVE,
                "admin", null, "PROMPT_VERSION_SCREEN"));
        PromptBundleRollbackService rollbacks = new PromptBundleRollbackService(jdbc,
                PromptBundleCatalog.shared().withVersions(new JdbcPromptVersionCatalog(versions, () -> jdbc,
                        () -> resolver)),
                mock(PromptGovernanceRuntimeCacheInvalidationService.class), null, new ObjectMapper(), CLOCK,
                new JpaPromptGovernanceStatusWriter(registry, rollbackLedger));

        PromptBundleRollbackService.Result result = transaction.execute(status -> rollbacks.rollback(
                new PromptBundleRollbackService.Request(SCOPE, PROMPT, "v2.0", "v1.0", "bad answers", true), "admin"));

        assertThat(result.status()).isEqualTo(PromptBundleRollbackService.AWAITING_APPROVAL);
        assertThat(state("v1.0")).isEqualTo("ACTIVE");
        assertThat(state("v2.0")).isEqualTo("AVAILABLE");
        assertThat(rollbacks.approve(result.executionKey(), "second").status())
                .isEqualTo(PromptBundleRollbackService.APPROVED);
    }

    // ----- the screens through the gate -----

    /**
     * A: through the gate, a version that is not used is used for decisions, an earlier one is used again (the
     * rollback of the screen), a new version is saved and used at once, a version is used first for some users and
     * run alongside, and the emergency rollback goes back; the confirmation shows the gate's answer for the version.
     */
    @Test
    void theScreensMoveAVersionThroughTheGate() {
        PromptVersionConsole console = console(() -> null);

        UseCheck check = console.useCheck(null, PROMPT, 2);
        assertThat(check.ready()).isTrue();
        assertThat(check.blockers()).isEmpty();
        assertThat(check.current()).isEqualTo("v1.0");

        assertThat(console.use(null, PROMPT, 2, "admin", "month end").applied()).isTrue();
        assertThat(state("v2.0")).isEqualTo("ACTIVE");
        assertThat(state("v1.0")).isEqualTo("AVAILABLE");
        // The version in use is the label the decisions read, not the newest Contexa version.
        assertThat(console.useCheck(null, PROMPT, 1).current()).isEqualTo("v2.0");
        assertThat(console.use(null, PROMPT, 1, "admin", "back").applied()).isTrue();
        assertThat(state("v1.0")).isEqualTo("ACTIVE");
        assertThat(state("v2.0")).isEqualTo("AVAILABLE");

        // Plan 3.4: "save and use" measures a version of the security decision instead; it is used through the gate.
        Created created = console.create(null, new DraftForm(PROMPT, 1, "Payroll", null,
                List.of(new FormPart("how-to-judge", "CHANGE", null, "1. Weigh the payroll calendar first.\n", null)),
                List.of(), true, "at once"), "admin");
        assertThat(created.used()).isNull();
        assertThat(created.measureRefusal()).isEqualTo("NO_MEASUREMENT_RUNNER");
        assertThat(state(created.name())).isEqualTo("AVAILABLE");
        assertThat(console.use(null, PROMPT, created.number(), "admin", "at once").applied()).isTrue();
        assertThat(state(created.name())).isEqualTo("ACTIVE");
        assertThat(state("v1.0")).isEqualTo("AVAILABLE");

        assertThat(console.startCanary(null, PROMPT, 2, 25, "tenant-a", "/api/documents/", "admin", null).applied())
                .isTrue();
        assertThat(state("v2.0")).isEqualTo("CANARY");
        assertThat(console.stopCanary(null, PROMPT, "admin", null).applied()).isTrue();
        assertThat(state("v2.0")).isEqualTo("AVAILABLE");
        assertThat(console.startShadow(null, PROMPT, 2, 5, 100, "admin", null).applied()).isTrue();
        assertThat(state("v2.0")).isEqualTo("SHADOW");
        assertThat(console.stopShadow(null, PROMPT, "admin", null).applied()).isTrue();
        assertThat(state("v2.0")).isEqualTo("AVAILABLE");

        PromptBundleRollbackService.Result rollback = console(this::rollbacks).emergencyRollback(null, PROMPT, 1, "bad",
                "admin");
        assertThat(rollback.status()).isEqualTo(PromptBundleRollbackService.AWAITING_APPROVAL);
        assertThat(state("v1.0")).isEqualTo("ACTIVE");
        assertThat(state(created.name())).isEqualTo("AVAILABLE");
    }

    /** E: a canary or a shadow the gate refuses leaves the share, targets and limit the row had. */
    @Test
    void aStartTheGateRefusesLeavesTheColumnsTheRowHad() {
        jdbc.update("update ctxa_prompt_governance_registry set release_status = 'RETIRED', canary_percent = 10,"
                + " canary_tenants = 'old', shadow_sample_percent = 5, shadow_daily_limit = 10 where prompt_version = 'v2.0'");
        PromptVersionConsole console = console(() -> null);

        assertThat(console.startCanary(null, PROMPT, 2, 25, "tenant-a", "/api/", "admin", null).applied()).isFalse();
        assertThat(console.startShadow(null, PROMPT, 2, 10, 200, "admin", null).applied()).isFalse();

        assertThat(jdbc.queryForMap("select canary_percent, canary_tenants, canary_resource_families,"
                + " shadow_sample_percent, shadow_daily_limit from ctxa_prompt_governance_registry where"
                + " prompt_version = 'v2.0'")).containsEntry("canary_percent", 10).containsEntry("canary_tenants", "old")
                .containsEntry("canary_resource_families", null).containsEntry("shadow_sample_percent", 5)
                .containsEntry("shadow_daily_limit", 10);
    }

    /** F: the version the decisions run without a label (the newest Contexa version, or the setting's) is not hidden. */
    @Test
    void theVersionTheDecisionsRunWithoutALabelIsNotHidden() {
        state("v1.0", "AVAILABLE");

        assertThatThrownBy(() -> console(() -> null).hide(null, PROMPT, 1, "admin"))
                .isInstanceOf(PromptVersionDocumentException.class)
                .satisfies(refused -> assertThat(((PromptVersionDocumentException) refused).problems())
                        .extracting(PromptVersionProblem::code).containsExactly(PromptVersionProblem.Code.IN_USE));
        assertThat(versions.find(null, PROMPT, 1).orElseThrow().hidden()).isFalse();

        resolver = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc, new ObjectMapper(),
                60_000L, 0L).registrySelector(), versions, () -> "v2.0", CLOCK);
        PromptVersionConsole bySetting = console(() -> null);
        assertThatThrownBy(() -> bySetting.hide(null, PROMPT, 2, "admin"))
                .isInstanceOf(PromptVersionDocumentException.class);
        bySetting.hide(null, PROMPT, 1, "admin");
        assertThat(versions.find(null, PROMPT, 1).orElseThrow().hidden()).isTrue();
    }

    private PromptVersionConsole console(Supplier<PromptBundleRollbackService> rollbacks) {
        PromptGovernanceReleaseGateService transactional = new PromptGovernanceReleaseGateService(null, registry,
                changes, evaluations, approvals, rollbackLedger, workflows, compatibility, budgets,
                new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> resolver)) {
            @Override
            public ReleaseTransitionReceipt transitionPromptRelease(String registryScope, String promptKey,
                                                                    String promptVersion, PromptBundleState targetState,
                                                                    String actor, String rationale,
                                                                    String approvalChannel) {
                return transaction.execute(status -> super.transitionPromptRelease(registryScope, promptKey,
                        promptVersion, targetState, actor, rationale, approvalChannel));
            }

            @Override
            public ReleaseGateAssessment assessPromptRelease(String registryScope, String promptKey,
                                                             String promptVersion) {
                return transaction.execute(status -> super.assessPromptRelease(registryScope, promptKey,
                        promptVersion));
            }
        };
        PromptVersionResolver decisions = resolver;
        return new PromptVersionConsole(versions, () -> null, () -> decisions, () -> jdbc,
                () -> new JdbcPromptReleaseQueryService(jdbc), () -> transactional,
                () -> new JdbcPromptGovernanceRuntimeCacheInvalidationService(jdbc), rollbacks, () -> null, () -> null,
                () -> null, null, () -> null, null, CLOCK);
    }

    private PromptBundleRollbackService rollbacks() {
        return new PromptBundleRollbackService(jdbc, PromptBundleCatalog.shared().withVersions(
                new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> resolver)),
                new JdbcPromptGovernanceRuntimeCacheInvalidationService(jdbc), null, new ObjectMapper(), CLOCK,
                new JdbcTestStatusWriter(jdbc));
    }

    private static void state(String version, String state) {
        jdbc.update("update ctxa_prompt_governance_registry set release_status = ?, updated_at = ? where"
                + " prompt_version = ?", state, Timestamp.from(CLOCK.instant()), version);
    }

    private static String state(String version) {
        return jdbc.queryForObject("select release_status from ctxa_prompt_governance_registry where prompt_version = ?",
                String.class, version);
    }
}
