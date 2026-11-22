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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateCondition;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateMode;
import io.contexa.contexacore.std.components.prompt.quality.QualityGatePolicy;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateReading;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSide;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexacore.testsupport.QualityGateFixtures;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsole;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ListView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.QualityRow;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Receipt;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.UseCheck;
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
import org.slf4j.LoggerFactory;
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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Plan 3.4, 3.9, 6 (the gate bypassed): the quality gate of the security decision through the version screens on a
 * database of their own, with the measurements of a test source. A version never used is blocked on its quality in
 * the blocking mode, a reason overrides it and the override is audited, a blank reason is refused; in the warning mode
 * it is used with the verdict kept. Going back to a version the scope used for decisions takes no quality condition,
 * the emergency rollback goes to such a version alone, a canary takes the quality gate. The confirmation shows the
 * nine conditions with their numbers, the cases that changed, the state of the measurements and the mode; the
 * versions that decide outside the gate (the newest Contexa version, the setting) are shown with the state of their
 * measurement and logged once.
 */
class PromptVersionQualityGatePostgresTest {

    private static final String SCOPE = "PLATFORM_GLOBAL";
    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final String TEMPLATE = "SecurityDecisionStandard";
    private static final Map<String, PromptVersionService.RegistryTarget> TARGETS = Map.of(PROMPT,
            new PromptVersionService.RegistryTarget(TEMPLATE, "CORTEX_PROMPT_CONTRACT_V5",
                    "SecurityDecisionStandardPromptTemplate", "contexa-cortex-core"));
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-22T09:00:00Z"), ZoneOffset.UTC);
    private static final String JUDGE = "system:\n  - key: how-to-judge\n    text: |\n      1. Weigh the duty roster"
            + " first.\n";
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

    private final List<String> audited = new CopyOnWriteArrayList<>();
    private PromptVersionService versions;
    private PromptVersionResolver resolver;
    private QualityGateFixtures.Source source;

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

    /**
     * v1.0 is the product version and used for decisions by its label; v2.0 and v3.0 are an organization's versions,
     * never used. The source of measurements finds v1.0 sound and v2.0 letting the case that must be caught through.
     */
    @BeforeEach
    void threeVersions() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_part, ctxa_prompt_version_trial_case, ctxa_prompt_version_trial,"
                + " ctxa_prompt_version, ctxa_prompt_governance_registry, ctxa_prompt_governance_release_workflow,"
                + " ctxa_prompt_governance_release_ledger, ctxa_prompt_governance_rollback_ledger,"
                + " ctxa_prompt_governance_rollback_execution, ctxa_prompt_governance_runtime_cache_invalidation CASCADE");
        audited.clear();
        versions = new PromptVersionService(() -> jdbc, SecurityDecisionPromptDocument.productReleases(), TARGETS, null,
                CLOCK);
        versions.registerProducts(null);
        versions.create(null, "prompt: " + PROMPT + "\nbasedOn: v1.0\ntitle: Finance closing\n" + JUDGE,
                PromptVersionRecord.SCREEN, null, "admin", null);
        versions.create(null, "prompt: " + PROMPT + "\nbasedOn: v1.0\ntitle: Payroll\n" + JUDGE.replace("roster",
                "ledger"), PromptVersionRecord.SCREEN, null, "admin", null);
        state("v1.0", "ACTIVE");
        resolver = resolver(() -> null);
        source = QualityGateFixtures.source(QualityGateReading.measured(QualityGateFixtures.input(
                QualityGateFixtures.sound("v1.0"), QualityGateFixtures.missesTheMustCatchCase("v2.0"))));
    }

    // ----- the blocking mode and the override -----

    @Test
    void aVersionNeverUsedIsBlockedOnItsQualityAndAReasonOverridesItWithAnAuditRecord() {
        PromptVersionConsole console = console(QualityGateMode.BLOCK);

        UseCheck check = console.useCheck(null, PROMPT, 2);

        assertThat(check.ready()).isFalse();
        assertThat(check.blockers()).singleElement().asString()
                .startsWith(PromptGovernanceReleaseGateService.QUALITY_GATE_BLOCKED);
        assertThat(check.productPolicyGaps()).isEmpty();
        assertThat(check.quality().mode()).isEqualTo("BLOCK");
        assertThat(check.quality().measurement()).isEqualTo("MEASURED");
        assertThat(check.quality().verdict()).isEqualTo("BLOCKED");
        assertThat(check.quality().applied()).isEqualTo("BLOCKED");
        assertThat(check.quality().rollback()).isFalse();
        assertThat(check.quality().overridable()).isTrue();
        assertThat(check.quality().rows()).extracting(QualityRow::condition)
                .containsExactlyElementsOf(Arrays.stream(QualityGateCondition.values()).map(Enum::name).toList());
        QualityRow mustCatch = row(check, QualityGateCondition.MUST_CATCH_NEVER_ALLOWED);
        assertThat(mustCatch.status()).isEqualTo("BLOCKED");
        assertThat(mustCatch.cases()).containsExactly(QualityGateFixtures.MUST_CATCH);
        assertThat(mustCatch.figures()).containsEntry("failedCases", 1)
                .containsEntry("failedAnswers", QualityGateFixtures.RUNS);
        assertThat(row(check, QualityGateCondition.MISS_NOT_INCREASED).comparisons()).singleElement()
                .satisfies(miss -> {
                    assertThat(miss.metric()).isEqualTo("MISS");
                    assertThat(miss.currentValue()).isEqualTo(0.0);
                    assertThat(miss.candidateValue()).isEqualTo(0.5);
                    // The noise of the version in use is not measured: not known, never zero.
                    assertThat(miss.noiseWidth()).isNull();
                });
        assertThat(check.quality().changes().newlyMissed()).containsExactly(QualityGateFixtures.MUST_CATCH);
        assertThat(source.reads()).contains(SCOPE + " " + PROMPT + " v2.0 v1.0");

        Receipt blocked = console.use(null, PROMPT, 2, "admin", "month end");
        assertThat(blocked.applied()).isFalse();
        assertThat(blocked.gateState()).isEqualTo("BLOCKED_BY_QUALITY_GATE");
        assertThat(blocked.qualityVerdict()).isEqualTo("BLOCKED");
        assertThatThrownBy(() -> console.use(null, PROMPT, 2, "admin", "month end", "  "))
                .isInstanceOf(PromptVersionConsole.RefusedException.class)
                .satisfies(refused -> assertThat(((PromptVersionConsole.RefusedException) refused).code())
                        .isEqualTo("OVERRIDE_REASON_REQUIRED"));
        assertThat(state("v2.0")).isEqualTo("AVAILABLE");
        assertThat(audited).isEmpty();

        Receipt overridden = console.use(null, PROMPT, 2, "admin", "month end", "fixes the outage of the payroll run");

        assertThat(overridden.applied()).isTrue();
        assertThat(overridden.qualityOverridden()).isTrue();
        assertThat(overridden.gateState()).isEqualTo(PromptGovernanceReleaseGateService.QUALITY_GATE_OVERRIDDEN);
        assertThat(state("v2.0")).isEqualTo("ACTIVE");
        assertThat(state("v1.0")).isEqualTo("AVAILABLE");
        assertThat(audited).containsExactly(
                PromptVersionAudit.USED_FOR_DECISIONS + " v2.0 admin v1.0 -> v2.0 (month end)",
                PromptVersionAudit.QUALITY_GATE_OVERRIDDEN + " v2.0 admin verdict BLOCKED (fixes the outage of the"
                        + " payroll run)");
        assertThat(jdbc.queryForList("select gate_state || ' ' || actor_name || ' ' || rationale from"
                + " ctxa_prompt_governance_release_workflow where prompt_version = 'v2.0' and workflow_state ="
                + " 'APPROVED_AND_APPLIED'", String.class)).singleElement().asString()
                .startsWith(PromptGovernanceReleaseGateService.QUALITY_GATE_OVERRIDDEN + " admin")
                .contains("MUST_CATCH_NEVER_ALLOWED", "fixes the outage of the payroll run");
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_governance_release_workflow where"
                + " prompt_version = 'v2.0' and workflow_state = 'BLOCKED' and gate_state = 'BLOCKED_BY_QUALITY_GATE'",
                Integer.class)).isEqualTo(1);
    }

    @Test
    void inTheWarningModeTheBlockedVersionIsUsedWithTheVerdictKeptAndNoOverride() {
        Receipt receipt = console(QualityGateMode.WARN).use(null, PROMPT, 2, "admin", null);

        assertThat(receipt.applied()).isTrue();
        assertThat(receipt.qualityVerdict()).isEqualTo("BLOCKED");
        assertThat(receipt.qualityApplied()).isEqualTo("WARNING");
        assertThat(receipt.qualityOverridden()).isFalse();
        assertThat(state("v2.0")).isEqualTo("ACTIVE");
        assertThat(audited).containsExactly(PromptVersionAudit.USED_FOR_DECISIONS + " v2.0 admin v1.0 -> v2.0");
    }

    // ----- going back, the emergency rollback and the canary -----

    @Test
    void goingBackToAVersionUsedBeforeTakesNoQualityConditionAndTheEmergencyRollbackGoesToSuchAVersionAlone() {
        PromptVersionConsole console = console(QualityGateMode.BLOCK);
        assertThat(console.use(null, PROMPT, 2, "admin", null, "urgent fix").applied()).isTrue();

        // v1.0 decided before v2.0 by its label: the screen uses it again without the quality gate.
        UseCheck back = console.useCheck(null, PROMPT, 1);
        assertThat(back.quality().rollback()).isTrue();
        assertThat(back.ready()).isTrue();
        int reads = source.reads().size();
        Receipt receipt = console.use(null, PROMPT, 1, "admin", "back");
        assertThat(receipt.applied()).isTrue();
        assertThat(receipt.qualityOverridden()).isFalse();
        assertThat(source.reads()).hasSize(reads);
        assertThat(state("v1.0")).isEqualTo("ACTIVE");

        // v3.0 never decided: the emergency rollback refuses it and nothing changes.
        PromptBundleRollbackService.Result refused = console.emergencyRollback(null, PROMPT, 3, "bad answers",
                "admin");
        assertThat(refused.status()).isEqualTo(PromptBundleRollbackService.REFUSED);
        assertThat(refused.refusals()).containsExactly(PromptBundleRollbackService.TARGET_NOT_USED_FOR_DECISIONS);
        assertThat(state("v1.0")).isEqualTo("ACTIVE");
        assertThat(state("v3.0")).isEqualTo("AVAILABLE");

        // v2.0 decided before (overridden): the emergency rollback goes back to it at once.
        PromptBundleRollbackService.Result rollback = console.emergencyRollback(null, PROMPT, 2, "bad answers",
                "admin");
        assertThat(rollback.status()).isEqualTo(PromptBundleRollbackService.AWAITING_APPROVAL);
        assertThat(state("v2.0")).isEqualTo("ACTIVE");
        assertThat(state("v1.0")).isEqualTo("AVAILABLE");
    }

    @Test
    void aCanaryOfAVersionWithoutAMeasurementIsRefusedInTheBlockingModeAndAReasonOverridesIt() {
        source.answer(QualityGateReading.missing(Set.of(QualityGateSide.CANDIDATE), null));
        PromptVersionConsole console = console(QualityGateMode.BLOCK);

        // The confirmation of the canary reads the quality gate of the canary, as the move then applies it.
        UseCheck check = console.useCheck(null, PROMPT, 3, PromptBundleState.CANARY);
        assertThat(check.ready()).isFalse();
        assertThat(check.blockers()).singleElement().asString()
                .startsWith(PromptGovernanceReleaseGateService.QUALITY_GATE_BLOCKED);
        assertThat(check.quality().measurement()).isEqualTo("MISSING");
        assertThat(check.quality().measurementSides()).containsExactly("CANDIDATE");
        assertThat(check.quality().applied()).isEqualTo("BLOCKED");
        assertThat(check.quality().rollback()).isFalse();
        assertThat(check.quality().overridable()).isTrue();
        assertThat(row(check, QualityGateCondition.COMPARABLE_MEASUREMENTS).status()).isEqualTo("BLOCKED");
        assertThatThrownBy(() -> console.useCheck(null, PROMPT, 3, PromptBundleState.SHADOW))
                .isInstanceOf(IllegalArgumentException.class);

        Receipt refused = console.startCanary(null, PROMPT, 3, 25, "tenant-a", "/api/", "admin", null);

        assertThat(refused.applied()).isFalse();
        assertThat(refused.blockers()).singleElement().asString().contains("measurement=MISSING");
        assertThat(state("v3.0")).isEqualTo("AVAILABLE");
        assertThat(jdbc.queryForMap("select canary_percent, canary_tenants from ctxa_prompt_governance_registry"
                + " where prompt_version = 'v3.0'")).containsEntry("canary_percent", null)
                .containsEntry("canary_tenants", null);

        Receipt overridden = console.startCanary(null, PROMPT, 3, 25, "tenant-a", "/api/", "admin", null,
                "the canary measures it on live traffic");

        assertThat(overridden.applied()).isTrue();
        assertThat(overridden.qualityOverridden()).isTrue();
        assertThat(state("v3.0")).isEqualTo("CANARY");
        assertThat(audited).containsExactly(PromptVersionAudit.CANARY_STARTED + " v3.0 admin 25%",
                PromptVersionAudit.QUALITY_GATE_OVERRIDDEN + " v3.0 admin verdict BLOCKED (the canary measures it on"
                        + " live traffic)");
    }

    // ----- what counts as used for decisions -----

    @Test
    void aVersionWasUsedForDecisionsWhenItDecidesTheGateAppliedItARollbackWentToItOrItDecidedAsAnotherStarted() {
        JdbcPromptVersionCatalog catalog = new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> resolver);

        assertThat(catalog.usedForDecisions(SCOPE, PROMPT, "v1.0")).as("deciding now").isTrue();
        assertThat(catalog.usedForDecisions(SCOPE, PROMPT, "v2.0")).isFalse();

        workflow("v2.0", "ACTIVE", "BLOCKED", SCOPE);
        workflow("v2.0", "CANARY", "APPROVED_AND_APPLIED", SCOPE);
        workflow("v2.0", "ACTIVE", "APPROVED_AND_APPLIED", "tenant-b");
        assertThat(catalog.usedForDecisions(SCOPE, PROMPT, "v2.0")).as("blocked, a canary, another scope").isFalse();
        workflow("v2.0", "ACTIVE", "APPROVED_AND_APPLIED", SCOPE);
        assertThat(catalog.usedForDecisions(SCOPE, PROMPT, "v2.0")).as("applied by the gate").isTrue();

        execution("v3.0", PromptBundleRollbackService.REFUSED);
        assertThat(catalog.usedForDecisions(SCOPE, PROMPT, "v3.0")).as("a refused rollback").isFalse();
        execution("v3.0", PromptBundleRollbackService.AWAITING_APPROVAL);
        assertThat(catalog.usedForDecisions(SCOPE, PROMPT, "v3.0")).as("a rollback").isTrue();

        jdbc.update("insert into ctxa_prompt_governance_rollback_ledger (registry_scope, prompt_key, prompt_version,"
                + " rollback_reference, rollback_target_prompt_version, rollback_state, rollback_readiness_state,"
                + " rollback_strategy, rollback_reason, prepared_by, registration_source) values (?, ?, 'v5.0', 'ref',"
                + " 'v4.0', 'TARGET_DECLARED', 'READY', 'VERSION_ROLLBACK', 'test', 'pqa', 'test')", SCOPE, PROMPT);
        assertThat(catalog.usedForDecisions(SCOPE, PROMPT, "v4.0")).as("deciding as another started").isTrue();
        assertThat(catalog.usedForDecisions(SCOPE, PROMPT, "2026.11.16-v1.0")).as("no version name").isFalse();
    }

    // ----- outside the gate -----

    @Test
    void theVersionsThatDecideOutsideTheGateAreShownWithTheirMeasurementAndLoggedOnce() {
        source.answer(QualityGateReading.missing(Set.of(QualityGateSide.CANDIDATE), null));
        assertThat(console(QualityGateMode.WARN).list(null, PROMPT, false).outsideGate()).as("the label decides")
                .isNull();

        // Without a label the newest Contexa version decides (a new resolver: the registry's selection is cached).
        state("v1.0", "AVAILABLE");
        resolver = resolver(() -> null);
        ListView newest = console(QualityGateMode.WARN).list(null, PROMPT, false);
        assertThat(newest.outsideGate().version()).isEqualTo("v1.0");
        assertThat(newest.outsideGate().source()).isEqualTo("BUILD_DEFAULT");
        assertThat(newest.outsideGate().measurement()).isEqualTo(QualityMeasurementState.MISSING.name());
        assertThat(source.reads()).contains(SCOPE + " " + PROMPT + " v1.0 null");

        // The setting names v2.0: it decides outside the gate, which the confirmation shows and the resolver logs once.
        resolver = resolver(() -> "v2.0");
        resolver.setQualityGateSource(() -> source);
        UseCheck check = console(QualityGateMode.WARN).useCheck(null, PROMPT, 3);
        assertThat(check.outsideGate().version()).isEqualTo("v2.0");
        assertThat(check.outsideGate().source()).isEqualTo("CONFIGURATION");
        assertThat(check.outsideGate().measurement()).isEqualTo("MISSING");

        Logger logger = (Logger) LoggerFactory.getLogger(PromptVersionResolver.class);
        ListAppender<ILoggingEvent> lines = new ListAppender<>();
        lines.start();
        logger.addAppender(lines);
        try {
            PromptVersionResolver decisions = resolver(() -> "v2.0");
            QualityGateFixtures.Source measurements = QualityGateFixtures.source(
                    QualityGateReading.unmeasurable("NO_REPLAY"));
            decisions.setQualityGateSource(() -> measurements);
            PromptGovernanceResolutionContext request = new PromptGovernanceResolutionContext(SCOPE, PROMPT, TEMPLATE,
                    null, null, null, null, Map.of());
            for (int decision = 0; decision < 3; decision++) {
                assertThat(decisions.select(request, null).bundleVersion()).isEqualTo("v2.0");
            }

            assertThat(measurements.reads()).containsExactly(SCOPE + " " + PROMPT + " v2.0 null");
            assertThat(lines.list).filteredOn(line -> line.getLevel() == Level.WARN)
                    .extracting(ILoggingEvent::getFormattedMessage).singleElement().asString()
                    .contains("v2.0 decides outside the release gate",
                            "contexa.security.tiered.prompt-bundle.active", "UNMEASURABLE");
        }
        finally {
            logger.detachAppender(lines);
        }
    }

    // ----- helpers -----

    private PromptVersionResolver resolver(Supplier<String> setting) {
        return new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc, new ObjectMapper(),
                60_000L, 0L).registrySelector(), versions, setting, CLOCK);
    }

    private PromptVersionConsole console(QualityGateMode mode) {
        PromptVersionResolver decisions = resolver;
        JdbcPromptVersionCatalog catalog = new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> decisions);
        PromptGovernanceReleaseGateService transactional = new PromptGovernanceReleaseGateService(null, registry,
                changes, evaluations, approvals, rollbackLedger, workflows, compatibility, budgets, catalog, null,
                new QualityGatePolicy(source, mode, QualityGateFixtures.SETTINGS)) {
            @Override
            public ReleaseTransitionReceipt transitionPromptRelease(String registryScope, String promptKey,
                                                                    String promptVersion, PromptBundleState targetState,
                                                                    String actor, String rationale,
                                                                    String approvalChannel, String overrideReason) {
                return transaction.execute(status -> super.transitionPromptRelease(registryScope, promptKey,
                        promptVersion, targetState, actor, rationale, approvalChannel, overrideReason));
            }

            @Override
            public ReleaseGateAssessment assessPromptRelease(String registryScope, String promptKey,
                                                             String promptVersion) {
                return transaction.execute(status -> super.assessPromptRelease(registryScope, promptKey,
                        promptVersion));
            }
        };
        PromptBundleRollbackService rollbacks = new PromptBundleRollbackService(jdbc,
                PromptBundleCatalog.shared().withVersions(catalog),
                new JdbcPromptGovernanceRuntimeCacheInvalidationService(jdbc), null, new ObjectMapper(), CLOCK,
                new JdbcTestStatusWriter(jdbc));
        PromptVersionAudit audit = (action, scope, prompt, version, actor, detail) -> audited.add(action + " "
                + version + " " + actor + (detail != null ? " " + detail : ""));
        return new PromptVersionConsole(versions, () -> null, () -> decisions, () -> jdbc,
                () -> new JdbcPromptReleaseQueryService(jdbc), () -> transactional,
                () -> new JdbcPromptGovernanceRuntimeCacheInvalidationService(jdbc), () -> rollbacks, () -> null,
                () -> null, () -> null, null, () -> null, audit, CLOCK);
    }

    private static QualityRow row(UseCheck check, QualityGateCondition condition) {
        return check.quality().rows().stream().filter(row -> row.condition().equals(condition.name())).findFirst()
                .orElseThrow();
    }

    private static void workflow(String version, String target, String workflowState, String scope) {
        jdbc.update("insert into ctxa_prompt_governance_release_workflow (registry_scope, prompt_key, prompt_version,"
                + " current_release_status, target_release_status, workflow_state, gate_state, approval_channel,"
                + " actor_name, rationale) values (?, ?, ?, 'AVAILABLE', ?, ?, 'READY_FOR_PRODUCTION',"
                + " 'PROMPT_VERSION_CONSOLE', 'admin', 'test')", scope, PROMPT, version, target, workflowState);
    }

    private static void execution(String version, String status) {
        jdbc.update("insert into ctxa_prompt_governance_rollback_execution (execution_key, registry_scope, prompt_key,"
                + " from_version, to_version, actor, reason, emergency, status, executed_at) values (?, ?, ?, 'v1.0', ?,"
                + " 'admin', 'test', true, ?, ?)", "RBX-" + status, SCOPE, PROMPT, version, status,
                Timestamp.from(CLOCK.instant()));
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
