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
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptRelease;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocument;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompt;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompts;
import io.contexa.contexacore.std.rag.QueryTransformPrompt;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsole;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Receipt;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.UseCheck;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionResolver;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.aiam.components.prompt.ConditionTemplatePromptTemplate;
import io.contexa.contexaiam.aiam.components.prompt.PolicyGenerationStreamingTemplate;
import io.contexa.contexaiam.aiam.components.prompt.PolicyGenerationTemplate;
import io.contexa.contexaiam.aiam.components.prompt.ResourceNamingTemplate;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
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
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K79 (plan 3.9, 3.11): every prompt the build ships is used through the release gate of the screen, the security
 * decision and the seven others, each with the policy its product declares, so "use" meets no blocker; the injection
 * guard stays the security decision's; a prompt whose product the gate does not know is still blocked.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptVersionUseEveryPromptPostgresTest {

    private static final String SCOPE = "PLATFORM_GLOBAL";
    private static final VersionedPrompts OTHERS = new VersionedPrompts(List.of(new PolicyGenerationTemplate(),
            new PolicyGenerationStreamingTemplate(), new ConditionTemplatePromptTemplate(), new ResourceNamingTemplate(),
            QueryTransformPrompt.BEHAVIOR, QueryTransformPrompt.RISK, QueryTransformPrompt.POLICY));
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

    /** The eight prompts with their product version v1.0 and an organization's version v2.0 that changes one part. */
    @BeforeEach
    void everyPromptWithAnOrganizationsVersion() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_part, ctxa_prompt_version_trial_case, ctxa_prompt_version_trial,"
                + " ctxa_prompt_version, ctxa_prompt_version_folder_scan, ctxa_prompt_governance_registry,"
                + " ctxa_prompt_governance_release_workflow, ctxa_prompt_governance_release_ledger,"
                + " ctxa_prompt_governance_rollback_ledger, ctxa_prompt_governance_rollback_execution,"
                + " ctxa_prompt_governance_runtime_cache_invalidation CASCADE");
        Map<String, PromptVersionService.RegistryTarget> targets = new LinkedHashMap<>();
        targets.put(SecurityDecisionPromptDocument.PROMPT, new PromptVersionService.RegistryTarget(
                "SecurityDecisionStandard", "CORTEX_PROMPT_CONTRACT_V5", "SecurityDecisionStandardPromptTemplate",
                "contexa-cortex-core"));
        List<ProductPromptRelease> products = new ArrayList<>(SecurityDecisionPromptDocument.productReleases());
        for (VersionedPrompt prompt : OTHERS.prompts()) {
            PromptGovernanceDescriptor descriptor = prompt.registryDescriptor();
            targets.put(prompt.prompt(), new PromptVersionService.RegistryTarget(descriptor.templateKey(),
                    descriptor.contractVersion(), descriptor.templateClassName(), descriptor.owner()));
            products.addAll(prompt.productReleases());
        }
        versions = new PromptVersionService(() -> jdbc, products, targets, PromptVersionAudit.none(), CLOCK);
        versions.registerProducts(null);
        versions.create(null, "prompt: " + SecurityDecisionPromptDocument.PROMPT + "\nbasedOn: v1.0\ntitle: Ours\n"
                + "system:\n  - key: how-to-judge\n    text: |\n      1. Weigh the duty roster first.\n",
                PromptVersionRecord.SCREEN, null, "admin", null);
        for (VersionedPrompt prompt : OTHERS.prompts()) {
            versions.create(null, changedPart(prompt), PromptVersionRecord.SCREEN, null, "admin", null);
        }
        resolver = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc, new ObjectMapper(),
                60_000L, 0L).registrySelector(), versions, () -> null, CLOCK);
    }

    @Test
    void everyPromptIsUsedThroughTheGateWithoutABlocker() {
        PromptVersionConsole console = console(OTHERS);
        List<String> prompts = Stream.concat(Stream.of(SecurityDecisionPromptDocument.PROMPT),
                OTHERS.prompts().stream().map(VersionedPrompt::prompt)).toList();
        assertThat(prompts).hasSize(8);

        for (String prompt : prompts) {
            UseCheck check = console.useCheck(null, prompt, 2);
            assertThat(check.blockers()).as(prompt).isEmpty();
            assertThat(check.ready()).as(prompt).isTrue();

            Receipt receipt = console.use(null, prompt, 2, "admin", "our wording");

            assertThat(receipt.blockers()).as(prompt).isEmpty();
            assertThat(receipt.applied()).as(prompt).isTrue();
            assertThat(state(prompt, "v2.0")).as(prompt).isEqualTo("ACTIVE");
            assertThat(jdbc.queryForObject("select workflow_state from ctxa_prompt_governance_release_workflow where"
                    + " prompt_key = ? and prompt_version = 'v2.0'", String.class, prompt)).as(prompt)
                    .isEqualTo("APPROVED_AND_APPLIED");
        }
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_governance_registry where prompt_version ="
                + " 'v2.0' and release_status = 'ACTIVE'", Integer.class)).isEqualTo(8);
    }

    /** A prompt whose product the gate does not know has no policy and stays blocked. */
    @Test
    void aPromptWithoutAKnownProductIsStillBlocked() {
        PromptVersionConsole console = console(new VersionedPrompts(List.of()));

        Receipt receipt = console.use(null, "ResourceNaming", 2, "admin", "our wording");

        assertThat(receipt.applied()).isFalse();
        assertThat(receipt.blockers()).extracting(blocker -> blocker.split(" ")[0]).containsExactly(
                "MODEL_COMPATIBILITY_MISSING", "BUDGET_PROFILE_MISSING", "TOKEN_COUNTING_POLICY_MISSING",
                "CACHE_POLICY_MISSING", "COMPACTION_POLICY_MISSING");
        assertThat(state("ResourceNaming", "v2.0")).isEqualTo("AVAILABLE");
        // The security decision is known without the others.
        assertThat(console.use(null, SecurityDecisionPromptDocument.PROMPT, 2, "admin", null).applied()).isTrue();
    }

    /**
     * A version of the prompt that changes the text of its first part an organization may change (one without items):
     * its text and a sentence of the organization.
     */
    private static String changedPart(VersionedPrompt prompt) {
        for (String group : List.of("system", "user")) {
            List<PromptVersionDocument.Part> parts = "system".equals(group) ? prompt.product().system()
                    : prompt.product().user();
            for (PromptVersionDocument.Part part : parts) {
                if (Boolean.FALSE.equals(part.locked()) && !part.prepared()
                        && (part.items() == null || part.items().isEmpty())
                        && (part.whenText() == null || part.whenText().isEmpty())
                        && part.text() != null && !part.text().isBlank()) {
                    StringBuilder text = new StringBuilder();
                    (part.text().stripTrailing() + "\nUse the words of our organization.").lines()
                            .forEach(line -> text.append("      ").append(line).append('\n'));
                    return "prompt: " + prompt.prompt() + "\nbasedOn: v1.0\ntitle: Ours\n" + group + ":\n  - key: "
                            + part.key() + "\n    text: |2\n" + text;
                }
            }
        }
        throw new IllegalStateException("No part of " + prompt.prompt() + " may change");
    }

    /** The screen with the gate the application builds, each call in a transaction of the registry's entities. */
    private PromptVersionConsole console(VersionedPrompts others) {
        PromptGovernanceReleaseGateService gate = new PromptGovernanceReleaseGateService(null, registry, changes,
                evaluations, approvals, rollbackLedger, workflows, compatibility, budgets,
                new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> resolver), others) {
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
        PromptVersionConsole console = new PromptVersionConsole(versions, () -> null, () -> decisions, () -> jdbc,
                () -> new JdbcPromptReleaseQueryService(jdbc), () -> gate,
                () -> new JdbcPromptGovernanceRuntimeCacheInvalidationService(jdbc), () -> null, () -> null, () -> null,
                () -> null, null, () -> null, null, CLOCK);
        console.setVersionedPrompts(OTHERS);
        return console;
    }

    private static String state(String prompt, String version) {
        return jdbc.queryForObject("select release_status from ctxa_prompt_governance_registry where registry_scope = ?"
                + " and prompt_key = ? and prompt_version = ?", String.class, SCOPE, prompt, version);
    }
}
