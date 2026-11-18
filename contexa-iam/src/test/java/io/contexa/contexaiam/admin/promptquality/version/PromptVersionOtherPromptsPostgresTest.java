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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptRelease;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionInUse;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionStore;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompt;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompts;
import io.contexa.contexacore.std.rag.QueryTransformPrompt;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptGovernanceDescriptorResolver;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.VersionView;
import io.contexa.contexaiam.aiam.components.prompt.ConditionTemplatePromptTemplate;
import io.contexa.contexaiam.aiam.components.prompt.PolicyGenerationStreamingTemplate;
import io.contexa.contexaiam.aiam.components.prompt.PolicyGenerationTemplate;
import io.contexa.contexaiam.aiam.components.prompt.ResourceNamingTemplate;
import io.contexa.contexaiam.aiam.protocol.context.ResourceNamingContext;
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
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Plan 6-7 on a database with the schema of a new installation: the seven prompts other than the security decision
 * register their product document as their v1.0 beside it, each with its own numbers and registry row; the setting
 * {@code prompt-bundle.active} names a version of the security decision only; the label of another prompt is what its
 * call draws, through the store; and the version screen shows that prompt drawn with its example input.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptVersionOtherPromptsPostgresTest {

    private static final VersionedPrompts PROMPTS = new VersionedPrompts(List.of(new PolicyGenerationTemplate(),
            new PolicyGenerationStreamingTemplate(), new ConditionTemplatePromptTemplate(), new ResourceNamingTemplate(),
            QueryTransformPrompt.BEHAVIOR, QueryTransformPrompt.RISK, QueryTransformPrompt.POLICY));
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;
    private PromptVersionService versions;
    private Map<String, PromptVersionService.RegistryTarget> targets;
    private List<ProductPromptRelease> products;

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
    void noVersionYet() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_part, ctxa_prompt_version_trial_case, ctxa_prompt_version_trial,"
                + " ctxa_prompt_version, ctxa_prompt_version_folder_scan, ctxa_prompt_governance_registry,"
                + " ctxa_prompt_governance_runtime_cache_invalidation CASCADE");
        targets = new LinkedHashMap<>();
        targets.put(SecurityDecisionPromptDocument.PROMPT, new PromptVersionService.RegistryTarget(
                "SecurityDecisionStandard", "CORTEX_PROMPT_CONTRACT_V5", "SecurityDecisionStandardPromptTemplate",
                "contexa-cortex-core"));
        products = new ArrayList<>(SecurityDecisionPromptDocument.productReleases());
        for (VersionedPrompt prompt : PROMPTS.prompts()) {
            PromptGovernanceDescriptor descriptor = prompt.registryDescriptor();
            targets.put(prompt.prompt(), new PromptVersionService.RegistryTarget(descriptor.templateKey(),
                    descriptor.contractVersion(), descriptor.templateClassName(), descriptor.owner()));
            products.addAll(prompt.productReleases());
        }
        versions = new PromptVersionService(() -> jdbc, products, targets, PromptVersionAudit.none(), Clock.systemUTC());
    }

    @Test
    void theSevenPromptsRegisterTheirV10BesideTheSecurityDecision() {
        versions.registerProducts(null);

        assertThat(versions.prompts()).containsExactly(SecurityDecisionPromptDocument.PROMPT, "PolicyGeneration",
                "PolicyGenerationStreaming", "ConditionTemplate", "ResourceNaming", "BehaviorQueryTransform",
                "RiskQueryTransform", "PolicyQueryTransform");
        for (String prompt : versions.prompts()) {
            assertThat(versions.list(null, prompt, false)).as(prompt).extracting(PromptVersionRecord::name)
                    .containsExactly("v1.0");
            assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_governance_registry where prompt_key = ?"
                    + " and prompt_version = 'v1.0'", Integer.class, prompt)).as(prompt).isEqualTo(1);
        }
        assertThat(versions.registerProducts(null)).as("a second start").isEmpty();
    }

    @Test
    void theLabelOfAnotherPromptIsWhatItsCallDrawsAndTheSettingIsTheSecurityDecisionsAlone() {
        versions.registerProducts(null);
        versions.create(null, "prompt: ResourceNaming\nbasedOn: v1.0\ntitle: Finance names\nsystem:\n"
                + "  - key: role\n    text: |\n      You name the finance department's resources.\n",
                PromptVersionRecord.SCREEN, null, "admin", null);
        jdbc.update("update ctxa_prompt_governance_registry set release_status = 'ACTIVE' where prompt_key ="
                + " 'ResourceNaming' and prompt_version = 'v2.0'");
        PromptVersionResolver resolver = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc,
                new ObjectMapper()).registrySelector(), versions, () -> "v9.0", Clock.systemUTC());
        PromptVersionStore store = new JdbcPromptVersionStore(versions, PROMPTS.productStore());
        ResourceNamingTemplate template = new ResourceNamingTemplate();
        template.setPromptVersions(new PromptVersionInUse(() -> resolver, () -> store));

        String system = template.generateSystemPrompt(request(), null);

        assertThat(system).contains("You name the finance department's resources.")
                .doesNotContain("You are a resource naming specialist AI");
        assertThat(template.getPromptGovernanceDescriptor().promptVersion()).isEqualTo("v2.0");
        // The setting names v9.0 of the security decision; the newest Contexa version of a prompt without a label runs.
        PolicyGenerationTemplate policy = new PolicyGenerationTemplate();
        policy.setPromptVersions(new PromptVersionInUse(() -> resolver, () -> store));
        policy.generateSystemPrompt(request(), null);
        assertThat(policy.getPromptGovernanceDescriptor().promptVersion()).isEqualTo("v1.0");
    }

    @Test
    void theVersionScreenShowsAnotherPromptDrawnWithItsExampleInput() {
        versions.registerProducts(null);
        PromptVersionConsole console = new PromptVersionConsole(versions, () -> null, () -> null, () -> jdbc,
                () -> null, () -> null, () -> null, () -> null, () -> null, () -> null, () -> null, null, () -> null,
                null, Clock.systemUTC());
        console.setVersionedPrompts(PROMPTS);

        VersionView naming = console.version(null, "ResourceNaming", 1).orElseThrow();
        VersionView query = console.version(null, "RiskQueryTransform", 1).orElseThrow();

        assertThat(naming.decisionPrompt()).isFalse();
        assertThat(naming.preview().example()).isTrue();
        assertThat(naming.preview().system()).contains("You are a resource naming specialist AI");
        assertThat(naming.preview().user()).contains("identifier: /api/users/{id}");
        assertThat(query.preview().system()).isNull();
        assertThat(query.preview().user()).contains("Original Query: who exported the payroll report last night");

        // K69: another prompt's size counts a block added to its user prompt as that prompt draws it, under its title.
        versions.create(null, "prompt: ResourceNaming\nbasedOn: v1.0\ntitle: Finance names\nuser:\n"
                + "  - key: finance-terms\n    add-after: reference\n    title: Finance terms\n    text: |\n"
                + "      A ledger is a book of accounts.\n", PromptVersionRecord.SCREEN, null, "admin", null);
        VersionView terms = console.version(null, "ResourceNaming", 2).orElseThrow();
        assertThat(terms.size().addedUserTokens()).isEqualTo(PromptAssembler.tokensOf(1 + "Finance terms:\n".length()
                + "A ledger is a book of accounts.\n".length()));
        assertThat(terms.size().baseAddedUserTokens()).isZero();
        assertThat(terms.size().estimatedDeltaMs()).isNull();
        // K131: changed in the next version, the block is still the version's own, in the size and the prompt.
        versions.create(null, "prompt: ResourceNaming\nbasedOn: v2.0\ntitle: Finance names\nuser:\n"
                + "  - key: finance-terms\n    text: |\n      A ledger is a book of the accounts of a year.\n",
                PromptVersionRecord.SCREEN, null, "admin", null);
        VersionView changed = console.version(null, "ResourceNaming", 3).orElseThrow();
        assertThat(changed.size().addedUserTokens()).isEqualTo(PromptAssembler.tokensOf(1
                + "Finance terms:\n".length() + "A ledger is a book of the accounts of a year.\n".length()));
        assertThat(changed.size().baseAddedUserTokens()).isEqualTo(terms.size().addedUserTokens());
        assertThat(changed.preview().user()).contains("Finance terms:\nA ledger is a book of the accounts of a year.\n");
    }

    /**
     * K53 (plan 3.3): an installation of the policy generation's release 2026.11.17 registers the release that names
     * no data with its sentence as its next Contexa version; without a label that version runs, and a label on the
     * earlier one keeps it with what it always drew.
     */
    @Test
    void anUpgradeRegistersThePolicyGenerationReleaseOfTheDataSentenceAsItsNextContexaVersion() {
        List<ProductPromptRelease> first = products.stream().filter(release -> !PolicyGenerationTemplate.PROMPT
                .equals(release.prompt()) || "2026.11.17-v1.0".equals(release.release())).toList();
        new PromptVersionService(() -> jdbc, first, targets, PromptVersionAudit.none(), Clock.systemUTC())
                .registerProducts(null);
        assertThat(versions.list(null, PolicyGenerationTemplate.PROMPT, false)).extracting(PromptVersionRecord::name)
                .containsExactly("v1.0");

        assertThat(versions.registerProducts(null)).extracting(PromptVersionService.Saved::name)
                .containsExactly("v2.0");
        assertThat(versions.list(null, PolicyGenerationTemplate.PROMPT, false))
                .extracting(PromptVersionRecord::name, PromptVersionRecord::provider, PromptVersionRecord::originName)
                .containsExactly(tuple("v2.0", PromptVersionRecord.CONTEXA, "2026.11.18-v1.0"),
                        tuple("v1.0", PromptVersionRecord.CONTEXA, "2026.11.17-v1.0"));
        PromptVersionStore store = new JdbcPromptVersionStore(versions, PROMPTS.productStore());

        PolicyGenerationTemplate newest = new PolicyGenerationTemplate();
        newest.setPromptVersions(new PromptVersionInUse(() -> resolver(), () -> store));
        assertThat(newest.generateUserPrompt(request(), null))
                .contains("[Data]\nNo IAM data or similar query patterns were provided.\n");
        assertThat(newest.getPromptGovernanceDescriptor().promptVersion()).isEqualTo("v2.0");

        jdbc.update("update ctxa_prompt_governance_registry set release_status = 'ACTIVE' where prompt_key ="
                + " 'PolicyGeneration' and prompt_version = 'v1.0'");
        PolicyGenerationTemplate labelled = new PolicyGenerationTemplate();
        labelled.setPromptVersions(new PromptVersionInUse(() -> resolver(), () -> store));
        assertThat(labelled.generateUserPrompt(request(), null)).contains("[Data]\nnull\n");
        assertThat(labelled.getPromptGovernanceDescriptor().promptVersion()).isEqualTo("v1.0");
    }

    private PromptVersionResolver resolver() {
        return new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc, new ObjectMapper())
                .registrySelector(), versions, () -> null, Clock.systemUTC());
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static AIRequest<? extends DomainContext> request() {
        AIRequest request = mock(AIRequest.class);
        when(request.getContext()).thenReturn(new ResourceNamingContext());
        when(request.getParameter(anyString(), any(Class.class))).thenReturn(null);
        return request;
    }
}
