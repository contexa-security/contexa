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
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleRunnability;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRelease;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionCatalog;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptGovernanceDescriptorResolver;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Plan 3.9: the version table read by the release machinery. The catalog reads it on every call (a version saved after
 * the start is seen at once), a version runs when it is there and not hidden, the version a scope decides with is the
 * one the resolver chooses (its label, else the newest Contexa version), a finished trial is evidence of a version, the
 * shadow release of a version carries its row's share and limit, and the replay targets are the shown versions.
 */
class JdbcPromptVersionCatalogPostgresTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final String SCOPE = "PLATFORM_GLOBAL";
    private static final String TEMPLATE = "SecurityDecisionStandard";
    private static final Map<String, PromptVersionService.RegistryTarget> TARGETS = Map.of(PROMPT,
            new PromptVersionService.RegistryTarget(TEMPLATE, "CORTEX_PROMPT_CONTRACT_V5",
                    "SecurityDecisionStandardPromptTemplate", "contexa-cortex-core"));
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-17T09:00:00Z"), ZoneOffset.UTC);
    private static final String JUDGE = """
            system:
              - key: how-to-judge
                text: |
                  1. Weigh the duty roster first.
            """;
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private PromptVersionService versions;
    private PromptVersionResolver resolver;
    private JdbcPromptVersionCatalog catalog;

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
    void theProductVersion() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_part, ctxa_prompt_version_trial_case, ctxa_prompt_version_trial,"
                + " ctxa_prompt_version, ctxa_prompt_governance_registry,"
                + " ctxa_prompt_governance_runtime_cache_invalidation CASCADE");
        versions = new PromptVersionService(() -> jdbc, SecurityDecisionPromptDocument.productReleases(), TARGETS, null,
                CLOCK);
        versions.registerProducts(null);
        resolver = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc, new ObjectMapper())
                .registrySelector(), versions, () -> null, CLOCK);
        catalog = new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> resolver);
    }

    @Test
    void theCatalogReadsTheVersionTableOnEveryCall() {
        PromptBundleCatalog withVersions = PromptBundleCatalog.shared().withVersions(catalog);
        assertThat(catalog.versions(SCOPE, PROMPT)).extracting(PromptVersionCatalog.Entry::name).containsExactly("v1.0");
        assertThat(PromptBundleRunnability.runnable(withVersions, SCOPE, PROMPT, "v2.0")).isFalse();

        organization("Finance closing");

        assertThat(catalog.versions(SCOPE, PROMPT)).extracting(PromptVersionCatalog.Entry::name)
                .containsExactly("v2.0", "v1.0");
        assertThat(catalog.find(SCOPE, PROMPT, "v2.0")).get().satisfies(entry -> {
            assertThat(entry.basedOnNumber()).isEqualTo(1);
            assertThat(entry.contexa()).isFalse();
            assertThat(entry.contentHash()).isEqualTo(versions.find(SCOPE, PROMPT, 2).orElseThrow().contentHash());
        });
        assertThat(PromptBundleRunnability.runnable(withVersions, SCOPE, PROMPT, "v2.0")).isTrue();
        assertThat(PromptBundleRunnability.runnable(withVersions, PROMPT, "V2.0")).isTrue();
        assertThat(catalog.assembled(SCOPE, PROMPT, "v2.0")).get()
                .satisfies(version -> assertThat(version.systemPart("how-to-judge").orElseThrow().text())
                        .contains("Weigh the duty Finance closing first."));
        // A bundle of the build still runs by its manifest; a version name never reads a manifest.
        assertThat(PromptBundleRunnability.runnable(withVersions, PROMPT, SecurityDecisionPromptBundles.V1.version()))
                .isTrue();
        assertThat(PromptBundleRunnability.runnable(PromptBundleCatalog.shared(), PROMPT, "v1.0")).isFalse();
    }

    @Test
    void aHiddenVersionIsInTheTableButDoesNotRun() {
        organization("Finance closing");
        versions.hide(null, PROMPT, 2, "admin");

        assertThat(catalog.find(SCOPE, PROMPT, "v2.0")).get().extracting(PromptVersionCatalog.Entry::hidden)
                .isEqualTo(true);
        assertThat(catalog.runnable(SCOPE, PROMPT, "v2.0")).isFalse();
        assertThat(PromptBundleRunnability.runnable(PromptBundleCatalog.shared().withVersions(catalog), SCOPE, PROMPT,
                "v2.0")).isFalse();
        assertThat(catalog.shown(SCOPE, PROMPT)).extracting(PromptVersionCatalog.Entry::name).containsExactly("v1.0");
    }

    @Test
    void theVersionAScopeDecidesWithIsItsLabelElseTheNewestContexaVersion() {
        organization("Finance closing");
        assertThat(catalog.deciding(SCOPE, PROMPT)).contains("v1.0");

        registry("v2.0", "ACTIVE");
        resolver = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc, new ObjectMapper())
                .registrySelector(), versions, () -> null, CLOCK);
        assertThat(catalog.deciding(SCOPE, PROMPT)).contains("v2.0");

        // A canary of part of the users is not what the scope decides with.
        registry("v1.0", "CANARY");
        jdbc.update("update ctxa_prompt_governance_registry set canary_percent = 50 where prompt_version = 'v1.0'");
        resolver = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc, new ObjectMapper())
                .registrySelector(), versions, () -> null, CLOCK);
        assertThat(catalog.deciding(SCOPE, PROMPT)).contains("v2.0");
        assertThat(new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> null).deciding(SCOPE, PROMPT)).isEmpty();
    }

    @Test
    void aFinishedTrialIsTheEvidenceOfAVersion() {
        organization("Finance closing");
        assertThat(catalog.trialFinished(SCOPE, PROMPT, "v2.0")).isFalse();

        trial(2, PromptVersionTrials.RUNNING);
        assertThat(catalog.trialFinished(SCOPE, PROMPT, "v2.0")).isFalse();
        trial(2, PromptVersionTrials.DONE);
        assertThat(catalog.trialFinished(SCOPE, PROMPT, "v2.0")).isTrue();
        assertThat(catalog.trialFinished(SCOPE, PROMPT, "v1.0")).isFalse();
        assertThat(catalog.trialFinished("TENANT_A", PROMPT, "v2.0")).isFalse();
    }

    /** Plan 3.4: the version run alongside the decisions carries its row's share and limit; a hidden one is none. */
    @Test
    void theShadowReleaseOfAVersionCarriesItsRowsShareAndLimit() {
        organization("Finance closing");
        registry("v2.0", "SHADOW");
        jdbc.update("update ctxa_prompt_governance_registry set shadow_sample_percent = 10, shadow_daily_limit = 50"
                + " where prompt_version = 'v2.0'");
        PromptGovernanceResolutionContext context = new PromptGovernanceResolutionContext(SCOPE, PROMPT, TEMPLATE,
                null, null, "/api/x", "GET", Map.of());

        assertThat(resolver.shadowRelease(context, "user-1")).isEqualTo(new PromptShadowRelease("v2.0", 10, 50));
        assertThat(resolver.shadow(context, "user-1").bundleVersion()).isEqualTo("v2.0");

        jdbc.update("update ctxa_prompt_version set hidden = true where version_number = 2");
        PromptVersionResolver later = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc,
                new ObjectMapper()).registrySelector(), versions, () -> null, CLOCK);
        assertThat(later.shadowRelease(context, "user-1")).isEqualTo(PromptShadowRelease.none());
    }

    /** Plan 3.8 (10): the replay targets are the shown versions of the database, newest first. */
    @Test
    void theReplayTargetsAreTheShownVersionsOfTheDatabase() {
        organization("Finance closing");
        organization("Payroll");
        versions.hide(null, PROMPT, 2, "admin");
        SealedDecisionReplays replays = new SealedDecisionReplays(mock(SealedEvidencePackageRepository.class),
                () -> null, null, null, new ObjectMapper(), new SealedEvidencePackageIntegrity(), () -> catalog);

        assertThat(replays.bundles()).containsExactly("v3.0", "v1.0");
    }

    private void organization(String title) {
        versions.create(null, "prompt: " + PROMPT + "\nbasedOn: v1.0\ntitle: " + title + "\n"
                + JUDGE.replace("roster", title), PromptVersionRecord.SCREEN, null, "admin", null);
    }

    private void registry(String version, String state) {
        jdbc.update("update ctxa_prompt_governance_registry set release_status = ?, updated_at = ? where"
                + " prompt_version = ?", state, Timestamp.from(CLOCK.instant()), version);
    }

    private void trial(int candidate, String status) {
        jdbc.update("insert into ctxa_prompt_version_trial (registry_scope, prompt_key, candidate_number,"
                + " reference_number, requested_count, status, created_by, created_at) values (?, ?, ?, 1, 20, ?,"
                + " 'admin', ?)", SCOPE, PROMPT, candidate, status, Timestamp.from(CLOCK.instant()));
    }
}
