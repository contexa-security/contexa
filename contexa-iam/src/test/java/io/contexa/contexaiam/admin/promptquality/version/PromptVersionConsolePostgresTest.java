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
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptSections;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptRelease;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentException;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import io.contexa.contexaiam.admin.promptquality.evidence.JdbcSealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptReleaseQueryService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptGovernanceRuntimeCacheInvalidationService;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.CheckView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Created;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Draft;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.DraftForm;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.FormPart;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ListView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.PartView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Preview;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Receipt;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.VersionView;
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
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Plan 6-6 on a database with the schema of a new installation: what the version screens show of the versions, the
 * labels and the checks, and what their changes do: a new version saved from the screen's form, used for decisions
 * through the release gate, hidden, a canary and a shadow started and stopped, changes carried onto a newer product
 * version, and the history the audit log keeps.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptVersionConsolePostgresTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final Map<String, PromptVersionService.RegistryTarget> TARGETS = Map.of(PROMPT,
            new PromptVersionService.RegistryTarget("SecurityDecisionStandard", "CORTEX_PROMPT_CONTRACT_V5",
                    "SecurityDecisionStandardPromptTemplate", "contexa-cortex-core"));
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-17T09:00:00Z"), ZoneOffset.UTC);
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private final List<String> audited = new ArrayList<>();
    private final PromptGovernanceReleaseGateService gate = mock(PromptGovernanceReleaseGateService.class);
    private final PromptGovernanceRuntimeCacheInvalidationService invalidation =
            mock(PromptGovernanceRuntimeCacheInvalidationService.class);
    private PromptVersionService versions;
    private PromptVersionConsole console;

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
                + " ctxa_prompt_version, ctxa_prompt_governance_registry, ctxa_audit_log, ctxa_sealed_evidence_package CASCADE");
        versions = service(SecurityDecisionPromptDocument.productReleases());
        versions.registerProducts(null);
        console = console(versions);
        // The gate moves the registry row as the release gate does: one version used for decisions per scope.
        when(gate.transitionPromptRelease(anyString(), anyString(), anyString(), any(PromptBundleState.class), any(),
                any(), anyString())).thenAnswer(call -> {
                    String scope = call.getArgument(0);
                    String prompt = call.getArgument(1);
                    String version = call.getArgument(2);
                    PromptBundleState target = call.getArgument(3);
                    if (target == PromptBundleState.ACTIVE) {
                        jdbc.update("update ctxa_prompt_governance_registry set release_status = 'AVAILABLE' where"
                                + " registry_scope = ? and prompt_key = ? and release_status = 'ACTIVE'", scope, prompt);
                    }
                    jdbc.update("update ctxa_prompt_governance_registry set release_status = ?, updated_at = ? where"
                            + " registry_scope = ? and prompt_key = ? and prompt_version = ?", target.name(),
                            Timestamp.from(CLOCK.instant()), scope, prompt, version);
                    return new PromptGovernanceReleaseGateService.ReleaseTransitionReceipt(scope, prompt, version, null,
                            target.name(), true, "PASSED", List.of(), LocalDateTime.now(CLOCK));
                });
    }

    private PromptVersionService service(List<ProductPromptRelease> products) {
        return new PromptVersionService(() -> jdbc, products, TARGETS,
                (action, scope, prompt, version, actor, detail) -> audited.add(action + " " + version), CLOCK);
    }

    private PromptVersionConsole console(PromptVersionService service) {
        return new PromptVersionConsole(service, () -> null, () -> null, () -> jdbc,
                () -> new JdbcPromptReleaseQueryService(jdbc), () -> gate, () -> invalidation, () -> null,
                () -> new JdbcPromptInspectionQueries(jdbc), () -> null, () -> null, "/etc/contexa/prompt-versions",
                () -> null, (action, scope, prompt, version, actor, detail) -> audited.add(action + " " + version),
                CLOCK);
    }

    private static DraftForm form(Integer base, List<FormPart> system, List<FormPart> user) {
        return new DraftForm(PROMPT, base, "Finance closing", "For the month end", system, user, false, null);
    }

    private static FormPart change(String key, String text) {
        return new FormPart(key, "CHANGE", null, text, null);
    }

    private static FormPart add(String key, String title, String text, String after) {
        return new FormPart(key, "ADD", title, text, after);
    }

    @Test
    void theListShowsTheProductVersionInUseAndWhatEachVersionIs() {
        ListView list = console.list(null, null, false);

        assertThat(list.prompt()).isEqualTo(PROMPT);
        assertThat(list.decisionPrompt()).isTrue();
        assertThat(list.used().version()).isEqualTo("v1.0");
        // No label yet: the newest Contexa version decides.
        assertThat(list.used().source()).isEqualTo("BUILD_DEFAULT");
        assertThat(list.counts().total()).isEqualTo(1);
        assertThat(list.counts().contexa()).isEqualTo(1);
        assertThat(list.versions()).singleElement().satisfies(row -> {
            assertThat(row.name()).isEqualTo("v1.0");
            assertThat(row.provider()).isEqualTo(PromptVersionRecord.CONTEXA);
            assertThat(row.state()).isEqualTo("USED");
            assertThat(row.fromDocument()).isFalse();
        });
        assertThat(list.newProduct()).isNull();
        assertThatThrownBy(() -> console.list(null, "no.such-prompt", false))
                .isInstanceOfSatisfying(PromptVersionConsole.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo("PROMPT_NOT_FOUND"));
    }

    @Test
    void aVersionSavedFromTheFormShowsWhatItChangedAgainstItsBase() {
        Created created = console.create(null, form(1, List.of(change("how-to-judge", "Weigh the duty roster first."),
                add("org-part-1", "Our organization", "The finance team closes on the 25th.", "how-to-judge")),
                List.of(add("org-block-1", "Organization reference", "Batch accounts run 01-05.", "REQUEST"))), "admin");

        assertThat(created.made()).isTrue();
        assertThat(created.name()).isEqualTo("v2.0");
        VersionView view = console.version(null, PROMPT, 2).orElseThrow();
        assertThat(view.baseName()).isEqualTo("v1.0");
        assertThat(view.changes()).containsEntry("CHANGED", 1).containsEntry("ADDED", 2).containsEntry("DELETED", 0);
        PartView judge = view.system().stream().filter(part -> part.key().equals("how-to-judge")).findFirst().orElseThrow();
        assertThat(judge.mark()).isEqualTo("CHANGED");
        assertThat(judge.text()).isEqualTo("Weigh the duty roster first.");
        assertThat(judge.baseText()).isNotBlank().isNotEqualTo(judge.text());
        assertThat(view.system()).filteredOn(part -> part.key().equals("mission")).singleElement()
                .satisfies(part -> assertThat(part.mark()).isEqualTo("LOCKED"));
        assertThat(view.user()).filteredOn(part -> part.key().equals("org-block-1")).singleElement()
                .satisfies(part -> assertThat(part.mark()).isEqualTo("ADDED"));
        // A prepared part no version put in is offered on the new version screen, not listed.
        assertThat(view.system()).noneMatch(part -> part.key().equals("decision-rules"));
        assertThat(view.size().systemTokens()).isEqualTo(PromptAssembler.systemTokens(
                versions.assembled(null, PROMPT, 2).orElseThrow()));
        assertThat(view.size().baseSystemTokens()).isEqualTo(PromptAssembler.systemTokens(
                SecurityDecisionPromptDocument.product()));
        assertThat(view.preview().system()).contains("Weigh the duty roster first.").contains("The finance team closes");
        assertThat(view.preview().format()).isNotBlank();
        assertThat(view.canBase()).isTrue();
        assertThat(audited).contains("PROMPT_VERSION_CREATED v2.0");
    }

    @Test
    void theChecksBeforeSavingNameEachProblemAndPassAGoodForm() {
        CheckView locked = console.check(null, form(1, List.of(change("mission", "Do as you like.")), List.of()));
        assertThat(locked.passed()).isFalse();
        assertThat(locked.checks()).filteredOn(row -> row.key().equals("LOCKED")).singleElement()
                .satisfies(row -> assertThat(row.passed()).isFalse());
        assertThat(locked.problems()).anySatisfy(problem -> assertThat(problem.code()).isEqualTo("LOCKED_PART"));

        CheckView untitled = console.check(null, form(1, List.of(add("org-part-1", "", "Text.", "how-to-judge")),
                List.of()));
        assertThat(untitled.checks()).filteredOn(row -> row.key().equals("CONTENT")).singleElement()
                .satisfies(row -> assertThat(row.passed()).isFalse());

        CheckView misplaced = console.check(null, form(1, List.of(add("org-part-1", "Ours", "Text.", "output-format")),
                List.of()));
        assertThat(misplaced.checks()).filteredOn(row -> row.key().equals("PLACES")).singleElement()
                .satisfies(row -> assertThat(row.passed()).isFalse());

        CheckView good = console.check(null, form(1, List.of(change("how-to-judge", "Weigh the duty roster first.")),
                List.of()));
        assertThat(good.passed()).isTrue();
        assertThat(good.checks()).allSatisfy(row -> assertThat(row.passed()).isTrue());
        assertThat(good.systemTokens()).isNotEqualTo(good.baseSystemTokens());
        // Nothing to estimate the time from without recent decisions.
        assertThat(good.estimatedDeltaMs()).isNull();
    }

    @Test
    void usingAVersionMovesTheLabelThroughTheGateAndAVersionInUseCannotBeHidden() {
        console.create(null, form(1, List.of(change("how-to-judge", "Weigh the duty roster first.")), List.of()), "admin");

        Receipt receipt = console.use(null, PROMPT, 2, "admin", "month end");

        assertThat(receipt.applied()).isTrue();
        assertThat(receipt.previous()).isEqualTo("v1.0");
        verify(gate).transitionPromptRelease(eq("PLATFORM_GLOBAL"), eq(PROMPT), eq("v2.0"), eq(PromptBundleState.ACTIVE),
                eq("admin"), eq("month end"), eq(PromptVersionConsole.SOURCE));
        verify(invalidation).publish(eq("PLATFORM_GLOBAL"), eq(PROMPT), eq("v2.0"), anyString(), eq("admin"));
        ListView list = console.list(null, PROMPT, false);
        assertThat(list.used().version()).isEqualTo("v2.0");
        assertThat(list.used().source()).isEqualTo("REGISTRY");
        assertThat(list.used().since()).isEqualTo(CLOCK.instant());
        assertThat(list.versions()).extracting(PromptVersionConsoleDtos.VersionRow::state)
                .containsExactly("USED", "UNUSED");
        assertThat(audited).contains("PROMPT_VERSION_USED_FOR_DECISIONS v2.0");

        assertThatThrownBy(() -> console.hide(null, PROMPT, 2, "admin")).isInstanceOf(PromptVersionDocumentException.class);
        console.hide(null, PROMPT, 1, "admin");
        assertThat(console.list(null, PROMPT, false).versions()).hasSize(1);
        assertThat(console.list(null, PROMPT, true).versions()).filteredOn(PromptVersionConsoleDtos.VersionRow::hidden)
                .singleElement().satisfies(row -> assertThat(row.state()).isEqualTo("HIDDEN"));
        assertThatThrownBy(() -> console.use(null, PROMPT, 1, "admin", null))
                .isInstanceOfSatisfying(PromptVersionConsole.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo("VERSION_HIDDEN"));
    }

    @Test
    void aCanaryAndAShadowKeepTheirSettingsOnTheRegistryRowUntilTheyStop() {
        console.create(null, form(1, List.of(change("how-to-judge", "Weigh the duty roster first.")), List.of()), "admin");
        console.create(null, form(1, List.of(change("how-to-judge", "Weigh the approvals first.")), List.of()), "admin");

        assertThatThrownBy(() -> console.startCanary(null, PROMPT, 2, 30, null, null, "admin", null))
                .isInstanceOfSatisfying(PromptVersionConsole.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo("CANARY_PERCENT"));
        assertThat(console.startCanary(null, PROMPT, 2, 25, "tenant-a, tenant-b", "/api/payments\n/api/export",
                "admin", "pilot").applied()).isTrue();
        Map<String, Object> row = jdbc.queryForMap("select release_status, canary_percent, canary_tenants,"
                + " canary_resource_families from ctxa_prompt_governance_registry where prompt_version = 'v2.0'");
        assertThat(row).containsEntry("release_status", "CANARY").containsEntry("canary_percent", 25)
                .containsEntry("canary_tenants", "tenant-a,tenant-b")
                .containsEntry("canary_resource_families", "/api/payments,/api/export");
        assertThatThrownBy(() -> console.startCanary(null, PROMPT, 3, 10, null, null, "admin", null))
                .isInstanceOfSatisfying(PromptVersionConsole.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo("CANARY_RUNNING"));
        assertThat(console.list(null, PROMPT, false).running().canary()).isEqualTo("v2.0");

        assertThatThrownBy(() -> console.startShadow(null, PROMPT, 3, 7, 100, "admin", null))
                .isInstanceOfSatisfying(PromptVersionConsole.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo("SHADOW_PERCENT"));
        assertThatThrownBy(() -> console.startShadow(null, PROMPT, 3, 5, 0, "admin", null))
                .isInstanceOfSatisfying(PromptVersionConsole.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo("SHADOW_DAILY_LIMIT"));
        assertThat(console.startShadow(null, PROMPT, 3, 10, 300, "admin", null).applied()).isTrue();
        assertThat(console.list(null, PROMPT, false).running()).satisfies(running -> {
            assertThat(running.shadow()).isEqualTo("v3.0");
            assertThat(running.shadowSamplePercent()).isEqualTo(10);
            assertThat(running.shadowDailyLimit()).isEqualTo(300);
        });

        assertThat(console.stopCanary(null, PROMPT, "admin", null).applied()).isTrue();
        assertThat(console.stopShadow(null, PROMPT, "admin", null).applied()).isTrue();
        assertThat(jdbc.queryForList("select canary_percent, shadow_sample_percent from ctxa_prompt_governance_registry"
                + " where prompt_version in ('v2.0', 'v3.0')")).allSatisfy(stopped ->
                assertThat(stopped.values()).containsOnlyNulls());
        assertThatThrownBy(() -> console.stopCanary(null, PROMPT, "admin", null))
                .isInstanceOfSatisfying(PromptVersionConsole.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo("NO_CANARY"));
        assertThat(audited).contains("PROMPT_VERSION_CANARY_STARTED v2.0", "PROMPT_VERSION_SHADOW_STARTED v3.0",
                "PROMPT_VERSION_CANARY_STOPPED v2.0", "PROMPT_VERSION_SHADOW_STOPPED v3.0");
    }

    @Test
    void theNewVersionScreenOpensTheEditablePartsAndCarriesChangesOntoANewerProductVersion() {
        console.create(null, form(1, List.of(change("how-to-judge", "Weigh the duty roster first."),
                add("org-part-1", "Our organization", "The finance team closes on the 25th.", "how-to-judge")),
                List.of()), "admin");
        console.use(null, PROMPT, 2, "admin", null);
        Draft draft = console.draft(null, PROMPT, 1, null).orElseThrow();
        assertThat(draft.nextName()).isEqualTo("v3.0");
        assertThat(draft.system()).filteredOn(part -> part.key().equals("mission")).singleElement()
                .satisfies(part -> assertThat(part.editable()).isFalse());
        assertThat(draft.system()).filteredOn(part -> part.key().equals("how-to-judge")).singleElement()
                .satisfies(part -> assertThat(part.editable()).isTrue());
        assertThat(draft.prepared()).extracting(PromptVersionConsoleDtos.DraftPart::key)
                .containsExactlyInAnyOrder("decision-rules", "verified-signal-boundary");
        assertThat(draft.systemPlaces()).contains("mission", "how-to-judge", "honesty-more").doesNotContain("output-format");
        assertThat(draft.userPlaces()).contains("REQUEST");

        // A newer product version: the organization's version keeps deciding, and the screen offers to carry it.
        ProductPromptRelease current = SecurityDecisionPromptDocument.productReleases().get(0);
        ProductPromptRelease newer = new ProductPromptRelease(PROMPT, "2027.01.10",
                current.document().replace("release: " + quoted(current.document()), "release: 2027.01.10"));
        PromptVersionService upgraded = service(List.of(current, newer));
        assertThat(upgraded.registerProducts(null)).extracting(PromptVersionService.Saved::name).containsExactly("v3.0");
        PromptVersionConsole after = console(upgraded);
        assertThat(after.list(null, PROMPT, false).newProduct()).satisfies(product -> {
            assertThat(product.version()).isEqualTo("v3.0");
            assertThat(product.usedVersion()).isEqualTo("v2.0");
            assertThat(product.usedBase()).isEqualTo("v1.0");
            assertThat(product.carry()).isTrue();
        });
        Draft carried = after.draft(null, PROMPT, 3, 2).orElseThrow();
        assertThat(carried.carriedFrom()).isEqualTo("v2.0");
        assertThat(carried.carried()).hasSize(2).allSatisfy(change -> assertThat(change.movable()).isTrue());
    }

    /**
     * Plan 3.3: the label stays on an older Contexa version when a newer one is registered; the list says so, and the
     * newer one is used as it is (nothing to carry).
     */
    @Test
    void aNewerProductVersionIsNoticedWhenAnOlderContexaVersionDecides() {
        jdbc.update("update ctxa_prompt_governance_registry set release_status = 'ACTIVE' where prompt_key = ? and"
                + " prompt_version = 'v1.0'", PROMPT);
        ProductPromptRelease current = SecurityDecisionPromptDocument.productReleases().get(0);
        ProductPromptRelease newer = new ProductPromptRelease(PROMPT, "2027.01.10",
                current.document().replace("release: " + quoted(current.document()), "release: 2027.01.10"));
        PromptVersionService upgraded = service(List.of(current, newer));
        assertThat(upgraded.registerProducts(null)).extracting(PromptVersionService.Saved::name).containsExactly("v2.0");

        ListView list = console(upgraded).list(null, PROMPT, false);

        assertThat(list.used().version()).isEqualTo("v1.0");
        assertThat(list.newProduct()).satisfies(product -> {
            assertThat(product.version()).isEqualTo("v2.0");
            assertThat(product.usedVersion()).isEqualTo("v1.0");
            assertThat(product.carry()).isFalse();
        });
    }

    /** Plan 3.5: a prepared part the base put in can be taken out again in the next version. */
    @Test
    void aPreparedPartTheBaseIncludedCanBeTakenOutInTheNextVersion() {
        console.create(null, form(1, List.of(new FormPart("decision-rules", "INCLUDE", null, null, null)), List.of()),
                "admin");
        Draft draft = console.draft(null, PROMPT, 2, null).orElseThrow();
        assertThat(draft.system()).filteredOn(part -> part.key().equals("decision-rules")).singleElement()
                .satisfies(part -> assertThat(part.included()).isTrue());

        console.create(null, form(2, List.of(new FormPart("decision-rules", "DELETE", null, null, null)), List.of()),
                "admin");

        assertThat(console.version(null, PROMPT, 3).orElseThrow().system())
                .noneMatch(part -> part.key().equals("decision-rules") && "INCLUDED".equals(part.mark()));
        assertThat(console.draft(null, PROMPT, 3, null).orElseThrow().prepared())
                .extracting(PromptVersionConsoleDtos.DraftPart::key).contains("decision-rules");
    }

    private static String quoted(String document) {
        String line = document.lines().filter(text -> text.startsWith("release:")).findFirst().orElseThrow();
        return line.substring("release:".length()).trim();
    }

    /** The confirmation of "use for decisions" shows the gate's answer for the version in use (plan 3.9). */
    @Test
    void theConfirmationOfUsingAVersionShowsTheGatesAnswer() {
        console.create(null, form(1, List.of(change("how-to-judge", "Weigh the duty roster first.")), List.of()), "admin");
        when(gate.assessPromptRelease("PLATFORM_GLOBAL", PROMPT, "v2.0")).thenReturn(
                new PromptGovernanceReleaseGateService.ReleaseGateAssessment("PLATFORM_GLOBAL", PROMPT, "v2.0", "AVAILABLE",
                        List.of(new PromptGovernanceReleaseGateService.ReleaseGateTarget("ACTIVE", false, "BLOCKED",
                                List.of("EMPIRICAL_EVAL_MISSING"))), null));

        PromptVersionConsoleDtos.UseCheck check = console.useCheck(null, PROMPT, 2);

        assertThat(check.version()).isEqualTo("v2.0");
        assertThat(check.current()).isEqualTo("v1.0");
        assertThat(check.ready()).isFalse();
        assertThat(check.blockers()).containsExactly("EMPIRICAL_EVAL_MISSING");
        assertThat(check.latestTrial()).isNull();
    }

    /** The emergency rollback goes back from the version in use, tells the caches, and another operator approves it. */
    @Test
    void anEmergencyRollbackGoesBackFromTheVersionInUseAndIsApprovedByAnother() {
        console.create(null, form(1, List.of(change("how-to-judge", "Weigh the duty roster first.")), List.of()), "admin");
        console.use(null, PROMPT, 2, "admin", null);
        PromptBundleRollbackService rollbacks = mock(PromptBundleRollbackService.class);
        when(rollbacks.rollback(any(), eq("admin"))).thenReturn(new PromptBundleRollbackService.Result("key-1",
                PromptBundleRollbackService.AWAITING_APPROVAL, null, List.of()));
        when(rollbacks.approve("key-1", "second")).thenReturn(new PromptBundleRollbackService.Result("key-1",
                PromptBundleRollbackService.APPROVED, null, List.of()));
        PromptVersionConsole withRollback = new PromptVersionConsole(versions, () -> null, () -> null, () -> jdbc,
                () -> new JdbcPromptReleaseQueryService(jdbc), () -> gate, () -> invalidation, () -> rollbacks,
                () -> new JdbcPromptInspectionQueries(jdbc), () -> null, () -> null, null, () -> null,
                (action, scope, prompt, version, actor, detail) -> audited.add(action + " " + version), CLOCK);

        assertThat(withRollback.emergencyRollback(null, PROMPT, 1, "bad answers", "admin").status())
                .isEqualTo(PromptBundleRollbackService.AWAITING_APPROVAL);
        verify(rollbacks).rollback(new PromptBundleRollbackService.Request("PLATFORM_GLOBAL", PROMPT, "v2.0", "v1.0",
                "bad answers", true), "admin");
        verify(invalidation).publish(eq("PLATFORM_GLOBAL"), eq(PROMPT), eq("v1.0"), anyString(), eq("admin"));
        assertThat(withRollback.approveRollback(null, PROMPT, "key-1", "second").status())
                .isEqualTo(PromptBundleRollbackService.APPROVED);
        assertThat(audited).contains("PROMPT_VERSION_EMERGENCY_ROLLBACK v1.0", "PROMPT_VERSION_ROLLBACK_APPROVED key-1");
        assertThatThrownBy(() -> console.emergencyRollback(null, PROMPT, 1, "x", "admin"))
                .isInstanceOfSatisfying(PromptVersionConsole.RefusedException.class,
                        refused -> assertThat(refused.code()).isEqualTo("ROLLBACK_MISSING"));
    }

    @Test
    void theHistoryIsWhatTheAuditLogKeepsOfThePrompt() {
        jdbc.update("insert into ctxa_audit_log (timestamp, principal_name, resource_identifier, action, decision, reason,"
                + " details, event_category) values (?, 'admin', ?, 'PROMPT_VERSION_USED_FOR_DECISIONS', 'RECORDED',"
                + " 'v1.0 -> v2.0 (month end)', ?, 'PROMPT_VERSION_CHANGED')", Timestamp.from(CLOCK.instant()),
                PROMPT + "@v2.0", "{\"scope\":\"PLATFORM_GLOBAL\",\"prompt\":\"" + PROMPT + "\",\"version\":\"v2.0\"}");
        jdbc.update("insert into ctxa_audit_log (timestamp, principal_name, resource_identifier, action, decision,"
                + " event_category) values (?, 'admin', 'cortex.other@v1.0', 'PROMPT_VERSION_CREATED', 'RECORDED',"
                + " 'PROMPT_VERSION_CHANGED')", Timestamp.from(CLOCK.instant()));

        assertThat(console.history(PromptVersionService.PLATFORM_SCOPE, PROMPT)).singleElement().satisfies(row -> {
            assertThat(row.actor()).isEqualTo("admin");
            assertThat(row.action()).isEqualTo("PROMPT_VERSION_USED_FOR_DECISIONS");
            assertThat(row.version()).isEqualTo("v2.0");
            assertThat(row.reason()).isEqualTo("v1.0 -> v2.0 (month end)");
        });
        assertThat(console.advanced(null, PROMPT).folder().setting()).isEqualTo("/etc/contexa/prompt-versions");
        assertThat(console.advanced(null, PROMPT).folder().enabled()).isFalse();
        assertThatThrownBy(console::rescan).isInstanceOfSatisfying(PromptVersionConsole.RefusedException.class,
                refused -> assertThat(refused.code()).isEqualTo("FOLDER_NOT_SET"));
    }

    private static final String CLOSING = "Finance staff export the ledger on the last two business days of a month.";
    private static final String CLOSING_BLOCK = "=== Finance closing (reference written by your organization) ===\n"
            + CLOSING + "\n";

    /**
     * K64: the checks of the new version screen count a block added to the user prompt in the size and in the decision
     * time they estimate, as the prompt draws it with its header.
     */
    @Test
    void theChecksCountABlockAddedToTheUserPromptInTheSizeAndTheTime() {
        int blockTokens = PromptAssembler.tokensOf(1 + CLOSING_BLOCK.length());
        jdbc.update("insert into ctxa_ai_security_decision_observation (observation_id, request_id, user_id,"
                + " http_method, request_path, created_at, llm_latency_ms, prompt_tokens) values ('obs-k64', 'req-k64',"
                + " 'alice', 'GET', '/api/ledger', ?, 10000, 5000)", Timestamp.from(CLOCK.instant()));
        try {
            CheckView view = console.check(null, form(1, List.of(),
                    List.of(add("org-closing", "Finance closing", CLOSING, "REQUEST"))));

            assertThat(view.passed()).isTrue();
            assertThat(view.systemTokens()).isEqualTo(view.baseSystemTokens());
            assertThat(view.baseAddedUserTokens()).isZero();
            assertThat(view.addedUserTokens()).isEqualTo(blockTokens);
            // Two milliseconds a token, the median of the latest decisions.
            assertThat(view.estimatedDeltaMs()).isEqualTo(2L * blockTokens);
        }
        finally {
            jdbc.update("delete from ctxa_ai_security_decision_observation where observation_id = 'obs-k64'");
        }
    }

    /**
     * Plan 3.10 (2): the finished prompt of a version shows the latest sealed decision drawn with that version, the
     * blocks it adds at their places, even when no decision ran it yet; the decision a version drew is shown as it was
     * drawn. A decision that cannot be drawn again is shown as it was drawn, with why and the added blocks beside it;
     * without any sealed decision there is no user prompt.
     */
    @Test
    void theFinishedPromptDrawsTheLatestSealedDecisionWithTheVersionAndTheBlocksItAdds() {
        console.create(null, form(1, List.of(), List.of(add("org-closing", "Finance closing", CLOSING, "REQUEST"))),
                "admin");
        sealedDecision("pkg-1", "req-1", "v1.0");
        SealedDecisionReplays replays = replays();
        console.setSealedDrawing(() -> (packageId, version) -> replays.drawPackage(packageId, version)
                .map(drawn -> drawn.drawing().userPrompt()));

        Preview product = console.version(null, PROMPT, 1).orElseThrow().preview();
        assertThat(product.user()).isEqualTo("the user prompt v1.0 drew");
        assertThat(product.drawnWithThisVersion()).isTrue();
        assertThat(product.drawnAgain()).isFalse();

        String productDrawn = replays.drawPackage("pkg-1", "v1.0").orElseThrow().drawing().userPrompt();
        Preview organization = console.version(null, PROMPT, 2).orElseThrow().preview();
        assertThat(organization.user()).isEqualTo(insertedAfter(productDrawn, "REQUEST", CLOSING_BLOCK));
        assertThat(organization.drawnAgain()).isTrue();
        assertThat(organization.drawnWithThisVersion()).isTrue();
        assertThat(organization.drawnWith()).isEqualTo("v2.0");
        assertThat(organization.requestId()).isEqualTo("req-1");
        assertThat(organization.notDrawn()).isNull();

        // Without the decision pipeline, or when the drawing fails, the decision is shown as it was drawn.
        console.setSealedDrawing(() -> null);
        Preview unavailable = console.version(null, PROMPT, 2).orElseThrow().preview();
        assertThat(unavailable.user()).isEqualTo("the user prompt v1.0 drew");
        assertThat(unavailable.drawnWith()).isEqualTo("v1.0");
        assertThat(unavailable.drawnWithThisVersion()).isFalse();
        assertThat(unavailable.drawnAgain()).isFalse();
        assertThat(unavailable.notDrawn()).isEqualTo("UNAVAILABLE");
        assertThat(unavailable.addedBlocks()).extracting(PartView::key).containsExactly("org-closing");
        console.setSealedDrawing(() -> (packageId, version) -> {
            throw new SealedDecisionReplays.UnavailableException();
        });
        assertThat(console.version(null, PROMPT, 2).orElseThrow().preview().notDrawn()).isEqualTo("UNAVAILABLE");
        console.setSealedDrawing(() -> (packageId, version) -> {
            throw new IllegalStateException("The sealed context does not read");
        });
        Preview failed = console.version(null, PROMPT, 2).orElseThrow().preview();
        assertThat(failed.notDrawn()).isEqualTo("FAILED");
        assertThat(failed.user()).isEqualTo("the user prompt v1.0 drew");

        jdbc.execute("TRUNCATE ctxa_sealed_evidence_package CASCADE");
        Preview none = console.version(null, PROMPT, 2).orElseThrow().preview();
        assertThat(none.user()).isNull();
        assertThat(none.notDrawn()).isNull();
        assertThat(none.addedBlocks()).extracting(PartView::key).containsExactly("org-closing");
    }

    /** A sealed decision of the security decision drawn with the version, with a context the replay can draw from. */
    private static void sealedDecision(String packageId, String requestId, String drawnWith) {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder().userId("alice").organizationId("org-1").build())
                .session(CanonicalSecurityContext.Session.builder().sessionId("session-1").clientIp("10.0.0.1")
                        .build())
                .resource(CanonicalSecurityContext.Resource.builder().resourceId("/api/ledger/export")
                        .requestPath("/api/ledger/export").httpMethod("GET").actionFamily("EXPORT")
                        .resourceClass("SENSITIVE").build())
                .requestObservedAt(Instant.parse("2026-11-17T08:00:00Z"))
                .build();
        jdbc.update("insert into ctxa_sealed_evidence_package (package_id, correlation_id, user_id, captured_at,"
                + " seal_state, package_hash, decision_json, raw_user_prompt, prompt_execution_metadata_json,"
                + " canonical_context_json, request_facts_json) values (?, ?, 'alice', ?, 'SEALED', ?, ?, ?, ?, ?, ?)",
                packageId, requestId, Timestamp.from(CLOCK.instant().minusSeconds(60)), "hash-" + packageId,
                "{\"action\":\"ALLOW\"}", "the user prompt " + drawnWith + " drew",
                "{\"" + PromptExecutionMetadata.PROMPT_VERSION_NAME + "\":\"" + drawnWith + "\"}",
                new CanonicalSecurityContextSerializer(JSON).serialize(context),
                "{\"userId\":\"alice\",\"sessionId\":\"session-1\",\"clientIp\":\"10.0.0.1\"}");
    }

    /** The replays as the engine runs them, drawing with the versions of the database; there is no pipeline to ask. */
    private SealedDecisionReplays replays() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityDecisionPromptSections(new SecurityEventEnricher(), properties, event -> Optional.empty(),
                        new PromptContextComposer(), null, null, null));
        template.setPromptVersionStore(new JdbcPromptVersionStore(versions,
                SecurityDecisionPromptDocument.productStore()));
        SealedDecisionReplayService service = new SealedDecisionReplayService(template, null,
                new BaselineLearningService(null, new SecurityZeroTrustProperties()), properties,
                StructuredOutputCapabilityRegistry.defaultRegistry(), () -> null, null, "OBSERVE",
                new CanonicalSecurityContextSerializer(JSON), JSON);
        return new SealedDecisionReplays(new JdbcSealedEvidencePackageRepository(jdbc), () -> service, null, null, JSON,
                new SealedEvidencePackageIntegrity(), () -> new JdbcPromptVersionCatalog(versions, () -> jdbc,
                () -> null));
    }

    /** The text with the block drawn right after the block of the title: after a blank line, before the next one. */
    private static String insertedAfter(String text, String title, String block) {
        int header = text.startsWith("=== " + title + " ") ? 0 : text.indexOf("\n=== " + title + " ");
        assertThat(header).as("the prompt draws the block " + title).isGreaterThanOrEqualTo(0);
        int next = text.indexOf("\n=== ", header + 1);
        return next < 0 ? text + "\n" + block
                : text.substring(0, next + 1) + block + "\n" + text.substring(next + 1);
    }
}
