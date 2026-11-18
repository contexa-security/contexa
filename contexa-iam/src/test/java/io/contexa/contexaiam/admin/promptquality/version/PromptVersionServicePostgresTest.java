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
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptRelease;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentException;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionProblem;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptGovernanceDescriptorResolver;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptGovernanceRuntimeCacheInvalidationService;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.TaskScheduler;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Plan 6-3 on a database with the schema of a new installation: the product versions are registered on a first
 * installation and an upgrade, the numbers count up (two saves at once take two numbers), a version does not change,
 * the content hash names the prompt a version draws, the folder registers each document once, an import finds its base
 * by its content hash, a download imports back to the same content hash, an installation that ran bundles retires their
 * rows, and the version a decision runs is chosen by the label, the setting and the newest Contexa version in this
 * order, on two servers within the invalidation poll.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
@ExtendWith(OutputCaptureExtension.class)
class PromptVersionServicePostgresTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final String TEMPLATE_KEY = "SecurityDecisionStandard";
    private static final Map<String, PromptVersionService.RegistryTarget> TARGETS = Map.of(PROMPT,
            new PromptVersionService.RegistryTarget(TEMPLATE_KEY, "CORTEX_PROMPT_CONTRACT_V5",
                    "SecurityDecisionStandardPromptTemplate", "contexa-cortex-core"));
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private final List<String> audited = new ArrayList<>();
    private final MovingClock clock = new MovingClock(Instant.parse("2026-11-16T09:00:00Z"));
    private PromptVersionService versions;

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
                + " ctxa_prompt_governance_runtime_cache_invalidation");
        versions = service(SecurityDecisionPromptDocument.productReleases());
    }

    private PromptVersionService service(List<ProductPromptRelease> products) {
        return new PromptVersionService(() -> jdbc, products, TARGETS,
                (action, scope, prompt, version, actor, detail) -> audited.add(action + " " + version), clock);
    }

    private static String organization(String basedOn, String body) {
        return "prompt: cortex.security-decision\nbasedOn: " + basedOn + "\ntitle: Finance closing\n" + body;
    }

    private static final String JUDGE = """
            system:
              - key: how-to-judge
                text: |
                  1. Weigh the duty roster first.
            """;

    @Test
    void aFirstInstallationRegistersTheNewestProductAsV1AndAnUpgradeTheNewerOnesInOrder() {
        List<PromptVersionService.Saved> first = versions.registerProducts(null);
        assertThat(first).extracting(PromptVersionService.Saved::name).containsExactly("v1.0");
        assertThat(versions.registerProducts(null)).as("a second start").isEmpty();
        PromptVersionRecord v1 = versions.find(null, PROMPT, 1).orElseThrow();
        assertThat(v1.provider()).isEqualTo(PromptVersionRecord.CONTEXA);
        // K66: the build ships 2026.11.16-v1.0 and 2026.11.18-v1.0; a first installation registers the newest alone.
        assertThat(v1.originName()).isEqualTo("2026.11.18-v1.0");
        assertThat(v1.contentHash()).isEqualTo(SecurityDecisionPromptDocument.product().contentHash());

        // An organization's version stays where it is when Contexa ships two newer releases.
        versions.create(null, organization("v1.0", JUDGE), PromptVersionRecord.SCREEN, null, "admin", null);
        List<ProductPromptRelease> shipped = SecurityDecisionPromptDocument.productReleases();
        ProductPromptRelease current = shipped.get(shipped.size() - 1);
        List<ProductPromptRelease> upgraded = List.of(current, release(current, "2026.12.01-v1.1", "two"),
                release(current, "2027.01.10-v1.2", "three"));
        List<PromptVersionService.Saved> upgrade = service(upgraded).registerProducts(null);

        assertThat(upgrade).extracting(PromptVersionService.Saved::name).containsExactly("v3.0", "v4.0");
        assertThat(versions.find(null, PROMPT, 3).orElseThrow().originName()).isEqualTo("2026.12.01-v1.1");
        assertThat(versions.latestProduct(null, PROMPT).orElseThrow().name()).isEqualTo("v4.0");
        assertThat(service(upgraded).registerProducts(null)).isEmpty();
    }

    /** A product release of another Contexa build: the same document with its release and one changeable part. */
    private static ProductPromptRelease release(ProductPromptRelease base, String release, String word) {
        String text = base.document().replace("release: " + base.release(), "release: " + release)
                .replace("5. When the facts cannot separate the explanations, say what is missing.",
                        "5. When the facts cannot separate the explanations, say what is missing (" + word + ").");
        return new ProductPromptRelease(base.prompt(), release, text);
    }

    @Test
    void numbersCountUpAndTwoSavesAtOnceTakeTwoNumbers() throws Exception {
        versions.registerProducts(null);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        List<Callable<PromptVersionService.Saved>> saves = List.of(
                () -> versions.create(null, organization("v1.0", JUDGE), PromptVersionRecord.SCREEN, null, "a", null),
                () -> versions.create(null, organization("v1.0", JUDGE.replace("duty roster", "approval")),
                        PromptVersionRecord.SCREEN, null, "b", null));
        List<Integer> numbers = new ArrayList<>();
        for (Future<PromptVersionService.Saved> saved : pool.invokeAll(saves)) {
            numbers.add(saved.get().number());
        }
        pool.shutdown();

        assertThat(numbers).containsExactlyInAnyOrder(2, 3);
        assertThat(versions.create(null, organization("v2.0", JUDGE), PromptVersionRecord.SCREEN, null, "c", null)
                .name()).isEqualTo("v4.0");
        assertThat(audited).contains("PROMPT_VERSION_CREATED v1.0", "PROMPT_VERSION_CREATED v4.0");
    }

    @Test
    void aVersionDoesNotChangeAndTheSameResultHasTheSameHash() {
        versions.registerProducts(null);
        PromptVersionService.Saved one = versions.create(null, organization("v1.0", JUDGE), PromptVersionRecord.SCREEN,
                null, "a", null);
        PromptVersionService.Saved same = versions.create(null, organization("v1.0", JUDGE).replace("Finance closing",
                "Another title"), PromptVersionRecord.SCREEN, null, "b", null);
        PromptVersionService.Saved other = versions.create(null, organization("v1.0", JUDGE.replace("duty roster",
                "approvals")), PromptVersionRecord.SCREEN, null, "c", null);

        assertThat(same.number()).isNotEqualTo(one.number());
        assertThat(same.contentHash()).isEqualTo(one.contentHash()).isNotEqualTo(other.contentHash());
        AssembledPrompt read = versions.assembled(null, PROMPT, one.number()).orElseThrow();
        assertThat(read.contentHash()).isEqualTo(one.contentHash());
        assertThat(read.draw(AssembledPrompt.JUDGMENT, Set.of(), null)).contains("1. Weigh the duty roster first.");
        // The table has a row per part of the document, written once; nothing in the service updates a version but
        // its hidden mark.
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_part p join ctxa_prompt_version v on"
                + " v.id = p.version_id where v.version_number = ?", Integer.class, one.number())).isEqualTo(1);
        assertThat(jdbc.queryForObject("select release_status from ctxa_prompt_governance_registry where prompt_version"
                + " = ?", String.class, one.name())).isEqualTo("AVAILABLE");
    }

    @Test
    void theFolderRegistersANewOrChangedDocumentOnceAndRecordsADocumentItCannotSave(@TempDir Path folder)
            throws Exception {
        versions.registerProducts(null);
        Files.writeString(folder.resolve("finance.yaml"), organization("v1.0", JUDGE));
        Files.writeString(folder.resolve("broken.yaml"), organization("v1.0", """
                system:
                  - key: mission
                    text: |
                      You are our analyst.
                """));
        Files.writeString(folder.resolve("notes.txt"), "not a document");
        PromptVersionFolderScanner node1 = new PromptVersionFolderScanner(() -> jdbc, versions, folder, "node-1", () -> null);
        PromptVersionFolderScanner node2 = new PromptVersionFolderScanner(() -> jdbc, service(
                SecurityDecisionPromptDocument.productReleases()), folder, "node-2", null);

        ExecutorService pool = Executors.newFixedThreadPool(2);
        List<Future<PromptVersionFolderScanner.Scan>> scans = pool.invokeAll(List.of(node1::scan, node2::scan));
        int registered = 0;
        for (Future<PromptVersionFolderScanner.Scan> scan : scans) {
            assertThat(scan.get().documents()).isEqualTo(2);
            assertThat(scan.get().errors()).singleElement().asString().startsWith("broken.yaml: LOCKED_PART");
            registered += scan.get().registered();
        }
        pool.shutdown();
        assertThat(registered).as("two nodes register the document once").isEqualTo(1);
        assertThat(node1.scan().registered()).as("the same document read again").isZero();

        Files.writeString(folder.resolve("finance.yaml"), organization("v1.0", JUDGE.replace("duty roster", "plan")));
        assertThat(node1.scan().registered()).as("the changed document").isEqualTo(1);
        List<PromptVersionRecord> fromFolder = versions.list(null, PROMPT, false).stream()
                .filter(record -> PromptVersionRecord.FOLDER.equals(record.origin())).toList();
        assertThat(fromFolder).extracting(PromptVersionRecord::name).containsExactly("v3.0", "v2.0");
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_folder_scan where errors like"
                + " 'broken.yaml%'", Integer.class)).isEqualTo(4);

        // A folder version is changed in its document, not on the screen.
        assertThatThrownBy(() -> versions.create(null, organization("v2.0", JUDGE), PromptVersionRecord.SCREEN, null,
                "admin", null)).isInstanceOf(PromptVersionDocumentException.class)
                .satisfies(refused -> assertThat(codes(refused)).containsExactly(
                        PromptVersionProblem.Code.BASE_FROM_DOCUMENT));
    }

    @Test
    void anImportFindsItsBaseByItsContentHashAndADownloadImportsBackToTheSameContentHash() {
        versions.registerProducts(null);
        PromptVersionService.Saved made = versions.create(null, organization("v1.0", JUDGE), PromptVersionRecord.SCREEN,
                null, "admin", null);
        String diff = versions.export(null, PROMPT, made.number(), false).orElseThrow();
        String rendered = versions.export(null, PROMPT, made.number(), true).orElseThrow();
        assertThat(diff).contains("basedOn: \"v1.0\"", "basedOnHash: \"sha256:"
                + SecurityDecisionPromptDocument.product().contentHash() + "\"");
        assertThat(rendered).contains("kind: \"rendered\"");

        // Another scope stands for another server: its v1.0 is the same product, found by its content hash.
        versions.registerProducts("TENANT-B");
        PromptVersionService.Saved imported = versions.importDocument("TENANT-B", diff.replace("basedOn: \"v1.0\"",
                "basedOn: \"v9.0\""), "finance.yaml", "admin", null);
        assertThat(imported.contentHash()).isEqualTo(made.contentHash());
        assertThat(versions.find("TENANT-B", PROMPT, imported.number()).orElseThrow().origin())
                .isEqualTo(PromptVersionRecord.IMPORT);

        assertThatThrownBy(() -> versions.importDocument("TENANT-B", rendered, "copy.yaml", "admin", null))
                .satisfies(refused -> assertThat(codes(refused)).contains(PromptVersionProblem.Code.RENDERED_DOCUMENT));
        assertThatThrownBy(() -> versions.importDocument("TENANT-B", organization("v1.0", JUDGE)
                .replace("basedOn: v1.0", "basedOnHash: sha256:" + "0".repeat(64)), "lost.yaml", "admin", null))
                .satisfies(refused -> assertThat(codes(refused)).containsExactly(PromptVersionProblem.Code.NO_BASE));
    }

    /**
     * K64 (plan 3.5, check 4): the screen, the folder and an import hold a block added to the user prompt to the length
     * limit alike, as the prompt draws it with its header: a long one does not fit, a short one does, and the size the
     * checks show counts it.
     */
    @Test
    void theScreenTheFolderAndAnImportCountABlockAddedToTheUserPromptInTheLength(@TempDir Path folder)
            throws Exception {
        versions.registerProducts(null);
        int system = PromptAssembler.systemTokens(SecurityDecisionPromptDocument.product());
        PromptAssembler.LengthLimit limit = new PromptAssembler.LengthLimit(system + 1_000 + 300 + 1_000, 300, 1_000);
        String longer = organization("v1.0", userBlock("word ".repeat(4_000)));
        String shorter = "The ledger is exported on the last day.";
        int shortTokens = PromptAssembler.tokensOf(1 + ("=== Finance closing (reference written by your organization)"
                + " ===\n" + shorter + "\n").length());

        PromptVersionService.Preview checked = versions.check(null, organization("v1.0", userBlock(shorter)),
                PromptVersionRecord.SCREEN, limit);
        assertThat(checked.problems()).isEmpty();
        assertThat(checked.systemTokens()).isEqualTo(checked.baseSystemTokens()).isEqualTo(system);
        assertThat(checked.baseAddedUserTokens()).isZero();
        assertThat(checked.addedUserTokens()).isEqualTo(shortTokens);
        assertThat(versions.check(null, longer, PromptVersionRecord.SCREEN, limit).problems())
                .extracting(PromptVersionProblem::code).containsExactly(PromptVersionProblem.Code.TOO_LONG);

        // The screen.
        assertThatThrownBy(() -> versions.create(null, longer, PromptVersionRecord.SCREEN, null, "admin", limit))
                .satisfies(refused -> assertThat(codes(refused)).containsExactly(PromptVersionProblem.Code.TOO_LONG));
        PromptVersionService.Saved screen = versions.create(null, organization("v1.0", userBlock(shorter)),
                PromptVersionRecord.SCREEN, null, "admin", limit);
        assertThat(SecurityDecisionPromptDocument.organizationBlockTokens(
                versions.assembled(null, PROMPT, screen.number()).orElseThrow())).isEqualTo(shortTokens);

        // The folder.
        Files.writeString(folder.resolve("long.yaml"), longer);
        Files.writeString(folder.resolve("short.yaml"), organization("v1.0", userBlock(shorter + " Folder.")));
        PromptVersionFolderScanner.Scan scan = new PromptVersionFolderScanner(() -> jdbc, versions, folder, "node-1",
                () -> limit).scan();
        assertThat(scan.registered()).isEqualTo(1);
        assertThat(scan.errors()).singleElement().asString().startsWith("long.yaml: TOO_LONG");

        // An import.
        assertThatThrownBy(() -> versions.importDocument(null, longer, "long-import.yaml", "admin", limit))
                .satisfies(refused -> assertThat(codes(refused)).containsExactly(PromptVersionProblem.Code.TOO_LONG));
        assertThat(versions.importDocument(null, organization("v1.0", userBlock(shorter + " Import.")),
                "short-import.yaml", "admin", limit).made()).isTrue();

        // On a base that added the block, only what the new version adds more counts; a block taken out counts less.
        String base = screen.name();
        PromptVersionService.Preview more = versions.check(null, organization(base, """
                user:
                  - key: org-desk
                    add-after: org-closing
                    title: Security desk
                    text: The desk answers within an hour.
                """), PromptVersionRecord.SCREEN, limit);
        assertThat(more.baseAddedUserTokens()).isEqualTo(shortTokens);
        assertThat(more.addedUserTokens()).isGreaterThan(shortTokens);
        PromptVersionService.Preview fewer = versions.check(null, organization(base, """
                user:
                  - key: org-closing
                    delete: true
                """), PromptVersionRecord.SCREEN, limit);
        assertThat(fewer.baseAddedUserTokens()).isEqualTo(shortTokens);
        assertThat(fewer.addedUserTokens()).isZero();
    }

    private static String userBlock(String text) {
        return "user:\n  - key: org-closing\n    add-after: REQUEST\n    title: Finance closing\n    text: |\n      "
                + text + "\n";
    }

    @Test
    void aVersionInUseCannotBeHiddenAndAHiddenVersionKeepsItsContent() {
        versions.registerProducts(null);
        PromptVersionService.Saved made = versions.create(null, organization("v1.0", JUDGE), PromptVersionRecord.SCREEN,
                null, "admin", null);
        label(made.name(), "ACTIVE");
        assertThatThrownBy(() -> versions.hide(null, PROMPT, made.number(), "admin"))
                .satisfies(refused -> assertThat(codes(refused)).containsExactly(PromptVersionProblem.Code.IN_USE));

        label(made.name(), "AVAILABLE");
        versions.hide(null, PROMPT, made.number(), "admin");
        assertThat(versions.list(null, PROMPT, false)).extracting(PromptVersionRecord::name).containsExactly("v1.0");
        assertThat(versions.assembled(null, PROMPT, made.number())).isPresent();
        assertThat(audited).contains("PROMPT_VERSION_HIDDEN v2.0");
    }

    @Test
    void anInstallationThatRanBundlesRetiresTheirRowsOnce() {
        jdbc.update("insert into ctxa_prompt_governance_registry (registry_scope, prompt_key, template_key, prompt_version,"
                + " contract_version, prompt_artifact_hash_sha256, release_status, owner_name, template_class_name,"
                + " registration_source) values ('PLATFORM_GLOBAL', ?, ?, '2026.10.24-v19.21', 'C', ?, 'PRODUCTION',"
                + " 'o', 't', 'BUILD')", PROMPT, TEMPLATE_KEY, "a".repeat(64));
        versions.registerProducts(null);

        assertThat(versions.retireEarlierBundles(null)).isEqualTo(1);
        assertThat(versions.retireEarlierBundles(null)).isZero();
        assertThat(jdbc.queryForList("select prompt_version || ' ' || release_status from ctxa_prompt_governance_registry"
                + " order by prompt_version", String.class)).containsExactly("2026.10.24-v19.21 RETIRED",
                "v1.0 AVAILABLE");
    }

    @Test
    void theLabelComesBeforeTheSettingAndTheSettingBeforeTheNewestContexaVersion() {
        versions.registerProducts(null);
        versions.create(null, organization("v1.0", JUDGE), PromptVersionRecord.SCREEN, null, "admin", null);
        versions.create(null, organization("v1.0", JUDGE.replace("duty roster", "plan")), PromptVersionRecord.SCREEN,
                null, "admin", null);
        AtomicReference<String> setting = new AtomicReference<>();
        JdbcPromptGovernanceDescriptorResolver registry = new JdbcPromptGovernanceDescriptorResolver(jdbc,
                new ObjectMapper());
        PromptVersionResolver resolver = new PromptVersionResolver(registry.registrySelector(), versions, setting::get,
                clock);

        assertThat(resolver.select(context(null), "alice"))
                .isEqualTo(new PromptBundleSelection("v1.0", PromptBundleSelectionSource.BUILD_DEFAULT));
        setting.set("v3.0");
        assertThat(resolver.select(context(null), "alice"))
                .isEqualTo(new PromptBundleSelection("v3.0", PromptBundleSelectionSource.CONFIGURATION));
        label("v2.0", "ACTIVE");
        assertThat(new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc, new ObjectMapper())
                .registrySelector(), versions, setting::get, clock)
                .select(context(null), "alice"))
                .isEqualTo(new PromptBundleSelection("v2.0", PromptBundleSelectionSource.REGISTRY));
    }

    /** Plan 3.4: the label of the request's scope, else the label of the platform scope. */
    @Test
    void theRequestScopeRunsItsOwnLabelAndAScopeWithoutOneThePlatforms() {
        versions.registerProducts(null);
        versions.create(null, organization("v1.0", JUDGE), PromptVersionRecord.SCREEN, null, "admin", null);
        versions.create(null, organization("v1.0", JUDGE.replace("duty roster", "plan")), PromptVersionRecord.SCREEN,
                null, "admin", null);
        label("v2.0", "ACTIVE");
        labelIn("TENANT-A", "v3.0", "ACTIVE");
        PromptVersionResolver resolver = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc,
                new ObjectMapper()).registrySelector(), versions, () -> null, clock);

        assertThat(resolver.select(context("TENANT-A"), "alice"))
                .isEqualTo(new PromptBundleSelection("v3.0", PromptBundleSelectionSource.REGISTRY));
        assertThat(resolver.select(context("TENANT-B"), "alice"))
                .isEqualTo(new PromptBundleSelection("v2.0", PromptBundleSelectionSource.REGISTRY));
    }

    /**
     * Plan 3.4: a setting that names a version that does not exist (or is hidden) is said once and the newest Contexa
     * version runs until it exists; a version made later runs from then on; an earlier bundle's name is said once,
     * whatever runs.
     */
    @Test
    void aSettingOfNoVersionALaterVersionOrAnEarlierBundleIsSaidOnceAndPassedOver(CapturedOutput output) {
        versions.registerProducts(null);
        AtomicReference<String> setting = new AtomicReference<>("v3.0");
        PromptVersionResolver resolver = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc,
                new ObjectMapper()).registrySelector(), versions, setting::get, clock);

        assertThat(resolver.select(context(null), "alice")).as("a version not made yet")
                .isEqualTo(new PromptBundleSelection("v1.0", PromptBundleSelectionSource.BUILD_DEFAULT));
        assertThat(resolver.select(context(null), "alice").bundleVersion()).isEqualTo("v1.0");
        versions.create(null, organization("v1.0", JUDGE), PromptVersionRecord.SCREEN, null, "admin", null);
        versions.create(null, organization("v1.0", JUDGE.replace("duty roster", "plan")), PromptVersionRecord.SCREEN,
                null, "admin", null);
        clock.move(Duration.ofSeconds(61));
        assertThat(resolver.select(context(null), "alice")).as("the version made later")
                .isEqualTo(new PromptBundleSelection("v3.0", PromptBundleSelectionSource.CONFIGURATION));
        versions.hide(null, PROMPT, 3, "admin");
        clock.move(Duration.ofSeconds(61));
        assertThat(resolver.select(context(null), "alice").bundleVersion()).as("a hidden version").isEqualTo("v1.0");

        setting.set("2026.10.24-v19.21");
        label("v2.0", "ACTIVE");
        PromptVersionResolver labelled = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc,
                new ObjectMapper()).registrySelector(), versions, setting::get, clock);
        assertThat(labelled.select(context(null), "alice").bundleVersion()).as("an earlier bundle beside a label")
                .isEqualTo("v2.0");
        label("v2.0", "AVAILABLE");
        PromptVersionResolver unlabelled = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc,
                new ObjectMapper()).registrySelector(), versions, setting::get, clock);
        unlabelled.select(context(null), "alice");
        assertThat(unlabelled.select(context(null), "alice").bundleVersion()).as("an earlier bundle").isEqualTo("v1.0");

        assertThat(output.getOut().split("names v3.0, which is not a version", -1)).as("said once").hasSize(2);
        assertThat(output.getOut().split("names 2026.10.24-v19.21, an earlier bundle", -1))
                .as("said once by each resolver").hasSize(3);
    }

    /**
     * Plan 6-3: the start of a node registers the product versions, retires the rows of earlier bundles, reads the
     * document folder once and has it read every minute; another node starting after it registers nothing again.
     */
    @Test
    void theStartOfANodeRegistersTheProductsRetiresTheBundlesAndReadsTheFolderEveryMinute(@TempDir Path folder)
            throws Exception {
        jdbc.update("insert into ctxa_prompt_governance_registry (registry_scope, prompt_key, template_key, prompt_version,"
                + " contract_version, prompt_artifact_hash_sha256, release_status, owner_name, template_class_name,"
                + " registration_source) values ('PLATFORM_GLOBAL', ?, ?, '2026.11.16-v1.0', 'C', ?, 'ACTIVE',"
                + " 'o', 't', 'BUILD')", PROMPT, TEMPLATE_KEY, "a".repeat(64));
        Files.writeString(folder.resolve("finance.yaml"), organization("v1.0", JUDGE));
        TaskScheduler scheduler = mock(TaskScheduler.class);

        new PromptVersionStartup(versions, new PromptVersionFolderScanner(() -> jdbc, versions, folder, "node-1", () -> null))
                .start(scheduler);
        new PromptVersionStartup(service(SecurityDecisionPromptDocument.productReleases()), null).start(null);

        assertThat(versions.list(null, PROMPT, false)).extracting(PromptVersionRecord::name, PromptVersionRecord::origin)
                .containsExactly(tuple("v2.0", PromptVersionRecord.FOLDER), tuple("v1.0", PromptVersionRecord.PRODUCT));
        assertThat(jdbc.queryForList("select prompt_version || ' ' || release_status from ctxa_prompt_governance_registry"
                + " order by prompt_version", String.class))
                .containsExactly("2026.11.16-v1.0 RETIRED", "v1.0 AVAILABLE", "v2.0 AVAILABLE");
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_folder_scan where node_name = 'node-1'"
                + " and registered_count = 1", Integer.class)).isEqualTo(1);
        verify(scheduler).scheduleWithFixedDelay(any(Runnable.class), any(Instant.class),
                eq(PromptVersionStartup.FOLDER_INTERVAL));
        assertThat(audited).contains("PROMPT_VERSION_CREATED v1.0", "PROMPT_VERSION_FOLDER_REGISTERED v2.0");
    }

    @Test
    void aStoreThatCannotReadTheDatabaseRunsWhatItReadAndElseTheProductDocument() {
        versions.registerProducts(null);
        PromptVersionService.Saved made = versions.create(null, organization("v1.0", JUDGE), PromptVersionRecord.SCREEN,
                null, "admin", null);
        PromptVersionService.Saved neverRead = versions.create(null, organization("v1.0", JUDGE.replace("duty roster",
                "plan")), PromptVersionRecord.SCREEN, null, "admin", null);
        AtomicReference<JdbcTemplate> current = new AtomicReference<>(jdbc);
        PromptVersionService failing = new PromptVersionService(current::get, SecurityDecisionPromptDocument
                .productReleases(), TARGETS, null, clock);
        JdbcPromptVersionStore store = new JdbcPromptVersionStore(failing, SecurityDecisionPromptDocument.productStore());
        assertThat(store.find(PROMPT, made.name())).isPresent();

        current.set(new JdbcTemplate());
        assertThat(store.find(PROMPT, made.name())).as("the version read before").isPresent();
        assertThat(store.find(PROMPT, neverRead.name())).as("a version never read: the engine runs the product")
                .isEmpty();
        assertThat(store.find(PROMPT, "2026.11.18-v1.0")).as("the product by its release").isPresent();
        assertThat(store.find(PROMPT, "2026.11.16-v1.0")).as("the product by the bundle's name").isPresent();
        PromptVersionResolver resolver = new PromptVersionResolver(null, failing, () -> null, clock);
        assertThat(resolver.select(context(null), "alice")).isEqualTo(PromptBundleSelection.none());
    }

    @Test
    void twoServersFollowALabelMovedOnOneOfThemWithinTheInvalidationPoll() throws Exception {
        versions.registerProducts(null);
        versions.create(null, organization("v1.0", JUDGE), PromptVersionRecord.SCREEN, null, "admin", null);
        label("v1.0", "ACTIVE");
        PromptVersionResolver serverA = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc,
                new ObjectMapper()).registrySelector(), versions, () -> null, clock);
        PromptVersionResolver serverB = new PromptVersionResolver(new JdbcPromptGovernanceDescriptorResolver(jdbc,
                new ObjectMapper()).registrySelector(), versions, () -> null, clock);
        assertThat(serverA.select(context(null), "a").bundleVersion()).isEqualTo("v1.0");
        assertThat(serverB.select(context(null), "a").bundleVersion()).isEqualTo("v1.0");

        label("v1.0", "AVAILABLE");
        label("v2.0", "ACTIVE");
        new JdbcPromptGovernanceRuntimeCacheInvalidationService(jdbc).publish("PLATFORM_GLOBAL", PROMPT, "v2.0",
                "used for decisions", "admin");
        long started = System.nanoTime();
        while (!("v2.0".equals(serverA.select(context(null), "a").bundleVersion())
                && "v2.0".equals(serverB.select(context(null), "a").bundleVersion()))) {
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(6));
            Thread.sleep(200);
        }
    }

    private static void label(String version, String state) {
        labelIn("PLATFORM_GLOBAL", version, state);
    }

    private static void labelIn(String scope, String version, String state) {
        int updated = jdbc.update("update ctxa_prompt_governance_registry set release_status = ?, updated_at ="
                + " current_timestamp where registry_scope = ? and prompt_key = ? and prompt_version = ?", state, scope,
                PROMPT, version);
        if (updated == 0) {
            jdbc.update("insert into ctxa_prompt_governance_registry (registry_scope, prompt_key, template_key,"
                    + " prompt_version, contract_version, prompt_artifact_hash_sha256, release_status, owner_name,"
                    + " template_class_name, registration_source) values (?, ?, ?, ?, 'C', ?, ?, 'o', 't', 'TEST')",
                    scope, PROMPT, TEMPLATE_KEY, version, "b".repeat(64), state);
        }
    }

    private static PromptGovernanceResolutionContext context(String scope) {
        return new PromptGovernanceResolutionContext(scope, PROMPT, TEMPLATE_KEY, scope, null, null, null, Map.of());
    }

    private static List<PromptVersionProblem.Code> codes(Throwable refused) {
        return ((PromptVersionDocumentException) refused).problems().stream().map(PromptVersionProblem::code)
                .collect(Collectors.toList());
    }

    /** A clock a test moves on, as the caches of the resolver read it. */
    private static final class MovingClock extends Clock {

        private volatile Instant now;

        private MovingClock(Instant now) {
            this.now = now;
        }

        void move(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
