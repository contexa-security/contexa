package io.contexa.contexaiam.admin.promptquality.governance;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.support.VocabularyVersion;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElement;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleManifest;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptRelease;
import io.contexa.contexaiam.admin.promptquality.version.JdbcPromptVersionCatalog;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionRecord;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
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
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * W6-10 (P6-CHANGE-7), plan 3.9: a rollback switches the scope's version used for decisions at once to a version of the
 * database (v2.0) that exists, is not hidden and is registered; it is recorded with its conditions, an emergency stop
 * waits for a second operator, and a refused rollback changes nothing. Each of the 15 refusals is read as plan 3.9 says:
 * the three target refusals are one ({@code TARGET_MISSING_OR_HIDDEN}), the vocabulary is the target's reason codes,
 * and the policy set is asked for by the version's name. The prompts that still have manifests keep the rules of a
 * bundle (plan 6-7).
 */
class PromptBundleRollbackServiceTest {

    private static final String SCOPE = "PLATFORM_GLOBAL";
    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final Map<String, PromptVersionService.RegistryTarget> TARGETS = Map.of(PROMPT,
            new PromptVersionService.RegistryTarget("SecurityDecisionStandard", "CORTEX_PROMPT_CONTRACT_V5",
                    "SecurityDecisionStandardPromptTemplate", "contexa-cortex-core"));
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-17T01:00:00Z"), ZoneOffset.UTC);
    /** The bundles of a prompt that still has manifests: a source that declares its target, and one it does not. */
    private static final String KEY = "cortex.rollback-test";
    private static final String FROM = "2026.01.02-r2";
    private static final String TO = "2026.01.01-r1";
    private static final String UNDECLARED = "2026.01.03-r3";
    private static final String JUDGE = """
            system:
              - key: how-to-judge
                text: |
                  1. Weigh the duty roster first.
            """;

    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    private PromptGovernanceRuntimeCacheInvalidationService invalidation;
    private PromptVersionService versions;
    private PromptBundleRollbackService service;

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

    /** v1.0 is the product version, v2.0 an organization's version on it; both are registered and not used. */
    @BeforeEach
    void twoVersions() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_part, ctxa_prompt_version_trial_case, ctxa_prompt_version_trial,"
                + " ctxa_prompt_version, ctxa_prompt_governance_registry, ctxa_prompt_governance_rollback_execution,"
                + " ctxa_prompt_governance_rollback_ledger, ctxa_prompt_governance_runtime_cache_invalidation CASCADE");
        versions = versions(SecurityDecisionPromptDocument.productReleases());
        versions.registerProducts(null);
        versions.create(null, "prompt: " + PROMPT + "\nbasedOn: v1.0\ntitle: Finance closing\n" + JUDGE,
                PromptVersionRecord.SCREEN, null, "admin", null);
        invalidation = mock(PromptGovernanceRuntimeCacheInvalidationService.class);
        service = service(null);
    }

    // ----- the versions of the database -----

    @Test
    void aRollbackToAShownVersionMakesItTheOneUsedAndTheVersionItReplacesAvailable() {
        status(PROMPT, "v2.0", "ACTIVE");

        PromptBundleRollbackService.Result result = rollback("v2.0", "v1.0", false);

        assertThat(result.status()).isEqualTo(PromptBundleRollbackService.EXECUTED);
        assertThat(result.refusals()).isEmpty();
        assertThat(result.conditions()).isEqualTo(new PromptBundleRollbackService.Conditions(true, true, true, true,
                true, PromptBundleRollbackService.NOT_APPLICABLE));
        assertThat(status(PROMPT, "v1.0")).isEqualTo("ACTIVE");
        assertThat(status(PROMPT, "v2.0")).isEqualTo("AVAILABLE");
        verify(invalidation).publish(eq(SCOPE), eq(PROMPT), eq("v1.0"), contains("v2.0"), eq("operator-a"));
        assertThat(execution(result.executionKey())).isEqualTo(List.of("EXECUTED", "operator-a", "v2.0", "v1.0"));
    }

    @Test
    void anotherVersionStillUsedForDecisionsIsLeftAvailableAndNamed() {
        status(PROMPT, "v2.0", "CANARY");
        status(PROMPT, "v1.0", "ACTIVE");
        versions.create(null, "prompt: " + PROMPT + "\nbasedOn: v1.0\ntitle: Payroll\n" + JUDGE.replace("roster",
                "ledger"), PromptVersionRecord.SCREEN, null, "admin", null);
        status(PROMPT, "v3.0", "AVAILABLE");

        PromptBundleRollbackService.Result result = rollback("v2.0", "v3.0", false);

        assertThat(result.status()).isEqualTo(PromptBundleRollbackService.EXECUTED);
        assertThat(status(PROMPT, "v3.0")).isEqualTo("ACTIVE");
        assertThat(status(PROMPT, "v2.0")).isEqualTo("AVAILABLE");
        assertThat(status(PROMPT, "v1.0")).isEqualTo("AVAILABLE");
        assertThat(conditionsJson(result.executionKey())).contains("superseded", "v1.0");
    }

    /** TARGET_NOT_IN_BUILD, TARGET_NOT_DECLARED and TARGET_NOT_REGISTERED are one refusal: the target is hidden. */
    @Test
    void aHiddenTargetIsRefusedAsMissingOrHiddenAndNothingChanges() {
        status(PROMPT, "v2.0", "ACTIVE");
        versions.hide(null, PROMPT, 1, "admin");

        PromptBundleRollbackService.Result result = rollback("v2.0", "v1.0", false);

        assertThat(result.status()).isEqualTo(PromptBundleRollbackService.REFUSED);
        assertThat(result.refusals()).containsExactly(PromptBundleRollbackService.TARGET_MISSING_OR_HIDDEN);
        assertThat(result.conditions().targetInBuild()).isFalse();
        assertThat(status(PROMPT, "v2.0")).isEqualTo("ACTIVE");
        verify(invalidation, never()).publish(anyString(), anyString(), anyString(), anyString(), anyString());
        assertThat(execution(result.executionKey()).get(0)).isEqualTo("REFUSED");
    }

    /** A version the table does not have is refused once, not three times. */
    @Test
    void aMissingTargetIsRefusedWithOneCode() {
        status(PROMPT, "v2.0", "ACTIVE");

        PromptBundleRollbackService.Result result = rollback("v2.0", "v9.0", false);

        assertThat(result.refusals()).containsExactly(PromptBundleRollbackService.TARGET_MISSING_OR_HIDDEN);
        assertThat(result.conditions()).extracting(PromptBundleRollbackService.Conditions::targetInBuild,
                PromptBundleRollbackService.Conditions::targetRegistered).containsExactly(false, false);
    }

    @Test
    void aTargetWithoutItsRegistryRowIsRefusedAsMissingOrHidden() {
        status(PROMPT, "v2.0", "ACTIVE");
        jdbc.update("delete from ctxa_prompt_governance_registry where prompt_version = 'v1.0'");

        PromptBundleRollbackService.Result result = rollback("v2.0", "v1.0", false);

        assertThat(result.refusals()).containsExactly(PromptBundleRollbackService.TARGET_MISSING_OR_HIDDEN);
        assertThat(result.conditions().targetInBuild()).isTrue();
        assertThat(result.conditions().targetRegistered()).isFalse();
    }

    /** VOCABULARY_INCOMPATIBLE: the reason codes of the target version are not the engine's. */
    @Test
    void aVersionWhoseReasonCodesAreNotTheEnginesIsRefusedAsVocabularyIncompatible() {
        ProductPromptRelease current = SecurityDecisionPromptDocument.productReleases().get(0);
        String fewerCodes = current.document().replace("\r\n", "\n")
                .replace("release: 2026.11.16-v1.0", "release: 2026.12.01-v1.1")
                .replace("      - key: RECORD_DECIDED_AFTER_REQUEST\n        text: \"the record was decided after this"
                        + " request\"\n", "");
        assertThat(fewerCodes).doesNotContain("key: RECORD_DECIDED_AFTER_REQUEST\n");
        versions(List.of(current, new ProductPromptRelease(PROMPT, "2026.12.01-v1.1", fewerCodes)))
                .registerProducts(null);
        status(PROMPT, "v2.0", "ACTIVE");

        PromptBundleRollbackService.Result result = rollback("v2.0", "v3.0", false);

        assertThat(result.refusals()).containsExactly("VOCABULARY_INCOMPATIBLE");
        assertThat(rollback("v2.0", "v1.0", false).status()).isEqualTo(PromptBundleRollbackService.EXECUTED);
    }

    /** POLICY_SET_MISSING: a host with policy sets is asked for the target by the version's name, as before by the bundle's. */
    @Test
    void aMissingPolicySetIsRefusedAndTheHostIsAskedForTheVersion() {
        status(PROMPT, "v2.0", "ACTIVE");
        List<String> asked = new ArrayList<>();
        PromptBundleRollbackService missing = service((scope, key, version) -> {
            asked.add(scope + " " + key + " " + version);
            return false;
        });

        PromptBundleRollbackService.Result refused = missing.rollback(new PromptBundleRollbackService.Request(SCOPE,
                PROMPT, "v2.0", "v1.0", "bad answers", false), "operator-a");

        assertThat(refused.refusals()).containsExactly("POLICY_SET_MISSING");
        assertThat(refused.conditions().policySet()).isEqualTo("MISSING");
        assertThat(asked).containsExactly(SCOPE + " " + PROMPT + " v1.0");
        PromptBundleRollbackService.Result executed = service((scope, key, version) -> true).rollback(
                new PromptBundleRollbackService.Request(SCOPE, PROMPT, "v2.0", "v1.0", "bad answers", false),
                "operator-a");
        assertThat(executed.status()).isEqualTo(PromptBundleRollbackService.EXECUTED);
        assertThat(executed.conditions().policySet()).isEqualTo("PRESENT");
    }

    @Test
    void aSourceThatIsNotUsedForDecisionsIsRefused() {
        PromptBundleRollbackService.Result result = rollback("v2.0", "v1.0", false);

        assertThat(result.refusals()).containsExactly("SOURCE_NOT_EXECUTING");
        assertThat(status(PROMPT, "v1.0")).isEqualTo("AVAILABLE");
    }

    @Test
    void anEmergencyRollbackRunsAtOnceAndAnotherOperatorApprovesIt() {
        status(PROMPT, "v2.0", "ACTIVE");

        PromptBundleRollbackService.Result stop = rollback("v2.0", "v1.0", true);

        assertThat(stop.status()).isEqualTo(PromptBundleRollbackService.AWAITING_APPROVAL);
        assertThat(status(PROMPT, "v1.0")).isEqualTo("ACTIVE");
        assertThat(service.approve(stop.executionKey(), "operator-a").refusals()).containsExactly("APPROVER_IS_ACTOR");
        assertThat(service.approve(stop.executionKey(), "operator-b").status())
                .isEqualTo(PromptBundleRollbackService.APPROVED);
        assertThat(service.approve(stop.executionKey(), "operator-c").refusals())
                .containsExactly("NOT_AWAITING_APPROVAL");
        assertThat(service.approve("RBX-unknown", "operator-b").refusals()).containsExactly("EXECUTION_NOT_FOUND");
        assertThat(execution(stop.executionKey()).get(0)).isEqualTo("APPROVED");
    }

    /** IAM-D25: a request without what a rollback needs is refused at once, and nothing is checked or recorded. */
    @Test
    void anIncompleteRequestIsRefusedWithEachMissingFieldAndNothingIsRecorded() {
        PromptBundleRollbackService.Result empty = service.rollback(null, "operator-a");
        PromptBundleRollbackService.Result blank = service.rollback(
                new PromptBundleRollbackService.Request(" ", "", " ", null, "", false), "operator-a");

        assertThat(empty.status()).isEqualTo(PromptBundleRollbackService.INCOMPLETE);
        assertThat(empty.refusals()).containsExactly("REQUEST_REQUIRED");
        assertThat(blank.status()).isEqualTo(PromptBundleRollbackService.INCOMPLETE);
        assertThat(blank.refusals()).containsExactly("REGISTRY_SCOPE_REQUIRED", "PROMPT_KEY_REQUIRED",
                "FROM_VERSION_REQUIRED", "TO_VERSION_REQUIRED", "REASON_REQUIRED");
        assertThat(blank.executionKey()).isNull();
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_governance_rollback_execution",
                Integer.class)).isZero();
    }

    /** The readiness and the rollback ledger read a target version as the rollback does: shown and registered. */
    @Test
    void theReadinessAndTheRollbackLedgerReadTheVersionTable() {
        status(PROMPT, "v2.0", "ACTIVE");

        PromptBundleRollbackService.Readiness readiness = service.readiness(SCOPE, PROMPT, "v2.0",
                List.of("v1.0", "v9.0"));

        assertThat(readiness.sourceExecuting()).isTrue();
        assertThat(readiness.targets()).containsExactly(
                new PromptBundleRollbackService.TargetReadiness("v1.0", true, true),
                new PromptBundleRollbackService.TargetReadiness("v9.0", false, false));
        assertThat(readiness.runnable()).isTrue();

        ledger(PROMPT, "v2.0", "v1.0", "PLANNED");
        ledger(PROMPT, "v3.0", "v9.0", "READY");
        assertThat(service.correctRollbackReadiness()).isEqualTo(2);
        assertThat(jdbc.queryForList("select rollback_readiness_state from ctxa_prompt_governance_rollback_ledger "
                + "order by prompt_version", String.class))
                .containsExactly("READY", PromptBundleRollbackService.TARGET_MISSING_OR_HIDDEN);
    }

    // ----- the prompts that still have manifests (plan 6-7) -----

    @Test
    void aDeclaredBundleTargetBecomesTheActiveBundleAndTheSourceIsDeprecated() {
        bundle(FROM, "PRODUCTION", "SecurityDecisionStandard", SCOPE);
        bundle(TO, "DRAFT", "SecurityDecisionStandard", SCOPE);

        PromptBundleRollbackService.Result result = service.rollback(
                new PromptBundleRollbackService.Request(SCOPE, KEY, FROM, TO, "bad answers", false), "operator-a");

        assertThat(result.status()).isEqualTo(PromptBundleRollbackService.EXECUTED);
        assertThat(status(KEY, FROM)).isEqualTo("DEPRECATED");
        assertThat(status(KEY, TO)).isEqualTo("ACTIVE");
    }

    /** N-GOV-5: the other active bundles of the scope, prompt key and template are deprecated with the source. */
    @Test
    void aBundleRollbackLeavesItsTargetTheOneActiveReleaseOfItsScopeKeyAndTemplate() {
        bundle(FROM, "CANARY", "SecurityDecisionStandard", SCOPE);
        bundle(TO, "ACTIVE", "SecurityDecisionStandard", SCOPE);
        bundle("2026.01.05-r5", "PRODUCTION", "SecurityDecisionStandard", SCOPE);
        bundle("2026.01.06-r6", "ACTIVE", "SecurityDecisionStandard", "TENANT_A");
        bundle("2026.01.07-r7", "ACTIVE", "OtherTemplate", SCOPE);

        PromptBundleRollbackService.Result result = service.rollback(
                new PromptBundleRollbackService.Request(SCOPE, KEY, FROM, TO, "canary answers", false), "operator-a");

        assertThat(result.status()).isEqualTo(PromptBundleRollbackService.EXECUTED);
        assertThat(status(KEY, TO)).isEqualTo("ACTIVE");
        assertThat(status(KEY, FROM)).isEqualTo("DEPRECATED");
        assertThat(status(KEY, "2026.01.05-r5")).isEqualTo("DEPRECATED");
        assertThat(status(KEY, "2026.01.06-r6")).isEqualTo("ACTIVE");
        assertThat(status(KEY, "2026.01.07-r7")).isEqualTo("ACTIVE");
        assertThat(conditionsJson(result.executionKey())).contains("2026.01.05-r5").doesNotContain("2026.01.06-r6");
    }

    /** A bundle the source's manifest does not declare, or one outside the build, is refused with the one code. */
    @Test
    void anUndeclaredBundleOrOneOutsideTheBuildIsRefusedAsMissingOrHidden() {
        bundle(FROM, "PRODUCTION", "SecurityDecisionStandard", SCOPE);
        bundle(UNDECLARED, "DRAFT", "SecurityDecisionStandard", SCOPE);

        PromptBundleRollbackService.Result undeclared = service.rollback(new PromptBundleRollbackService.Request(SCOPE,
                KEY, FROM, UNDECLARED, "older", false), "operator-a");
        PromptBundleRollbackService.Result outside = service.rollback(new PromptBundleRollbackService.Request(SCOPE,
                KEY, FROM, "2026.01.01-v1", "gone", false), "operator-a");

        assertThat(undeclared.refusals()).containsExactly(PromptBundleRollbackService.TARGET_MISSING_OR_HIDDEN);
        assertThat(undeclared.conditions().targetDeclared()).isFalse();
        assertThat(outside.refusals()).containsExactly(PromptBundleRollbackService.TARGET_MISSING_OR_HIDDEN,
                "VOCABULARY_INCOMPATIBLE");
        assertThat(status(KEY, FROM)).isEqualTo("PRODUCTION");
    }

    // ----- helpers -----

    private PromptVersionService versions(List<ProductPromptRelease> products) {
        return new PromptVersionService(() -> jdbc, products, TARGETS, null, CLOCK);
    }

    private PromptBundleRollbackService service(PromptPolicySetLookup policySets) {
        PromptBundleCatalog catalog = new PromptBundleCatalog(List.of(manifest(FROM, List.of(TO)),
                manifest(TO, List.of()), manifest(UNDECLARED, List.of())))
                .withVersions(new JdbcPromptVersionCatalog(versions, () -> jdbc, () -> null));
        return new PromptBundleRollbackService(jdbc, catalog, invalidation, policySets, new ObjectMapper(), CLOCK,
                new JdbcTestStatusWriter(jdbc));
    }

    private PromptBundleRollbackService.Result rollback(String from, String to, boolean emergency) {
        return service.rollback(new PromptBundleRollbackService.Request(SCOPE, PROMPT, from, to, "bad answers",
                emergency), "operator-a");
    }

    private static PromptBundleManifest manifest(String version, List<String> rollbackTargets) {
        List<PromptBundleElement> elements = PromptBundleHashes.ELEMENT_IDS.stream()
                .map(id -> PromptBundleHashes.present(id, version + " " + id, "test bundle")).toList();
        return new PromptBundleManifest(KEY, version, PromptBundleHashes.bundleHash(elements), elements, null, null,
                "test", List.of(), "pqa", "2026-01-01", null, List.of(VocabularyVersion.CURRENT), rollbackTargets,
                List.of());
    }

    private void status(String key, String version, String status) {
        jdbc.update("update ctxa_prompt_governance_registry set release_status = ? where prompt_key = ? and"
                + " prompt_version = ?", status, key, version);
    }

    private String status(String key, String version) {
        return jdbc.queryForObject("select release_status from ctxa_prompt_governance_registry where prompt_key = ? and"
                + " prompt_version = ?", String.class, key, version);
    }

    private void bundle(String version, String status, String template, String scope) {
        jdbc.update("""
                insert into ctxa_prompt_governance_registry (registry_scope, prompt_key, template_key, prompt_version,
                    contract_version, prompt_artifact_hash_sha256, release_status, owner_name,
                    template_class_name, registration_source)
                values (?, ?, ?, ?, 'CORTEX_PROMPT_CONTRACT_V3', 'hash', ?, 'pqa',
                    'SecurityDecisionStandardPromptTemplate', 'test')""", scope, KEY, template, version, status);
    }

    private void ledger(String key, String version, String target, String readiness) {
        jdbc.update("""
                        insert into ctxa_prompt_governance_rollback_ledger (registry_scope, prompt_key, prompt_version,
                            rollback_reference, rollback_target_prompt_version, rollback_state, rollback_readiness_state,
                            rollback_strategy, rollback_reason, prepared_by, registration_source)
                        values (?, ?, ?, 'ref', ?, 'TARGET_DECLARED', ?, 'VERSION_ROLLBACK', 'test', 'pqa', 'test')""",
                SCOPE, key, version, target, readiness);
    }

    private List<String> execution(String executionKey) {
        return jdbc.queryForObject("select status, actor, from_version, to_version from "
                        + "ctxa_prompt_governance_rollback_execution where execution_key = ?",
                (rs, n) -> List.of(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)), executionKey);
    }

    private String conditionsJson(String executionKey) {
        return jdbc.queryForObject("select conditions_json from ctxa_prompt_governance_rollback_execution where"
                + " execution_key = ?", String.class, executionKey);
    }
}
