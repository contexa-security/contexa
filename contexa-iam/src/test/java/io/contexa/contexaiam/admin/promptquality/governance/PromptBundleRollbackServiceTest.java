package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElement;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleManifest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * W6-10 (P6-CHANGE-7): a rollback switches the scope's active bundle at once to a target its manifest declares when the
 * target is in this build and reads the stored vocabulary; it is recorded with its conditions, an emergency stop waits
 * for a second operator, and a refused rollback changes nothing. PV-3: a target is ready only when it is in the build.
 * The bundles are this build's own (v20.22 declares v19.18).
 */
class PromptBundleRollbackServiceTest {

    private static final String SCOPE = "PLATFORM_GLOBAL";
    /**
     * Plan 6-2: the build runs one security decision bundle, which declares no rollback target, so the rollback is tested
     * on the bundles of a test catalog: a source that declares its target, the target, and a bundle no source declares.
     * Outside the security decision a bundle is in the build when the catalog holds its manifest.
     */
    private static final String KEY = "cortex.rollback-test";
    private static final String FROM = "2026.01.02-r2";
    private static final String TO = "2026.01.01-r1";
    private static final String UNDECLARED = "2026.01.03-r3";
    private static final String SECURITY_DECISION = "cortex.security-decision";
    /** K1: a security decision bundle whose manifest the catalog holds as a record but whose prompt no code draws. */
    private static final String RECORD_ONLY = "2026.10.30-v21.19";

    private PostgresTestDatabase database;
    private JdbcTemplate jdbc;
    private PromptGovernanceRuntimeCacheInvalidationService invalidation;
    private PromptBundleRollbackService service;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        PromptGovernanceTestSchema.apply(jdbc);
        invalidation = mock(PromptGovernanceRuntimeCacheInvalidationService.class);
        service = new PromptBundleRollbackService(jdbc, catalog(), invalidation, null,
                new ObjectMapper(), Clock.fixed(Instant.parse("2026-10-16T01:00:00Z"), ZoneOffset.UTC),
                new JdbcTestStatusWriter(jdbc));
    }

    @AfterEach
    void tearDown() {
        if (database != null) {
            database.close();
        }
    }

    @Test
    void aDeclaredTargetInTheBuildBecomesTheActiveBundle() {
        registry(FROM, "PRODUCTION");
        registry(TO, "DRAFT");

        PromptBundleRollbackService.Result result = service.rollback(
                new PromptBundleRollbackService.Request(SCOPE, KEY, FROM, TO, "bad answers", false), "operator-a");

        assertThat(result.status()).isEqualTo(PromptBundleRollbackService.EXECUTED);
        assertThat(result.conditions().policySet()).isEqualTo(PromptBundleRollbackService.NOT_APPLICABLE);
        // N-RBK-1: a rollback writes the canonical names, as the release gate does; older names are only read.
        assertThat(status(FROM)).isEqualTo("DEPRECATED");
        assertThat(status(TO)).isEqualTo("ACTIVE");
        verify(invalidation).publish(eq(SCOPE), eq(KEY), eq(TO), contains(FROM), eq("operator-a"));
        assertThat(execution(result.executionKey())).isEqualTo(List.of("EXECUTED", "operator-a", FROM, TO));
    }

    @Test
    void aCanarySourceTheGateWroteUnderItsCanonicalNameRollsBackToTheActiveTarget() {
        registry(FROM, "CANARY");
        registry(TO, "ACTIVE");

        PromptBundleRollbackService.Result result = service.rollback(
                new PromptBundleRollbackService.Request(SCOPE, KEY, FROM, TO, "canary answers", false), "operator-a");

        assertThat(result.status()).isEqualTo(PromptBundleRollbackService.EXECUTED);
        assertThat(status(FROM)).isEqualTo("DEPRECATED");
        assertThat(status(TO)).isEqualTo("ACTIVE");
    }

    /**
     * N-GOV-5: the target is the one active release of its scope, prompt key and template after a rollback; the other
     * active releases it replaces (bundles left active before N-GOV-5) are deprecated with the source and named in the
     * execution's conditions. Another scope and another template keep their releases.
     */
    @Test
    void aRollbackLeavesItsTargetTheOneActiveReleaseOfItsScopeKeyAndTemplate() {
        registry(FROM, "CANARY");
        registry(TO, "ACTIVE");
        registry("2026.10.13-v19.9", "PRODUCTION");
        registry("2026.10.11-v19.8", "ACTIVE");
        release("TENANT_A", "SecurityDecisionStandard", "2026.10.11-v19.7", "ACTIVE");
        release(SCOPE, "OtherTemplate", "2026.10.11-v19.5", "ACTIVE");

        PromptBundleRollbackService.Result result = service.rollback(
                new PromptBundleRollbackService.Request(SCOPE, KEY, FROM, TO, "canary answers", false), "operator-a");

        assertThat(result.status()).isEqualTo(PromptBundleRollbackService.EXECUTED);
        assertThat(status(TO)).isEqualTo("ACTIVE");
        assertThat(status(FROM)).isEqualTo("DEPRECATED");
        assertThat(status("2026.10.13-v19.9")).isEqualTo("DEPRECATED");
        assertThat(status("2026.10.11-v19.8")).isEqualTo("DEPRECATED");
        assertThat(status("2026.10.11-v19.7")).isEqualTo("ACTIVE");
        assertThat(status("2026.10.11-v19.5")).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("select conditions_json from ctxa_prompt_governance_rollback_execution "
                + "where execution_key = ?", String.class, result.executionKey()))
                .contains("superseded", "2026.10.13-v19.9", "2026.10.11-v19.8")
                .doesNotContain("2026.10.11-v19.7", "2026.10.11-v19.5");
    }

    @Test
    void aTargetTheManifestDoesNotDeclareIsRefusedAndNothingChanges() {
        // A bundle in the build that the source's manifest does not declare as its rollback target.
        String undeclared = UNDECLARED;
        registry(FROM, "PRODUCTION");
        registry(undeclared, "DRAFT");

        PromptBundleRollbackService.Result result = service.rollback(new PromptBundleRollbackService.Request(SCOPE, KEY,
                FROM, undeclared, "older", false), "operator-a");

        assertThat(result.status()).isEqualTo(PromptBundleRollbackService.REFUSED);
        assertThat(result.refusals()).containsExactly("TARGET_NOT_DECLARED");
        assertThat(status(FROM)).isEqualTo("PRODUCTION");
        verify(invalidation, never()).publish(anyString(), anyString(), anyString(), anyString(), anyString());
        assertThat(execution(result.executionKey()).get(0)).isEqualTo("REFUSED");
    }

    /**
     * K1 (plan 1-9): a security decision manifest declares a rollback target whose manifest the catalog holds, but no
     * code of this build renders it; a rollback to it would run the build's default bundle, so it is not in the build.
     */
    @Test
    void aDeclaredTargetTheBuildKeepsOnlyAsARecordIsNotInTheBuild() {
        String source = SecurityDecisionPromptBundles.V1.version();
        String recordOnly = RECORD_ONLY;
        registry(SECURITY_DECISION, source, "PRODUCTION");
        registry(SECURITY_DECISION, recordOnly, "DEPRECATED");

        PromptBundleRollbackService.Result result = service.rollback(new PromptBundleRollbackService.Request(SCOPE,
                SECURITY_DECISION, source, recordOnly, "older", false), "operator-a");

        assertThat(result.status()).isEqualTo(PromptBundleRollbackService.REFUSED);
        assertThat(result.refusals()).containsExactly("TARGET_NOT_IN_BUILD");
        assertThat(status(source)).isEqualTo("PRODUCTION");
        assertThat(service.readiness(SCOPE, SECURITY_DECISION, source, List.of(recordOnly)).targets())
                .singleElement()
                .satisfies(target -> assertThat(target.inBuild()).isFalse());
    }

    @Test
    void aTargetOutsideTheBuildIsRefused() {
        registry(FROM, "PRODUCTION");

        PromptBundleRollbackService.Result result = service.rollback(new PromptBundleRollbackService.Request(SCOPE, KEY,
                FROM, "2026.01.01-v1", "gone", false), "operator-a");

        assertThat(result.refusals()).contains("TARGET_NOT_IN_BUILD", "TARGET_NOT_DECLARED", "TARGET_NOT_REGISTERED");
    }

    @Test
    void anEmergencyStopRunsAtOnceAndWaitsForASecondOperator() {
        registry(FROM, "PRODUCTION");
        registry(TO, "DRAFT");

        PromptBundleRollbackService.Result stop = service.rollback(
                new PromptBundleRollbackService.Request(SCOPE, KEY, FROM, TO, "leak", true), "operator-a");

        assertThat(stop.status()).isEqualTo(PromptBundleRollbackService.AWAITING_APPROVAL);
        assertThat(status(TO)).isEqualTo("ACTIVE");
        assertThat(service.approve(stop.executionKey(), "operator-a").refusals()).containsExactly("APPROVER_IS_ACTOR");
        assertThat(service.approve(stop.executionKey(), "operator-b").status())
                .isEqualTo(PromptBundleRollbackService.APPROVED);
        assertThat(execution(stop.executionKey()).get(0)).isEqualTo("APPROVED");
    }

    @Test
    void aRollbackTargetIsReadyOnlyWhenItsBundleIsInTheBuild() {
        ledger(FROM, TO, "READY");
        ledger("2026.10.15-v20.20", "2026.01.01-v1", "READY");

        assertThat(service.correctRollbackReadiness()).isEqualTo(1);
        assertThat(jdbc.queryForList("select rollback_readiness_state from ctxa_prompt_governance_rollback_ledger "
                + "order by prompt_version", String.class)).containsExactly("TARGET_NOT_IN_BUILD", "READY");
    }

    /** IAM-D25: a request without what a rollback needs is refused at once, and nothing is checked or recorded. */
    @Test
    void anIncompleteRequestIsRefusedWithItsMissingFieldsAndNothingIsRecorded() {
        PromptBundleRollbackService.Result empty = service.rollback(null, "operator-a");
        PromptBundleRollbackService.Result partial = service.rollback(
                new PromptBundleRollbackService.Request(SCOPE, KEY, " ", TO, "", false), "operator-a");

        assertThat(empty.status()).isEqualTo(PromptBundleRollbackService.INCOMPLETE);
        assertThat(empty.refusals()).containsExactly("REQUEST_REQUIRED");
        assertThat(partial.status()).isEqualTo(PromptBundleRollbackService.INCOMPLETE);
        assertThat(partial.refusals()).containsExactly("FROM_VERSION_REQUIRED", "REASON_REQUIRED");
        assertThat(partial.executionKey()).isNull();
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_governance_rollback_execution",
                Integer.class)).isZero();
    }

    /**
     * IAM-D55: the version screen offers a rollback only when the same conditions the rollback checks would accept it:
     * the bundle executes in the scope, and a declared target is in the build and registered.
     */
    @Test
    void readinessReadsTheSourceAndTargetConditionsTheRollbackChecks() {
        registry(FROM, "CANARY");
        registry(TO, "DRAFT");

        PromptBundleRollbackService.Readiness executing = service.readiness(SCOPE, KEY, FROM,
                List.of(TO, "2026.01.01-v1"));

        assertThat(executing.sourceExecuting()).isTrue();
        assertThat(executing.targets()).containsExactly(
                new PromptBundleRollbackService.TargetReadiness(TO, true, true),
                new PromptBundleRollbackService.TargetReadiness("2026.01.01-v1", false, false));
        assertThat(executing.runnable()).isTrue();

        PromptBundleRollbackService.Readiness draft = service.readiness(SCOPE, KEY, TO, List.of(FROM));
        assertThat(draft.sourceExecuting()).isFalse();
        assertThat(draft.runnable()).isFalse();
        assertThat(service.readiness(SCOPE, KEY, FROM, null).runnable()).isFalse();
    }

    private void registry(String version, String status) {
        registry(KEY, version, status);
    }

    private void registry(String key, String version, String status) {
        jdbc.update("""
                        insert into ctxa_prompt_governance_registry (registry_scope, prompt_key, template_key, prompt_version,
                            contract_version, prompt_artifact_hash_sha256, release_status, owner_name,
                            template_class_name, registration_source)
                        values (?, ?, 'SecurityDecisionStandard', ?, 'CORTEX_PROMPT_CONTRACT_V3', 'hash', ?, 'pqa',
                            'SecurityDecisionStandardPromptTemplate', 'test')""",
                SCOPE, key, version, status);
    }

    /** The bundles the tests roll between, and a security decision bundle that declares a record as its target. */
    private static PromptBundleCatalog catalog() {
        return new PromptBundleCatalog(List.of(manifest(KEY, FROM, List.of(TO)), manifest(KEY, TO, List.of()),
                manifest(KEY, UNDECLARED, List.of()),
                manifest(SECURITY_DECISION, SecurityDecisionPromptBundles.V1.version(), List.of(RECORD_ONLY)),
                manifest(SECURITY_DECISION, RECORD_ONLY, List.of())));
    }

    private static PromptBundleManifest manifest(String key, String version, List<String> rollbackTargets) {
        List<PromptBundleElement> elements = List.of(PromptBundleHashes.present("B1", version, "test bundle"));
        return new PromptBundleManifest(key, version, PromptBundleHashes.bundleHash(elements), elements, null, null,
                "test", List.of(), "pqa", "2026-01-01", null, List.of(), rollbackTargets, List.of());
    }

    private void release(String scope, String templateKey, String version, String status) {
        jdbc.update("""
                insert into ctxa_prompt_governance_registry (registry_scope, prompt_key, template_key, prompt_version,
                    contract_version, prompt_artifact_hash_sha256, release_status, owner_name,
                    template_class_name, registration_source)
                values (?, ?, ?, ?, 'CORTEX_PROMPT_CONTRACT_V3', 'hash', ?, 'pqa',
                    'SecurityDecisionStandardPromptTemplate', 'test')""",
                scope, KEY, templateKey, version, status);
    }

    private void ledger(String version, String target, String readiness) {
        jdbc.update("""
                        insert into ctxa_prompt_governance_rollback_ledger (registry_scope, prompt_key, prompt_version,
                            rollback_reference, rollback_target_prompt_version, rollback_state, rollback_readiness_state,
                            rollback_strategy, rollback_reason, prepared_by, registration_source)
                        values (?, ?, ?, 'ref', ?, 'TARGET_DECLARED', ?, 'BUNDLE', 'test', 'pqa', 'test')""",
                SCOPE, KEY, version, target, readiness);
    }

    private String status(String version) {
        return jdbc.queryForObject("select release_status from ctxa_prompt_governance_registry where prompt_version = ?",
                String.class, version);
    }

    private List<String> execution(String executionKey) {
        return jdbc.queryForObject("select status, actor, from_version, to_version from "
                        + "ctxa_prompt_governance_rollback_execution where execution_key = ?",
                (rs, n) -> List.of(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)), executionKey);
    }
}
