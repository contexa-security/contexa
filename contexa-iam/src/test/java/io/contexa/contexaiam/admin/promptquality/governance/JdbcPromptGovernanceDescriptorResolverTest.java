package io.contexa.contexaiam.admin.promptquality.governance;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.std.components.prompt.PromptCompressionLedger;
import io.contexa.contexacore.std.components.prompt.PromptEvidenceCompleteness;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptorResolution;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(OutputCaptureExtension.class)
class JdbcPromptGovernanceDescriptorResolverTest {

    private static final String PROMPT_KEY = "cortex.security-decision";
    private static final String TEMPLATE_KEY = "SecurityDecisionStandard";
    private static final String V19 = "2026.10.11-v19.8";
    private static final String V20 = "2026.10.12-v20";

    private PostgresTestDatabase database;
    private JdbcTemplate jdbcTemplate;
    private JdbcPromptGovernanceDescriptorResolver resolver;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbcTemplate = database.jdbcTemplate();
        PromptGovernanceTestSchema.apply(jdbcTemplate);
        resolver = new JdbcPromptGovernanceDescriptorResolver(jdbcTemplate, new ObjectMapper(), 60_000L, 0L);
    }

    @AfterEach
    void tearDown() {
        if (database != null) {
            database.close();
        }
    }

    @Test
    void matchingCoreGovernanceReleaseOverridesRuntimeDescriptorMetadata() {
        insertRegistryRelease("ACTIVE_FOR_SCOPE", "base-version", "registry-artifact-hash-a");

        PromptGovernanceDescriptor fallback = fallbackDescriptor();
        PromptGovernanceDescriptorResolution resolution = resolver.resolve(
                fallback,
                new PromptGovernanceResolutionContext(
                        "PLATFORM_GLOBAL",
                        fallback.promptKey(),
                        fallback.templateKey(),
                        "tenant-a",
                        "resource-a",
                        "/finance/reports",
                        "GET",
                        Map.of()));

        assertThat(resolution.descriptor().promptVersion()).isEqualTo("base-version");
        assertThat(resolution.supplementalMetadata())
                .containsEntry("releaseStatus", "ACTIVE_FOR_SCOPE")
                .containsEntry("promptArtifactHashSha256", "registry-artifact-hash-a")
                .containsEntry("governanceResolutionSource", "CORE_PROMPT_GOVERNANCE_REGISTRY");

        PromptExecutionMetadata metadata = PromptGovernanceSupport.buildExecutionMetadata(
                resolution.descriptor(),
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                PromptEvidenceCompleteness.SUFFICIENT,
                null,
                "system prompt",
                "user prompt",
                "system prompt",
                "user prompt",
                PromptCompressionLedger.identity("system prompt", "user prompt"),
                resolution.supplementalMetadata());
        @SuppressWarnings("unchecked")
        Map<String, Object> governanceDescriptor =
                (Map<String, Object>) metadata.toMetadataMap().get("governanceDescriptor");

        assertThat(governanceDescriptor)
                .containsEntry("releaseStatus", "ACTIVE_FOR_SCOPE")
                .containsEntry("promptArtifactHashSha256", "registry-artifact-hash-a")
                .containsEntry("promptVersion", "base-version");
    }

    @Test
    void cacheInvalidationRefreshesResolvedRelease() {
        insertRegistryRelease("ACTIVE_FOR_SCOPE", "base-version", "registry-artifact-hash-a");
        PromptGovernanceDescriptor fallback = fallbackDescriptor();
        PromptGovernanceResolutionContext context = context("PLATFORM_GLOBAL");

        assertThat(resolver.resolve(fallback, context).supplementalMetadata())
                .containsEntry("promptArtifactHashSha256", "registry-artifact-hash-a");

        jdbcTemplate.update(
                """
                        update prompt_governance_registry
                           set prompt_artifact_hash_sha256 = ?,
                               updated_at = ?
                         where registry_scope = ?
                           and prompt_key = ?
                           and template_key = ?
                           and prompt_version = ?
                           and contract_version = ?
                        """,
                "registry-artifact-hash-b",
                Timestamp.valueOf("2026-04-27 10:05:00"),
                "PLATFORM_GLOBAL",
                fallback.promptKey(),
                fallback.templateKey(),
                fallback.promptVersion(),
                fallback.contractVersion());
        insertInvalidation("event-base-version", "PLATFORM_GLOBAL", fallback.promptKey(), fallback.templateKey(),
                fallback.promptVersion(), fallback.contractVersion());

        assertThat(resolver.resolve(fallback, context).supplementalMetadata())
                .containsEntry("promptArtifactHashSha256", "registry-artifact-hash-b");
    }

    @Test
    void activeReleaseForDifferentVersionCannotOverrideRuntimeDescriptor() {
        insertRegistryRelease("ACTIVE_FOR_SCOPE", "old-version", "old-artifact-hash");

        PromptGovernanceDescriptor fallback = fallbackDescriptor();
        PromptGovernanceDescriptorResolution resolution = resolver.resolve(fallback, context("PLATFORM_GLOBAL"));

        assertThat(resolution.descriptor()).isEqualTo(fallback);
        assertThat(resolution.supplementalMetadata())
                .containsEntry("promptGovernanceCacheState", "MISS");
    }

    /** W3-16: the registry selector runs the active release of the request's scope (PV-2). */
    @Test
    void theRegistrySelectsTheActiveReleaseOfTheScope() {
        insertRelease("PLATFORM_GLOBAL", "PRODUCTION", V19, null, "2026-10-11 10:00:00");
        insertRelease("PLATFORM_GLOBAL", "AVAILABLE", V20, null, "2026-10-12 10:00:00");

        assertThat(selector().select(context("PLATFORM_GLOBAL"), "alice"))
                .isEqualTo(new PromptBundleSelection(V19, PromptBundleSelectionSource.REGISTRY));
    }

    @Test
    void theLatestActiveReleaseIsSelected() {
        insertRelease("PLATFORM_GLOBAL", "ACTIVE", V19, null, "2026-10-11 10:00:00");
        insertRelease("PLATFORM_GLOBAL", "ACTIVE", V20, null, "2026-10-12 10:00:00");

        assertThat(selector().select(context("PLATFORM_GLOBAL"), "alice"))
                .isEqualTo(new PromptBundleSelection(V20, PromptBundleSelectionSource.REGISTRY));
    }

    @Test
    void withoutAnExecutingReleaseTheBuildDefaultRuns() {
        insertRelease("PLATFORM_GLOBAL", "AVAILABLE", V20, null, "2026-10-12 10:00:00");
        insertRelease("PLATFORM_GLOBAL", "DEPRECATED", V19, null, "2026-10-11 10:00:00");

        assertThat(selector().select(context("PLATFORM_GLOBAL"), "alice")).isEqualTo(PromptBundleSelection.none());
    }

    /** A canary release runs for the requests inside its share of the scope; the rest run the active release. */
    @Test
    void aCanaryReleaseRunsInsideItsShareOfTheScope() {
        int aliceShare = Math.floorMod("alice".hashCode(), 100);
        insertRelease("PLATFORM_GLOBAL", "ACTIVE", V19, null, "2026-10-11 10:00:00");
        insertRelease("PLATFORM_GLOBAL", "CANARY", V20, aliceShare + 1, "2026-10-12 10:00:00");

        assertThat(selector().select(context("PLATFORM_GLOBAL"), "alice"))
                .isEqualTo(new PromptBundleSelection(V20, PromptBundleSelectionSource.CANARY));

        setCanaryPercent(V20, aliceShare);
        assertThat(freshSelector().select(context("PLATFORM_GLOBAL"), "alice"))
                .isEqualTo(new PromptBundleSelection(V19, PromptBundleSelectionSource.REGISTRY));

        setCanaryPercent(V20, 0);
        assertThat(freshSelector().select(context("PLATFORM_GLOBAL"), "alice"))
                .isEqualTo(new PromptBundleSelection(V19, PromptBundleSelectionSource.REGISTRY));
    }

    @Test
    void aCanaryWithoutAShareRunsForTheWholeScope() {
        insertRelease("PLATFORM_GLOBAL", "ACTIVE", V19, null, "2026-10-11 10:00:00");
        insertRelease("PLATFORM_GLOBAL", "ACTIVE_FOR_SCOPE", V20, null, "2026-10-12 10:00:00");

        for (String subject : List.of("alice", "bob", "carol")) {
            assertThat(selector().select(context("PLATFORM_GLOBAL"), subject))
                    .isEqualTo(new PromptBundleSelection(V20, PromptBundleSelectionSource.CANARY));
        }
    }

    /** The releases of the request's own scope come before the platform's. */
    @Test
    void theRequestScopeComesBeforeThePlatformScope() {
        insertRelease("PLATFORM_GLOBAL", "ACTIVE", V19, null, "2026-10-11 10:00:00");
        insertRelease("TENANT_A", "ACTIVE", V20, null, "2026-10-12 10:00:00");

        assertThat(selector().select(context("tenant_a"), "alice"))
                .isEqualTo(new PromptBundleSelection(V20, PromptBundleSelectionSource.REGISTRY));
        assertThat(selector().select(context("TENANT_B"), "alice"))
                .isEqualTo(new PromptBundleSelection(V19, PromptBundleSelectionSource.REGISTRY));
    }

    /**
     * PV-23: an invalidation event clears the selection of its prompt key even without a template key or a contract
     * version, so an activation is seen at the next poll and not only when the cache expires.
     */
    @Test
    void anInvalidationOfThePromptKeyClearsTheSelection() {
        insertRelease("PLATFORM_GLOBAL", "ACTIVE", V19, null, "2026-10-11 10:00:00");
        insertRelease("PLATFORM_GLOBAL", "AVAILABLE", V20, null, "2026-10-12 10:00:00");
        assertThat(selector().select(context("PLATFORM_GLOBAL"), "alice").bundleVersion()).isEqualTo(V19);

        jdbcTemplate.update("update prompt_governance_registry set release_status = 'ACTIVE', updated_at = ? "
                + "where prompt_version = ?", Timestamp.valueOf("2026-10-12 11:00:00"), V20);
        insertInvalidation("event-other-key", "PLATFORM_GLOBAL", "other.prompt", null, "1", null);
        assertThat(selector().select(context("PLATFORM_GLOBAL"), "alice").bundleVersion())
                .as("an event of another prompt key leaves the selection cached")
                .isEqualTo(V19);

        insertInvalidation("event-v20-active", "PLATFORM_GLOBAL", PROMPT_KEY, null, V20, null);
        assertThat(selector().select(context("PLATFORM_GLOBAL"), "alice").bundleVersion()).isEqualTo(V20);
    }

    @Test
    void anInvalidationOfThePlatformScopeClearsTheSelectionOfEveryScope() {
        insertRelease("PLATFORM_GLOBAL", "ACTIVE", V19, null, "2026-10-11 10:00:00");
        assertThat(selector().select(context("TENANT_A"), "alice").bundleVersion()).isEqualTo(V19);

        insertRelease("PLATFORM_GLOBAL", "ACTIVE", V20, null, "2026-10-12 11:00:00");
        insertInvalidation("event-platform", "PLATFORM_GLOBAL", PROMPT_KEY, TEMPLATE_KEY, V20, "CORTEX_PROMPT_CONTRACT_V3");

        assertThat(selector().select(context("TENANT_A"), "alice").bundleVersion()).isEqualTo(V20);
    }

    /** PV-23: a registry or invalidation read that fails is logged as an error, and the build default runs. */
    @Test
    void aFailingRegistryReadIsLoggedAndTheBuildDefaultRuns(CapturedOutput output) {
        jdbcTemplate.execute("drop table prompt_governance_registry");
        jdbcTemplate.execute("drop table prompt_governance_runtime_cache_invalidation");

        assertThat(selector().select(context("PLATFORM_GLOBAL"), "alice")).isEqualTo(PromptBundleSelection.none());
        assertThat(output.getOut() + output.getErr())
                .contains("Prompt governance registry releases could not be read")
                .contains("Prompt governance cache invalidations could not be read");
    }

    private PromptBundleSelector selector() {
        return resolver.registrySelector();
    }

    /** A resolver without cached selections, for a registry changed without an invalidation event. */
    private PromptBundleSelector freshSelector() {
        resolver = new JdbcPromptGovernanceDescriptorResolver(jdbcTemplate, new ObjectMapper(), 60_000L, 0L);
        return resolver.registrySelector();
    }

    private void setCanaryPercent(String version, int percent) {
        jdbcTemplate.update("update prompt_governance_registry set canary_percent = ? where prompt_version = ?",
                percent, version);
    }

    private static PromptGovernanceResolutionContext context(String registryScope) {
        return new PromptGovernanceResolutionContext(registryScope, PROMPT_KEY, TEMPLATE_KEY, "tenant-a", "resource-a",
                "/finance/reports", "GET", Map.of());
    }

    private void insertInvalidation(String eventId, String scope, String promptKey, String templateKey,
                                    String promptVersion, String contractVersion) {
        jdbcTemplate.update(
                """
                        insert into prompt_governance_runtime_cache_invalidation (
                            event_id, registry_scope, prompt_key, template_key,
                            prompt_version, contract_version,
                            invalidation_reason, published_by, published_at, consumed
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                eventId, scope, promptKey, templateKey, promptVersion, contractVersion, "test release", "test",
                Timestamp.valueOf("2026-04-27 10:05:00"), false);
    }

    private void insertRelease(String scope, String releaseStatus, String promptVersion, Integer canaryPercent,
                               String updatedAt) {
        jdbcTemplate.update(
                """
                        insert into prompt_governance_registry (
                            registry_scope, prompt_key, template_key, prompt_version,
                            contract_version, prompt_artifact_hash_sha256, release_status,
                            owner_name, release_approval_reference, evaluation_baseline_reference,
                            rollback_prompt_version, change_summary, template_class_name,
                            registration_source, supported_model_profiles_json, canary_percent, created_at, updated_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                scope,
                PROMPT_KEY,
                TEMPLATE_KEY,
                promptVersion,
                V20.equals(promptVersion) ? "CORTEX_PROMPT_CONTRACT_V3" : "CORTEX_PROMPT_CONTRACT_V2",
                "hash-" + promptVersion,
                releaseStatus,
                "pqa",
                "PQA-SCOPE-RELEASE:test",
                "PQA-PORTFOLIO-PASSED:test",
                null,
                "test release",
                "io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate",
                "test",
                "[\"MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI\"]",
                canaryPercent,
                Timestamp.valueOf(updatedAt),
                Timestamp.valueOf(updatedAt));
    }

    private void insertRegistryRelease(String releaseStatus, String promptVersion, String artifactHash) {
        jdbcTemplate.update(
                """
                        insert into prompt_governance_registry (
                            registry_scope, prompt_key, template_key, prompt_version,
                            contract_version, prompt_artifact_hash_sha256, release_status,
                            owner_name, release_approval_reference, evaluation_baseline_reference,
                            rollback_prompt_version, change_summary, template_class_name,
                            registration_source, supported_model_profiles_json, created_at, updated_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                "PLATFORM_GLOBAL",
                PROMPT_KEY,
                TEMPLATE_KEY,
                promptVersion,
                "CORTEX_PROMPT_CONTRACT_V2",
                artifactHash,
                releaseStatus,
                "pqa",
                "PQA-SCOPE-RELEASE:test",
                "PQA-PORTFOLIO-PASSED:test",
                "base-version",
                "test release",
                "io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate",
                "test",
                "[\"MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI\"]",
                Timestamp.valueOf("2026-04-27 10:00:00"),
                promptVersion.endsWith("b") ? Timestamp.valueOf("2026-04-27 10:05:00") : Timestamp.valueOf("2026-04-27 10:00:00"));
    }

    private PromptGovernanceDescriptor fallbackDescriptor() {
        return new PromptGovernanceDescriptor(
                PROMPT_KEY,
                TEMPLATE_KEY,
                "base-version",
                "CORTEX_PROMPT_CONTRACT_V2",
                PromptReleaseStatus.PRODUCTION,
                "core",
                "CORE-APPROVAL",
                "CORE-EVAL",
                "rollback-version",
                "fallback",
                List.of("MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI"),
                "io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate");
    }
}
