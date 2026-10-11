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
import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import static org.assertj.core.api.Assertions.assertThat;

class JdbcPromptGovernanceDescriptorResolverTest {

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
        PromptGovernanceResolutionContext context = new PromptGovernanceResolutionContext(
                "PLATFORM_GLOBAL",
                fallback.promptKey(),
                fallback.templateKey(),
                "tenant-a",
                "resource-a",
                "/finance/reports",
                "GET",
                Map.of());

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
        jdbcTemplate.update(
                """
                        insert into prompt_governance_runtime_cache_invalidation (
                            event_id, registry_scope, prompt_key, template_key,
                            prompt_version, contract_version,
                            invalidation_reason, published_by, published_at, consumed
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                "event-base-version",
                "PLATFORM_GLOBAL",
                fallback.promptKey(),
                fallback.templateKey(),
                fallback.promptVersion(),
                fallback.contractVersion(),
                "test release",
                "test",
                Timestamp.valueOf("2026-04-27 10:05:00"),
                false);

        assertThat(resolver.resolve(fallback, context).supplementalMetadata())
                .containsEntry("promptArtifactHashSha256", "registry-artifact-hash-b");
    }

    @Test
    void activeReleaseForDifferentVersionCannotOverrideRuntimeDescriptor() {
        insertRegistryRelease("ACTIVE_FOR_SCOPE", "old-version", "old-artifact-hash");

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

        assertThat(resolution.descriptor()).isEqualTo(fallback);
        assertThat(resolution.supplementalMetadata())
                .containsEntry("promptGovernanceCacheState", "MISS");
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
                "cortex.security-decision",
                "SecurityDecisionStandard",
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
                "cortex.security-decision",
                "SecurityDecisionStandard",
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
