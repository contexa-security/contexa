package io.contexa.contexaiam.admin.promptquality.governance;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** PV-23: an invalidation published by the service names the release's template key and contract version. */
class JdbcPromptGovernanceRuntimeCacheInvalidationServiceTest {

    private static final String PROMPT_KEY = "cortex.security-decision";
    private static final String TEMPLATE_KEY = "SecurityDecisionStandard";

    private PostgresTestDatabase database;
    private JdbcTemplate jdbcTemplate;
    private JdbcPromptGovernanceRuntimeCacheInvalidationService service;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbcTemplate = database.jdbcTemplate();
        PromptGovernanceTestSchema.apply(jdbcTemplate);
        service = new JdbcPromptGovernanceRuntimeCacheInvalidationService(jdbcTemplate);
    }

    @AfterEach
    void tearDown() {
        if (database != null) {
            database.close();
        }
    }

    @Test
    void aPublishedInvalidationNamesTheReleasesTemplateKeyAndContractVersion() {
        insertRelease("2026.10.12-v20", "CORTEX_PROMPT_CONTRACT_V3", "AVAILABLE", "2026-10-12 10:00:00");

        PromptGovernanceCacheInvalidation published =
                service.publish("platform_global", PROMPT_KEY, "2026.10.12-v20", "canary started", "operator");

        Map<String, Object> row = jdbcTemplate.queryForMap(
                "select registry_scope, template_key, contract_version from prompt_governance_runtime_cache_invalidation"
                        + " where event_id = ?", published.eventId());
        assertThat(row)
                .containsEntry("registry_scope", "PLATFORM_GLOBAL")
                .containsEntry("template_key", TEMPLATE_KEY)
                .containsEntry("contract_version", "CORTEX_PROMPT_CONTRACT_V3");
    }

    @Test
    void anInvalidationOfAVersionWithoutAReleaseNamesNoTemplateKey() {
        PromptGovernanceCacheInvalidation published =
                service.publish("PLATFORM_GLOBAL", PROMPT_KEY, "2099.01.01-v99", "unknown", "operator");

        Map<String, Object> row = jdbcTemplate.queryForMap(
                "select template_key, contract_version from prompt_governance_runtime_cache_invalidation"
                        + " where event_id = ?", published.eventId());
        assertThat(row.get("template_key")).isNull();
        assertThat(row.get("contract_version")).isNull();
    }

    /** The activation the service announces is the selection at the next poll, not after the cache expires. */
    @Test
    void anActivationAnnouncedByTheServiceIsSelectedAtTheNextPoll() {
        insertRelease("2026.10.11-v19.8", "CORTEX_PROMPT_CONTRACT_V2", "ACTIVE", "2026-10-11 10:00:00");
        insertRelease("2026.10.12-v20", "CORTEX_PROMPT_CONTRACT_V3", "AVAILABLE", "2026-10-12 10:00:00");
        PromptBundleSelector selector =
                new JdbcPromptGovernanceDescriptorResolver(jdbcTemplate, new ObjectMapper(), 60_000L, 0L).registrySelector();
        PromptGovernanceResolutionContext context = new PromptGovernanceResolutionContext("PLATFORM_GLOBAL", PROMPT_KEY,
                TEMPLATE_KEY, null, null, null, null, Map.of());
        assertThat(selector.select(context, "alice").bundleVersion()).isEqualTo("2026.10.11-v19.8");

        jdbcTemplate.update("update prompt_governance_registry set release_status = 'CANARY', canary_percent = 100,"
                + " updated_at = ? where prompt_version = ?", Timestamp.valueOf("2026-10-12 11:00:00"), "2026.10.12-v20");
        service.publish("PLATFORM_GLOBAL", PROMPT_KEY, "2026.10.12-v20", "canary started", "operator");

        assertThat(selector.select(context, "alice").bundleVersion()).isEqualTo("2026.10.12-v20");
    }

    private void insertRelease(String promptVersion, String contractVersion, String releaseStatus, String updatedAt) {
        jdbcTemplate.update(
                """
                        insert into prompt_governance_registry (
                            registry_scope, prompt_key, template_key, prompt_version,
                            contract_version, prompt_artifact_hash_sha256, release_status,
                            owner_name, release_approval_reference, evaluation_baseline_reference,
                            change_summary, template_class_name, registration_source, created_at, updated_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                "PLATFORM_GLOBAL", PROMPT_KEY, TEMPLATE_KEY, promptVersion, contractVersion, "hash-" + promptVersion,
                releaseStatus, "pqa", "approval", "evaluation", "test release",
                "io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate", "test",
                Timestamp.valueOf(updatedAt), Timestamp.valueOf(updatedAt));
    }
}
