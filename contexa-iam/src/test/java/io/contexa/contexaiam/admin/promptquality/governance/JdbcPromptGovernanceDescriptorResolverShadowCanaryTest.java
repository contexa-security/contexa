package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W6-9 (P6-CHANGE-6): a canary release runs only for its target tenants and resource families inside its share, and a
 * shadow release is offered as the candidate of the shadow runner but never chosen to decide.
 */
class JdbcPromptGovernanceDescriptorResolverShadowCanaryTest {

    private static final String KEY = "cortex.security-decision";
    private static final String TEMPLATE = "SecurityDecisionStandard";
    private static final String ACTIVE = "2026.10.16-v20.22";
    private static final String CANDIDATE = "2026.10.16-v19.18";

    private PostgresTestDatabase database;
    private JdbcTemplate jdbc;
    private PromptBundleSelector selector;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        PromptGovernanceTestSchema.apply(jdbc);
        selector = new JdbcPromptGovernanceDescriptorResolver(jdbc, new ObjectMapper(), 60_000L, 0L).registrySelector();
    }

    @AfterEach
    void tearDown() {
        if (database != null) {
            database.close();
        }
    }

    @Test
    void aCanaryRunsOnlyForItsTargetTenants() {
        registry(ACTIVE, "PRODUCTION", null, null, null);
        registry(CANDIDATE, "CANARY", 100, "tenant-a,tenant-b", null);

        assertThat(selector.select(context("tenant-a", "/api/projects/GB-500/exports"), "user-1"))
                .isEqualTo(new PromptBundleSelection(CANDIDATE, PromptBundleSelectionSource.CANARY));
        assertThat(selector.select(context("tenant-c", "/api/projects/GB-500/exports"), "user-1"))
                .isEqualTo(new PromptBundleSelection(ACTIVE, PromptBundleSelectionSource.REGISTRY));
    }

    @Test
    void aCanaryRunsOnlyForItsTargetResourceFamilies() {
        registry(ACTIVE, "PRODUCTION", null, null, null);
        registry(CANDIDATE, "CANARY", 100, null, "/api/documents/");

        assertThat(selector.select(context("tenant-a", "/api/documents/D-1"), "user-1").source())
                .isEqualTo(PromptBundleSelectionSource.CANARY);
        assertThat(selector.select(context("tenant-a", "/api/projects/GB-500/exports"), "user-1").source())
                .isEqualTo(PromptBundleSelectionSource.REGISTRY);
    }

    @Test
    void aShadowReleaseIsTheShadowCandidateAndNeverDecides() {
        registry(ACTIVE, "PRODUCTION", null, null, null);
        registry(CANDIDATE, "EVAL_ONLY", null, null, null);

        assertThat(selector.select(context("tenant-a", "/api/projects/GB-500/exports"), "user-1"))
                .isEqualTo(new PromptBundleSelection(ACTIVE, PromptBundleSelectionSource.REGISTRY));
        assertThat(selector.shadow(context("tenant-a", "/api/projects/GB-500/exports"), "user-1"))
                .isEqualTo(new PromptBundleSelection(CANDIDATE, PromptBundleSelectionSource.SHADOW));
    }

    @Test
    void withoutAShadowReleaseThereIsNoCandidate() {
        registry(ACTIVE, "PRODUCTION", null, null, null);

        assertThat(selector.shadow(context("tenant-a", "/api/projects/GB-500/exports"), "user-1"))
                .isEqualTo(PromptBundleSelection.none());
    }

    private static PromptGovernanceResolutionContext context(String tenant, String path) {
        return new PromptGovernanceResolutionContext("PLATFORM_GLOBAL", KEY, TEMPLATE, tenant, null, path, "POST",
                Map.of());
    }

    private void registry(String version, String status, Integer percent, String tenants, String families) {
        jdbc.update("""
                        insert into prompt_governance_registry (registry_scope, prompt_key, template_key, prompt_version,
                            contract_version, prompt_artifact_hash_sha256, release_status, owner_name,
                            template_class_name, registration_source, canary_percent, canary_tenants,
                            canary_resource_families)
                        values ('PLATFORM_GLOBAL', ?, ?, ?, 'CORTEX_PROMPT_CONTRACT_V3', 'hash', ?, 'pqa',
                            'SecurityDecisionStandardPromptTemplate', 'test', ?, ?, ?)""",
                KEY, TEMPLATE, version, status, percent, tenants, families);
    }
}
