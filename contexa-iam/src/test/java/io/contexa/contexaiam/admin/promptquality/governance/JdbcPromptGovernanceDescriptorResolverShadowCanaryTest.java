package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRelease;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.IntStream;

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

    // ----- plan 3.4, 3.9: the versions of the database -----

    /** The canary rules run on versions named v2.0 as on bundles: its tenants, its addresses, its share. */
    @Test
    void aCanaryOfAVersionRunsForItsTenantsAndAddressesInsideItsShare() {
        registry("v1.0", "ACTIVE", null, null, null);
        registry("v2.0", "CANARY", 100, "tenant-a", "/api/documents/,DOC-7");

        assertThat(selector.select(context("tenant-a", "/api/documents/D-1"), "user-1"))
                .isEqualTo(new PromptBundleSelection("v2.0", PromptBundleSelectionSource.CANARY));
        assertThat(selector.select(new PromptGovernanceResolutionContext("PLATFORM_GLOBAL", KEY, TEMPLATE, "tenant-a",
                "DOC-7", "/api/other", "GET", Map.of()), "user-1").bundleVersion()).isEqualTo("v2.0");
        assertThat(selector.select(context("tenant-b", "/api/documents/D-1"), "user-1"))
                .isEqualTo(new PromptBundleSelection("v1.0", PromptBundleSelectionSource.REGISTRY));
        assertThat(selector.select(context("tenant-a", "/api/projects/P-1"), "user-1").bundleVersion())
                .isEqualTo("v1.0");
    }

    /** The same user always falls on the same side, on every server: the share is drawn by the hash of its key. */
    @Test
    void theSameUserAlwaysFallsOnTheSameSideOfTheCanary() {
        registry("v1.0", "ACTIVE", null, null, null);
        registry("v2.0", "CANARY", 25, null, null);
        PromptBundleSelector another = new JdbcPromptGovernanceDescriptorResolver(jdbc, new ObjectMapper(), 60_000L, 0L)
                .registrySelector();

        for (int user = 0; user < 200; user++) {
            String subject = "user-" + user;
            String first = selector.select(context("tenant-a", "/api/x"), subject).bundleVersion();
            assertThat(selector.select(context("tenant-a", "/api/y"), subject).bundleVersion()).isEqualTo(first);
            assertThat(another.select(context("tenant-a", "/api/x"), subject).bundleVersion()).isEqualTo(first);
        }
    }

    /** A share takes about that share of the users: 10, 25 and 50 percent of 2,000 users within 3 points. */
    @Test
    void aCanaryShareTakesThatShareOfTheUsers() {
        registry("v1.0", "ACTIVE", null, null, null);
        for (int percent : List.of(10, 25, 50)) {
            long inside = IntStream.range(0, 2_000)
                    .filter(user -> JdbcPromptGovernanceDescriptorResolver.insideShare(percent, "user-" + user))
                    .count();
            assertThat(inside).isBetween(20L * (percent - 3), 20L * (percent + 3));
        }
        assertThat(JdbcPromptGovernanceDescriptorResolver.insideShare(0, "user-1")).isFalse();
        assertThat(JdbcPromptGovernanceDescriptorResolver.insideShare(100, "user-1")).isTrue();
        assertThat(JdbcPromptGovernanceDescriptorResolver.insideShare(null, "user-1")).isTrue();
    }

    /** A request without a requester (a screen asking what the scope runs) is inside only a canary of the whole scope. */
    @Test
    void aRequestWithoutARequesterIsOutsideAPartialCanary() {
        registry("v1.0", "ACTIVE", null, null, null);
        registry("v2.0", "CANARY", 50, null, null);

        assertThat(selector.select(context(null, null), null).bundleVersion()).isEqualTo("v1.0");
        assertThat(selector.select(context(null, null), " ").bundleVersion()).isEqualTo("v1.0");
        jdbc.update("update ctxa_prompt_governance_registry set canary_percent = 100 where prompt_version = 'v2.0'");
        PromptBundleSelector fresh = new JdbcPromptGovernanceDescriptorResolver(jdbc, new ObjectMapper(), 60_000L, 0L)
                .registrySelector();
        assertThat(fresh.select(context(null, null), null).bundleVersion()).isEqualTo("v2.0");
    }

    /**
     * K45: a scope whose releases choose nothing for the request (a shadow alone, a canary the request falls outside of)
     * leaves the choice to the platform's label (plan 3.4: the label of the request's scope, else the platform's).
     */
    @Test
    void aScopeThatChoosesNothingLeavesTheChoiceToThePlatform() {
        registry("v1.0", "ACTIVE", null, null, null);
        scoped("TENANT_A", "v2.0", "SHADOW", null, null);
        scoped("TENANT_B", "v3.0", "CANARY", 100, "tenant-other");
        scoped("TENANT_C", "v4.0", "CANARY", 0, null);
        scoped("TENANT_D", "v5.0", "ACTIVE", null, null);

        assertThat(selector.select(scoped("TENANT_A"), "user-1"))
                .isEqualTo(new PromptBundleSelection("v1.0", PromptBundleSelectionSource.REGISTRY));
        assertThat(selector.select(scoped("TENANT_B"), "user-1").bundleVersion()).isEqualTo("v1.0");
        assertThat(selector.select(scoped("TENANT_C"), "user-1").bundleVersion()).isEqualTo("v1.0");
        // A scope with its own label keeps it.
        assertThat(selector.select(scoped("TENANT_D"), "user-1").bundleVersion()).isEqualTo("v5.0");
        // The scope's shadow is still the shadow of its requests.
        assertThat(selector.shadow(scoped("TENANT_A"), "user-1").bundleVersion()).isEqualTo("v2.0");
    }

    /** Plan 3.4: the shadow release's row sets its sample share and daily limit; a row without them sets none. */
    @Test
    void theShadowReleaseCarriesTheShareAndLimitItsRowSets() {
        registry("v1.0", "ACTIVE", null, null, null);
        registry("v2.0", "SHADOW", null, null, null);
        jdbc.update("update ctxa_prompt_governance_registry set shadow_sample_percent = 5, shadow_daily_limit = 200"
                + " where prompt_version = 'v2.0'");

        assertThat(selector.shadowRelease(context("tenant-a", "/api/x"), "user-1"))
                .isEqualTo(new PromptShadowRelease("v2.0", 5, 200));

        scoped("TENANT_A", "v3.0", "SHADOW", null, null);
        assertThat(selector.shadowRelease(scoped("TENANT_A"), "user-1"))
                .isEqualTo(new PromptShadowRelease("v3.0", null, null));
        assertThat(selector.shadowRelease(scoped("TENANT_Z"), "user-1").version()).isEqualTo("v2.0");
    }

    private static PromptGovernanceResolutionContext context(String tenant, String path) {
        return new PromptGovernanceResolutionContext("PLATFORM_GLOBAL", KEY, TEMPLATE, tenant, null, path, "POST",
                Map.of());
    }

    private static PromptGovernanceResolutionContext scoped(String scope) {
        return new PromptGovernanceResolutionContext(scope, KEY, TEMPLATE, scope.toLowerCase(Locale.ROOT),
                null, "/api/x", "POST", Map.of());
    }

    private void registry(String version, String status, Integer percent, String tenants, String families) {
        scoped("PLATFORM_GLOBAL", version, status, percent, tenants, families);
    }

    private void scoped(String scope, String version, String status, Integer percent, String tenants) {
        scoped(scope, version, status, percent, tenants, null);
    }

    private void scoped(String scope, String version, String status, Integer percent, String tenants, String families) {
        jdbc.update("""
                        insert into ctxa_prompt_governance_registry (registry_scope, prompt_key, template_key, prompt_version,
                            contract_version, prompt_artifact_hash_sha256, release_status, owner_name,
                            template_class_name, registration_source, canary_percent, canary_tenants,
                            canary_resource_families)
                        values (?, ?, ?, ?, 'CORTEX_PROMPT_CONTRACT_V3', 'hash', ?, 'pqa',
                            'SecurityDecisionStandardPromptTemplate', 'test', ?, ?, ?)""",
                scope, KEY, TEMPLATE, version, status, percent, tenants, families);
    }
}
