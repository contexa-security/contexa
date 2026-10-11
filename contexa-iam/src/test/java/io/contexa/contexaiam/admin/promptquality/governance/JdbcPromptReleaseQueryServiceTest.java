package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceJpaLedgerWriter;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import io.contexa.contexaiam.testsupport.PromptGovernanceJpaTestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JdbcPromptReleaseQueryServiceTest {

    private static final LocalDateTime T0 = LocalDateTime.of(2026, 10, 10, 9, 0);

    private PostgresTestDatabase database;
    private PromptGovernanceJpaTestContext jpa;
    private PromptGovernanceJpaLedgerWriter writer;
    private JdbcPromptReleaseQueryService service;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        PromptGovernanceTestSchema.apply(database.jdbcTemplate());
        jpa = PromptGovernanceJpaTestContext.open(database.dataSource());
        writer = jpa.ledgerWriter();
        service = new JdbcPromptReleaseQueryService(database.jdbcTemplate());
    }

    @AfterEach
    void tearDown() {
        if (jpa != null) {
            jpa.close();
        }
        if (database != null) {
            database.close();
        }
    }

    @Test
    void releaseRowCarriesTheLatestLedgerRollbackAndWorkflowRows() {
        registry("PLATFORM_GLOBAL", "2026.07.30-v19", "2026.07.26-v5", T0);
        approval("IMPORTED_DECLARATION", "PRODUCTION", T0.plusMinutes(1));
        approval("APPROVED", "ACTIVE_FOR_SCOPE", T0.plusMinutes(2));
        writer.upsertRollback("PLATFORM_GLOBAL", "cortex.security-decision", "2026.07.30-v19",
                "PQA-ROLLBACK:1", "2026.07.29-v18", "TARGET_DECLARED", "READY", "VERSION_ROLLBACK",
                "Rollback target is ready for this prompt release.", "admin", "PQA_PROMPT_INTEGRATED_MANAGEMENT",
                T0.plusMinutes(3));
        workflow("BLOCKED", "NO_ACTIVE_SCOPE_RULE", "{\"gateState\":\"NO_ACTIVE_SCOPE_RULE\"}", T0.plusMinutes(4));
        workflow("READY", "READY", null, T0.plusMinutes(5));

        List<JdbcPromptReleaseQueryService.PromptReleaseRow> rows = service.releases(null).releases();

        assertThat(rows).hasSize(1);
        JdbcPromptReleaseQueryService.PromptReleaseRow row = rows.get(0);
        assertThat(row.templateKey()).isEqualTo("SecurityDecisionStandard");
        assertThat(row.contractVersion()).isEqualTo("CORTEX_PROMPT_CONTRACT_V2");
        assertThat(row.releaseStatus()).isEqualTo("PRODUCTION");
        assertThat(row.bundleState()).isEqualTo("ACTIVE");
        assertThat(row.approvalState()).isEqualTo("APPROVED");
        assertThat(row.releaseLedgerStatus()).isEqualTo("ACTIVE_FOR_SCOPE");
        assertThat(row.rollbackTargetPromptVersion()).isEqualTo("2026.07.29-v18");
        assertThat(row.registryRollbackPromptVersion()).isEqualTo("2026.07.26-v5");
        assertThat(row.rollbackReadinessState()).isEqualTo("READY");
        assertThat(row.releaseWorkflowState()).isEqualTo("READY");
        assertThat(row.releaseWorkflowGateState()).isEqualTo("READY");
        assertThat(row.releaseWorkflowBlockers()).isNull();
        assertThat(row.updatedAt()).isEqualTo(T0);
    }

    @Test
    void versionWithoutLedgersFallsBackToTheRegistryRollbackVersionAndScopeFilters() {
        registry("PLATFORM_GLOBAL", "2026.07.30-v19", "2026.07.26-v5", T0);
        registry("TENANT_A", "2026.08.01-v20", "2026.07.30-v19", T0.plusMinutes(1));

        List<JdbcPromptReleaseQueryService.PromptReleaseRow> all = service.releases(null).releases();
        List<JdbcPromptReleaseQueryService.PromptReleaseRow> tenant = service.releases(" TENANT_A ").releases();

        assertThat(all).extracting(JdbcPromptReleaseQueryService.PromptReleaseRow::registryScope)
                .containsExactly("PLATFORM_GLOBAL", "TENANT_A");
        assertThat(tenant).hasSize(1);
        assertThat(tenant.get(0).promptVersion()).isEqualTo("2026.08.01-v20");
        assertThat(tenant.get(0).approvalState()).isNull();
        assertThat(tenant.get(0).rollbackState()).isNull();
        assertThat(tenant.get(0).rollbackTargetPromptVersion()).isEqualTo("2026.07.30-v19");
        assertThat(tenant.get(0).releaseWorkflowState()).isNull();
    }

    private void registry(String scope, String version, String rollbackVersion, LocalDateTime timestamp) {
        writer.upsertCandidateRegistry(scope, "cortex.security-decision", "SecurityDecisionStandard", version,
                "CORTEX_PROMPT_CONTRACT_V2", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "PRODUCTION", "contexa-cortex-core", "approval-" + version, "baseline-" + version, rollbackVersion,
                "summary", "SecurityDecisionStandardPromptTemplate", "STANDARD_TEMPLATE_BOOTSTRAP", "[]", timestamp);
    }

    private void approval(String approvalState, String releaseStatus, LocalDateTime timestamp) {
        writer.upsertReleaseApproval("PLATFORM_GLOBAL", "cortex.security-decision", "SecurityDecisionStandard",
                "2026.07.30-v19", "CORTEX_PROMPT_CONTRACT_V2", "approval-ref", releaseStatus, approvalState,
                "PQA_PROMPT_GOVERNANCE", "admin", "summary", "PQA_PROMPT_INTEGRATED_MANAGEMENT", timestamp);
    }

    private void workflow(String workflowState, String gateState, String blockersJson, LocalDateTime timestamp) {
        writer.recordWorkflow("PLATFORM_GLOBAL", "cortex.security-decision", "2026.07.30-v19", "PRODUCTION",
                "PRODUCTION", workflowState, gateState, "PQA_PROMPT_GOVERNANCE", "admin", "rationale", blockersJson,
                timestamp);
    }
}
