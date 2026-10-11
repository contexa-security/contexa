package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceJpaLedgerWriter;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import io.contexa.contexaiam.testsupport.PromptGovernanceJpaTestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PromptGovernanceReleaseLedgerIdentityTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 10, 10, 13, 0);

    private PostgresTestDatabase database;
    private PromptGovernanceJpaTestContext jpa;
    private JdbcTemplate jdbcTemplate;
    private PromptGovernanceJpaLedgerWriter writer;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbcTemplate = database.jdbcTemplate();
        PromptGovernanceTestSchema.apply(jdbcTemplate);
        jpa = PromptGovernanceJpaTestContext.open(database.dataSource());
        writer = jpa.ledgerWriter();
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
    void repeatedWritesOfOneReleaseIdentityKeepOneRowWithTemplateKeyAndContractVersion() {
        write("CORTEX_PROMPT_CONTRACT_V2", "PRODUCTION", "PQA_PROMPT_INTEGRATED_MANAGEMENT");
        write("CORTEX_PROMPT_CONTRACT_V2", "ACTIVE_FOR_SCOPE", "PQA_RUNTIME_GOVERNANCE");

        List<Map<String, Object>> rows = jdbcTemplate.queryForList("""
                select template_key, contract_version, release_status, registration_source
                  from prompt_governance_release_ledger
                """);

        assertThat(rows).hasSize(1);
        assertThat(rows.get(0))
                .containsEntry("template_key", "SecurityDecisionStandard")
                .containsEntry("contract_version", "CORTEX_PROMPT_CONTRACT_V2")
                .containsEntry("release_status", "ACTIVE_FOR_SCOPE")
                .containsEntry("registration_source", "PQA_RUNTIME_GOVERNANCE");
    }

    @Test
    void anotherContractVersionOfTheSamePromptVersionIsAnotherRow() {
        write("CORTEX_PROMPT_CONTRACT_V2", "PRODUCTION", "PQA_PROMPT_INTEGRATED_MANAGEMENT");
        write("CORTEX_PROMPT_CONTRACT_V3", "PRODUCTION", "PQA_PROMPT_INTEGRATED_MANAGEMENT");

        assertThat(jdbcTemplate.queryForList("""
                select contract_version
                  from prompt_governance_release_ledger
                 order by contract_version
                """, String.class)).containsExactly("CORTEX_PROMPT_CONTRACT_V2", "CORTEX_PROMPT_CONTRACT_V3");
    }

    @Test
    void anUpdateIsVisibleToJdbcInTheSameTransaction() {
        write("CORTEX_PROMPT_CONTRACT_V2", "PRODUCTION", "PQA_PROMPT_INTEGRATED_MANAGEMENT");

        String statusSeenByJdbc = jpa.transactionTemplate().execute(status -> {
            write("CORTEX_PROMPT_CONTRACT_V2", "ACTIVE_FOR_SCOPE", "PQA_RUNTIME_GOVERNANCE");
            String seen = jdbcTemplate.queryForObject(
                    "select release_status from prompt_governance_release_ledger", String.class);
            status.setRollbackOnly();
            return seen;
        });

        assertThat(statusSeenByJdbc).isEqualTo("ACTIVE_FOR_SCOPE");
        assertThat(jdbcTemplate.queryForObject(
                "select release_status from prompt_governance_release_ledger", String.class)).isEqualTo("PRODUCTION");
    }

    private void write(String contractVersion, String releaseStatus, String registrationSource) {
        writer.upsertReleaseApproval(
                "PLATFORM_GLOBAL",
                "cortex.security-decision",
                "SecurityDecisionStandard",
                "2026.04.04-e0.2",
                contractVersion,
                "PQA-RELEASE:PLATFORM_GLOBAL:cortex.security-decision:2026.04.04-e0.2",
                releaseStatus,
                "APPROVED",
                "PQA_PROMPT_GOVERNANCE",
                "admin",
                "Release gates were revalidated before production approval.",
                registrationSource,
                NOW);
    }
}
