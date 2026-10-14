package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/** The release registry lookup on PostgreSQL, with the registry table as the OSS schema declares it. */
class JdbcPromptReleaseLookupTest {

    private PostgresTestDatabase database;
    private JdbcTemplate jdbc;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        for (String statement : InspectionSchema.statements()) {
            jdbc.execute(statement);
        }
        register("2026.07.30-v19", "928ec415", "approval-1");
        register("2026.10.11-v19.8", "b885cce7", null);
    }

    @AfterEach
    void tearDown() {
        database.close();
    }

    @Test
    void aReleaseIsFoundByItsIdentityWhateverReleaseCameAfterIt() {
        JdbcPromptReleaseLookup lookup = new JdbcPromptReleaseLookup(jdbc);

        PromptReleaseLookup.PromptRelease old = lookup.find("PLATFORM_GLOBAL", "cortex.security-decision",
                "SecurityDecisionStandard", "2026.07.30-v19").orElseThrow();
        assertThat(old.artifactHash()).isEqualTo("928ec415");
        assertThat(old.contractVersion()).isEqualTo("CORTEX_PROMPT_CONTRACT_V2");
        assertThat(old.approvalReference()).isEqualTo("approval-1");
        assertThat(lookup.find("PLATFORM_GLOBAL", "cortex.security-decision", "SecurityDecisionStandard",
                "2026.10.11-v19.8").orElseThrow().approvalReference()).isNull();
        assertThat(lookup.find("PLATFORM_GLOBAL", "cortex.security-decision", "OtherTemplate", "2026.07.30-v19"))
                .isEmpty();
        assertThat(lookup.find("TENANT", "cortex.security-decision", "SecurityDecisionStandard", "2026.07.30-v19"))
                .isEmpty();
    }

    private void register(String version, String hash, String approval) {
        jdbc.update("""
                insert into prompt_governance_registry (registry_scope, prompt_key, template_key, prompt_version,
                       contract_version, prompt_artifact_hash_sha256, release_status, owner_name,
                       release_approval_reference, template_class_name, registration_source)
                values ('PLATFORM_GLOBAL', 'cortex.security-decision', 'SecurityDecisionStandard', ?,
                        'CORTEX_PROMPT_CONTRACT_V2', ?, 'ACTIVE', 'contexa', ?, 'Template', 'BUILD')
                """, version, hash, approval);
    }
}
