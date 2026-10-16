package io.contexa.contexaiam.admin.promptquality.governance;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * W7-14: the version screen lists the recorded rollback executions from or to a bundle of a scope, newest first, with
 * an emergency stop that waits for its approval; the executions of other bundles and scopes are not listed.
 */
class PromptBundleRollbackExecutionsTest {

    private static final String SCOPE = "PLATFORM_GLOBAL";
    private static final String KEY = "cortex.security-decision";
    private static final String FROM = SecurityDecisionPromptBundles.V20.version();
    private static final String TO = SecurityDecisionPromptBundles.DEFAULT.version();

    private PostgresTestDatabase database;
    private JdbcTemplate jdbc;
    private PromptBundleRollbackService service;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        PromptGovernanceTestSchema.apply(jdbc);
        service = new PromptBundleRollbackService(jdbc, PromptBundleCatalog.shared(),
                mock(PromptGovernanceRuntimeCacheInvalidationService.class), null, new ObjectMapper(),
                Clock.fixed(Instant.parse("2026-10-16T01:00:00Z"), ZoneOffset.UTC));
    }

    @AfterEach
    void tearDown() {
        if (database != null) {
            database.close();
        }
    }

    @Test
    void theExecutionsFromOrToTheBundleAreListedNewestFirst() {
        execution("RBX-1", SCOPE, FROM, TO, "EXECUTED", false, "2026-10-16 01:00:00");
        execution("RBX-2", SCOPE, TO, FROM, "AWAITING_APPROVAL", true, "2026-10-16 02:00:00");
        execution("RBX-3", SCOPE, "2026.10.15-v20.20", "2026.10.15-v19.17", "EXECUTED", false, "2026-10-16 03:00:00");
        execution("RBX-4", "TENANT_A", FROM, TO, "EXECUTED", false, "2026-10-16 04:00:00");

        List<PromptBundleRollbackService.Execution> executions = service.executions(SCOPE, KEY, FROM);

        assertThat(executions).extracting(PromptBundleRollbackService.Execution::executionKey)
                .containsExactly("RBX-2", "RBX-1");
        PromptBundleRollbackService.Execution stop = executions.get(0);
        assertThat(stop.status()).isEqualTo(PromptBundleRollbackService.AWAITING_APPROVAL);
        assertThat(stop.emergency()).isTrue();
        assertThat(stop.fromVersion()).isEqualTo(TO);
        assertThat(stop.toVersion()).isEqualTo(FROM);
        assertThat(stop.actor()).isEqualTo("operator-a");
        assertThat(stop.reason()).isEqualTo("reason RBX-2");
        assertThat(stop.executedAt()).isNotNull();
    }

    private void execution(String key, String scope, String from, String to, String status, boolean emergency,
                           String executedAt) {
        jdbc.update("insert into prompt_governance_rollback_execution (execution_key, registry_scope, prompt_key, "
                        + "from_version, to_version, actor, reason, emergency, status, conditions_json, executed_at) "
                        + "values (?, ?, ?, ?, ?, 'operator-a', ?, ?, ?, '{}', cast(? as timestamp))", key, scope, KEY,
                from, to, "reason " + key, emergency, status, executedAt);
    }
}
