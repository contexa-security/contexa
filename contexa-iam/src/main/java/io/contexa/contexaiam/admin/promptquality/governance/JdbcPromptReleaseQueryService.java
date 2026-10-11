package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;

/**
 * Reads the prompt versions of the registry with their latest release ledger, rollback ledger and release workflow
 * rows. Only the version management tables are read, so the result carries the basic release columns without the
 * enterprise runtime rule, policy and application ledgers. {@code bundleState} is the canonical state of the stored
 * release status (decision 1); a status of no known vocabulary has none.
 */
public class JdbcPromptReleaseQueryService {

    private static final String RELEASES_SQL = """
            select r.registry_scope,
                   r.prompt_key,
                   r.template_key,
                   r.prompt_version,
                   r.contract_version,
                   r.release_status,
                   r.prompt_artifact_hash_sha256,
                   r.rollback_prompt_version,
                   r.updated_at,
                   l.approval_state,
                   l.release_status as ledger_release_status,
                   coalesce(rb.rollback_target_prompt_version, r.rollback_prompt_version) as rollback_target_prompt_version,
                   rb.rollback_state,
                   rb.rollback_readiness_state,
                   rb.rollback_reference,
                   w.workflow_state,
                   w.gate_state,
                   w.blockers_json
              from prompt_governance_registry r
         left join lateral (
                   select approval_state, release_status
                     from prompt_governance_release_ledger
                    where registry_scope = r.registry_scope
                      and prompt_key = r.prompt_key
                      and template_key is not distinct from r.template_key
                      and prompt_version = r.prompt_version
                      and contract_version is not distinct from r.contract_version
                    order by updated_at desc
                    limit 1
                   ) l on true
         left join lateral (
                   select rollback_target_prompt_version, rollback_state, rollback_readiness_state, rollback_reference
                     from prompt_governance_rollback_ledger
                    where registry_scope = r.registry_scope
                      and prompt_key = r.prompt_key
                      and prompt_version = r.prompt_version
                    order by updated_at desc
                    limit 1
                   ) rb on true
         left join lateral (
                   select workflow_state, gate_state, blockers_json
                     from prompt_governance_release_workflow
                    where registry_scope = r.registry_scope
                      and prompt_key = r.prompt_key
                      and prompt_version = r.prompt_version
                    order by created_at desc, id desc
                    limit 1
                   ) w on true
            """;
    private static final String ORDER = " order by r.registry_scope, r.prompt_key, r.updated_at desc, r.prompt_version";

    private final JdbcTemplate jdbcTemplate;

    public JdbcPromptReleaseQueryService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    public PromptReleaseSnapshot releases(String registryScope) {
        List<PromptReleaseRow> rows = StringUtils.hasText(registryScope)
                ? jdbcTemplate.query(RELEASES_SQL + " where r.registry_scope = ?" + ORDER, this::mapRow, registryScope.trim())
                : jdbcTemplate.query(RELEASES_SQL + ORDER, this::mapRow);
        return new PromptReleaseSnapshot(rows);
    }

    private PromptReleaseRow mapRow(ResultSet rs, int rowNum) throws SQLException {
        Timestamp updatedAt = rs.getTimestamp("updated_at");
        return new PromptReleaseRow(
                rs.getString("registry_scope"),
                rs.getString("prompt_key"),
                rs.getString("template_key"),
                rs.getString("prompt_version"),
                rs.getString("contract_version"),
                rs.getString("release_status"),
                PromptBundleState.fromStoredValue(rs.getString("release_status")).map(Enum::name).orElse(null),
                rs.getString("prompt_artifact_hash_sha256"),
                rs.getString("approval_state"),
                rs.getString("ledger_release_status"),
                rs.getString("rollback_target_prompt_version"),
                rs.getString("rollback_prompt_version"),
                rs.getString("rollback_state"),
                rs.getString("rollback_readiness_state"),
                rs.getString("rollback_reference"),
                rs.getString("workflow_state"),
                rs.getString("gate_state"),
                rs.getString("blockers_json"),
                updatedAt == null ? null : updatedAt.toLocalDateTime());
    }

    public record PromptReleaseSnapshot(List<PromptReleaseRow> releases) {
    }

    public record PromptReleaseRow(
            String registryScope,
            String promptKey,
            String templateKey,
            String promptVersion,
            String contractVersion,
            String releaseStatus,
            String bundleState,
            String artifactHash,
            String approvalState,
            String releaseLedgerStatus,
            String rollbackTargetPromptVersion,
            String registryRollbackPromptVersion,
            String rollbackState,
            String rollbackReadinessState,
            String rollbackReference,
            String releaseWorkflowState,
            String releaseWorkflowGateState,
            String releaseWorkflowBlockers,
            LocalDateTime updatedAt) {
    }
}
