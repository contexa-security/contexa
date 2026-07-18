package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptLineageWriter;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;

public final class JdbcOfficialVerificationPromptLineageWriter implements OfficialVerificationPromptLineageWriter {

    private static final String INSERT_SQL = """
            insert into official_prompt_generation_lineage (
                package_id, aggregate_run_id, prompt_hash, context_hash,
                system_prompt_hash, user_prompt_hash, raw_prompt_hash,
                raw_system_prompt_hash, raw_user_prompt_hash,
                prompt_budget_profile, compression_applied, transformation_mode,
                raw_truth_parity, raw_user_field_count, final_user_field_count,
                field_diff_count, field_loss_count, field_changed_count,
                field_added_count, compacted_marker_count, truncated_marker_count,
                lineage_summary_json, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?)
            """;

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationPromptLineageWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void insert(Command command) {
        jdbcTemplate.update(INSERT_SQL,
                command.packageId(), command.aggregateRunId(), command.promptHash(), command.contextHash(),
                command.systemPromptHash(), command.userPromptHash(), command.rawPromptHash(),
                command.rawSystemPromptHash(), command.rawUserPromptHash(), command.promptBudgetProfile(),
                command.compressionApplied(), command.transformationMode(), command.rawTruthParity(),
                command.rawUserFieldCount(), command.finalUserFieldCount(), command.fieldDiffCount(),
                command.fieldLossCount(), command.fieldChangedCount(), command.fieldAddedCount(),
                command.compactedMarkerCount(), command.truncatedMarkerCount(), command.lineageSummaryJson(),
                Timestamp.from(Instant.now()));
    }
}
