package io.contexa.contexaiam.admin.promptquality.official.persistence;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationPromptSignalWriter;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;

public final class JdbcOfficialVerificationPromptSignalWriter implements OfficialVerificationPromptSignalWriter {

    private static final String INSERT_SQL = """
            insert into official_prompt_signal_ledger (
                package_id, aggregate_run_id, metric_code, check_code,
                signal_key, prompt_location, section_name, label_name,
                value_preview, value_hash, line_number, signal_role, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

    private final JdbcTemplate jdbcTemplate;

    public JdbcOfficialVerificationPromptSignalWriter(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = Objects.requireNonNull(jdbcTemplate, "jdbcTemplate");
    }

    @Override
    public void insert(Command command) {
        jdbcTemplate.update(INSERT_SQL,
                command.packageId(), command.aggregateRunId(), command.metricCode(), command.checkCode(),
                command.signalKey(), command.promptLocation(), command.sectionName(), command.labelName(),
                command.valuePreview(), command.valueHash(), command.lineNumber(), command.signalRole(),
                Timestamp.from(Instant.now()));
    }
}
