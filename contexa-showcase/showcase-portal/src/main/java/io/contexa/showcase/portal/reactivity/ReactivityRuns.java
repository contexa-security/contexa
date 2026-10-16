package io.contexa.showcase.portal.reactivity;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

/**
 * W6-1 (P6-CHANGE-2): the harness runs of the reactivity metrics (plan 8.4 to 8.7): the batch a run belongs to, the
 * kind of run and its variant label, so a metric reads the runs of one batch (table reactivity_run, V24).
 */
public class ReactivityRuns {

    /** A case as designed, one lab condition changed, a case-definition variant, an injection. */
    public enum Kind { BASE, LAB, VARIANT, INJECTION }

    /** One harness run: the case or variant key it ran, and when it was recorded. */
    public record Entry(String runId, String batchId, Kind kind, String label, String caseKey, Instant recordedAt) {
    }

    private final NamedParameterJdbcTemplate jdbc;

    public ReactivityRuns(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void record(String runId, String batchId, Kind kind, String label, String caseKey, Instant recordedAt) {
        jdbc.update("insert into reactivity_run (run_id, batch_id, kind, label, case_key, recorded_at) "
                        + "values (:run, :batch, :kind, :label, :case, :at)",
                new MapSqlParameterSource("run", runId).addValue("batch", batchId).addValue("kind", kind.name())
                        .addValue("label", label).addValue("case", caseKey)
                        .addValue("at", Timestamp.from(recordedAt)));
    }

    /** The runs of a batch in the order they were recorded. */
    public List<Entry> batch(String batchId) {
        return jdbc.query("select run_id, batch_id, kind, label, case_key, recorded_at from reactivity_run "
                        + "where batch_id = :batch order by recorded_at, run_id",
                new MapSqlParameterSource("batch", batchId),
                (rs, row) -> new Entry(rs.getString(1), rs.getString(2), Kind.valueOf(rs.getString(3)),
                        rs.getString(4), rs.getString(5), rs.getTimestamp(6).toInstant()));
    }
}
