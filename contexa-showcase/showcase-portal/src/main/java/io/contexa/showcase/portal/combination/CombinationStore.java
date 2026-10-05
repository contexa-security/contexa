package io.contexa.showcase.portal.combination;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Combination records (portal V7); the primary key keeps one record per cell, catalog version and version key. A record
 * whose run has an unresolved engine decision (a technical failure, not the engine's judgement, plan section 2) is
 * never shown or reused; the next completed run of the cell takes its place (docs/showcase/계획대조-검수.md N-2).
 */
public class CombinationStore {

    /** A step of the record's run has an unresolved engine decision. */
    private static final String UNRESOLVED_RUN =
            "exists (select 1 from run_decision d where d.run_id = combination_record.run_id and d.unresolved)";

    public record RecordRow(String comboKey, int catalogVersion, String versionKey, String runId, String visitorHash,
                            Instant recordedAt) {
    }

    private final NamedParameterJdbcTemplate jdbc;

    public CombinationStore(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<RecordRow> find(String comboKey, String versionKey) {
        return jdbc.query("""
                        select combo_key, catalog_version, version_key, run_id, visitor_hash, recorded_at
                          from combination_record
                         where combo_key = :key and catalog_version = :catalog and version_key = :version"""
                        + " and not " + UNRESOLVED_RUN,
                new MapSqlParameterSource("key", comboKey).addValue("catalog", CombinationCatalog.VERSION)
                        .addValue("version", versionKey), (rs, n) -> row(rs)).stream().findFirst();
    }

    public List<RecordRow> forVersions(Collection<String> versionKeys) {
        if (versionKeys.isEmpty()) {
            return List.of();
        }
        return jdbc.query("""
                        select combo_key, catalog_version, version_key, run_id, visitor_hash, recorded_at
                          from combination_record
                         where catalog_version = :catalog and version_key in (:versions)"""
                        + " and not " + UNRESOLVED_RUN,
                new MapSqlParameterSource("catalog", CombinationCatalog.VERSION).addValue("versions", versionKeys),
                (rs, n) -> row(rs));
    }

    /**
     * Keeps the first resolved run of a cell; a later run of the same cell and versions is not stored, except that it
     * replaces a record whose run was unresolved.
     */
    public boolean save(String comboKey, String versionKey, String runId, String visitorHash) {
        return jdbc.update("""
                        insert into combination_record (combo_key, catalog_version, version_key, run_id, visitor_hash)
                        values (:key, :catalog, :version, :run, :visitor)
                        on conflict (combo_key, catalog_version, version_key) do update
                           set run_id = excluded.run_id, visitor_hash = excluded.visitor_hash, recorded_at = now()"""
                        + " where " + UNRESOLVED_RUN,
                new MapSqlParameterSource("key", comboKey).addValue("catalog", CombinationCatalog.VERSION)
                        .addValue("version", versionKey).addValue("run", runId).addValue("visitor", visitorHash)) == 1;
    }

    /** Whether a step of the run has an unresolved engine decision. */
    public boolean unresolved(String runId) {
        Boolean unresolved = jdbc.queryForObject(
                "select exists (select 1 from run_decision where run_id = :run and unresolved)",
                new MapSqlParameterSource("run", runId), Boolean.class);
        return Boolean.TRUE.equals(unresolved);
    }

    private static RecordRow row(ResultSet rs) throws SQLException {
        Timestamp recorded = rs.getTimestamp(6);
        return new RecordRow(rs.getString(1), rs.getInt(2), rs.getString(3), rs.getString(4), rs.getString(5),
                recorded == null ? null : recorded.toInstant());
    }
}
