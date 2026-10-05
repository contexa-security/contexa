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

/** Combination records (portal V7); the primary key keeps one record per cell, catalog version and version key. */
public class CombinationStore {

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
                         where combo_key = :key and catalog_version = :catalog and version_key = :version""",
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
                         where catalog_version = :catalog and version_key in (:versions)""",
                new MapSqlParameterSource("catalog", CombinationCatalog.VERSION).addValue("versions", versionKeys),
                (rs, n) -> row(rs));
    }

    /** Keeps the first run of a cell; a later run of the same cell and versions is not stored. */
    public boolean save(String comboKey, String versionKey, String runId, String visitorHash) {
        return jdbc.update("""
                        insert into combination_record (combo_key, catalog_version, version_key, run_id, visitor_hash)
                        values (:key, :catalog, :version, :run, :visitor)
                        on conflict do nothing""",
                new MapSqlParameterSource("key", comboKey).addValue("catalog", CombinationCatalog.VERSION)
                        .addValue("version", versionKey).addValue("run", runId).addValue("visitor", visitorHash)) == 1;
    }

    private static RecordRow row(ResultSet rs) throws SQLException {
        Timestamp recorded = rs.getTimestamp(6);
        return new RecordRow(rs.getString(1), rs.getInt(2), rs.getString(3), rs.getString(4), rs.getString(5),
                recorded == null ? null : recorded.toInstant());
    }
}
