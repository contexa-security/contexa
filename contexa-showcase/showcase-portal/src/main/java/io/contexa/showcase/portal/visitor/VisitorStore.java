package io.contexa.showcase.portal.visitor;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.LinkedHashMap;
import java.util.Map;

/** Visitors (by identifier hash only) and their one prediction per scene (P2-DB-01). */
public class VisitorStore {

    private final NamedParameterJdbcTemplate jdbc;

    public VisitorStore(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void touch(String visitorHash) {
        jdbc.update("""
                        insert into visitor (visitor_hash) values (:visitor)
                        on conflict (visitor_hash) do update set last_seen_at = now()""",
                new MapSqlParameterSource("visitor", visitorHash));
    }

    /** Records the prediction; false when the visitor already predicted this scene. */
    public boolean predict(String visitorHash, String sceneKey, String choice) {
        touch(visitorHash);
        return jdbc.update("""
                        insert into prediction (visitor_hash, scene_key, choice) values (:visitor, :scene, :choice)
                        on conflict (visitor_hash, scene_key) do nothing""",
                new MapSqlParameterSource("visitor", visitorHash).addValue("scene", sceneKey)
                        .addValue("choice", choice)) == 1;
    }

    public Map<String, String> predictions(String visitorHash) {
        Map<String, String> predictions = new LinkedHashMap<>();
        jdbc.query("select scene_key, choice from prediction where visitor_hash = :visitor order by created_at",
                new MapSqlParameterSource("visitor", visitorHash),
                rs -> {
                    predictions.put(rs.getString(1), rs.getString(2));
                });
        return predictions;
    }

    public Map<String, Long> tally(String sceneKey) {
        Map<String, Long> tally = new LinkedHashMap<>();
        tally.put("ALLOW", 0L);
        tally.put("BLOCK", 0L);
        jdbc.query("select choice, count(*) from prediction where scene_key = :scene group by choice",
                new MapSqlParameterSource("scene", sceneKey), rs -> {
                    tally.put(rs.getString(1), rs.getLong(2));
                });
        return tally;
    }
}
