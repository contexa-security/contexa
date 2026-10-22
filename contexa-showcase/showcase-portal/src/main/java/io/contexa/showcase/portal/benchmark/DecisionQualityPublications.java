package io.contexa.showcase.portal.benchmark;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

/**
 * BM-S8 of docs/showcase/벤치마크-구현계획.md: the decision quality of a measurement protocol an operator published for a
 * setting (G5 of the v21 plan: each decision's reason codes against the facts they cite), stored when published so a
 * visitor reads stored values and no visitor request reads control D. Republishing a setting replaces its row.
 */
public class DecisionQualityPublications {

    /** The protocol is not one of the portal's. */
    public static final String UNKNOWN_PROTOCOL = "UNKNOWN_PROTOCOL";
    /** The protocol has not finished, so its decisions are not all there. */
    public static final String PROTOCOL_UNFINISHED = "PROTOCOL_UNFINISHED";
    /** The protocol ran no run of the setting. */
    public static final String OTHER_SETTING = "OTHER_SETTING";

    private final NamedParameterJdbcTemplate jdbc;

    public DecisionQualityPublications(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Why the protocol cannot be published for the setting, or empty when it can. */
    public Optional<String> refusal(String setting, String protocol) {
        MapSqlParameterSource parameters = new MapSqlParameterSource("protocol", protocol).addValue("setting", setting);
        Boolean finished = jdbc.query("""
                        select finished_at is not null from measurement_protocol where protocol_id = :protocol""",
                parameters, rs -> rs.next() ? rs.getBoolean(1) : null);
        if (finished == null) {
            return Optional.of(UNKNOWN_PROTOCOL);
        }
        if (!finished) {
            return Optional.of(PROTOCOL_UNFINISHED);
        }
        Long runs = jdbc.queryForObject("""
                        select count(*) from run where protocol_id = :protocol and setting_hash = :setting""",
                parameters, Long.class);
        return runs == null || runs == 0 ? Optional.of(OTHER_SETTING) : Optional.empty();
    }

    /** Publishes the view of a setting, replacing the one published before. */
    public void publish(String setting, String protocol, String quality, Instant at) {
        jdbc.update("""
                        insert into decision_quality_publication (setting_hash, protocol_id, quality, published_at)
                        values (:setting, :protocol, cast(:quality as jsonb), :at)
                        on conflict (setting_hash) do update set protocol_id = excluded.protocol_id,
                            quality = excluded.quality, published_at = excluded.published_at""",
                new MapSqlParameterSource("setting", setting).addValue("protocol", protocol)
                        .addValue("quality", quality).addValue("at", Timestamp.from(at)));
    }

    /** The view published for the setting; empty before any. */
    public Optional<String> published(String setting) {
        return jdbc.queryForList("select quality::text from decision_quality_publication where setting_hash = :setting",
                new MapSqlParameterSource("setting", setting), String.class).stream().findFirst();
    }
}
