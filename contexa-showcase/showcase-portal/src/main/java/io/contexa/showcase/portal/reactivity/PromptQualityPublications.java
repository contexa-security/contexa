package io.contexa.showcase.portal.reactivity;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * W7-13: the prompt quality an operator published for a measurement setting (table prompt_quality_publication, V25):
 * the harness batch and the measurement protocol it is counted from, with the view computed when it was published.
 * The harness metrics read control D for every step of the batch, so they are counted once, when published, and a
 * visitor reads the stored view.
 */
public class PromptQualityPublications {

    /** The setting is not a measurement setting hash. */
    public static final String UNKNOWN_SETTING = "UNKNOWN_SETTING";
    /** No measurement protocol has the ID. */
    public static final String UNKNOWN_PROTOCOL = "UNKNOWN_PROTOCOL";
    /** The protocol is still running: its figures are not final. */
    public static final String PROTOCOL_UNFINISHED = "PROTOCOL_UNFINISHED";
    /** The protocol has no run under the setting. */
    public static final String PROTOCOL_NOT_IN_SETTING = "PROTOCOL_NOT_IN_SETTING";
    /** No harness run was recorded under the batch. */
    public static final String UNKNOWN_BATCH = "UNKNOWN_BATCH";
    /** A completed run of the batch ran under another setting, or none ran under this one. */
    public static final String BATCH_NOT_IN_SETTING = "BATCH_NOT_IN_SETTING";
    /** N-PQ-1: a harness figure has no batch: neither its own nor the one batch for all was given. */
    public static final String MISSING_BATCH = "MISSING_BATCH";

    /** The reasons that are about the protocol, not a batch (N-PQ-1: they name no figure). */
    private static final Set<String> PROTOCOL_REASONS = Set.of(UNKNOWN_PROTOCOL, PROTOCOL_UNFINISHED,
            PROTOCOL_NOT_IN_SETTING);

    private final NamedParameterJdbcTemplate jdbc;

    public PromptQualityPublications(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Why the batch and the protocol cannot be published for the setting; empty when they can. */
    public Optional<String> refusal(String setting, String batch, String protocol) {
        MapSqlParameterSource params = new MapSqlParameterSource("setting", setting).addValue("batch", batch)
                .addValue("protocol", protocol);
        List<Map<String, Object>> protocols = jdbc.queryForList("""
                        select p.finished_at is not null as finished,
                               exists (select 1 from run r where r.protocol_id = p.protocol_id
                                          and r.setting_hash = :setting) as in_setting
                          from measurement_protocol p where p.protocol_id = :protocol""", params);
        if (protocols.isEmpty()) {
            return Optional.of(UNKNOWN_PROTOCOL);
        }
        if (!Boolean.TRUE.equals(protocols.get(0).get("finished"))) {
            return Optional.of(PROTOCOL_UNFINISHED);
        }
        if (!Boolean.TRUE.equals(protocols.get(0).get("in_setting"))) {
            return Optional.of(PROTOCOL_NOT_IN_SETTING);
        }
        Map<String, Object> runs = jdbc.queryForMap("""
                        select count(*) as recorded,
                               count(*) filter (where r.status = 'COMPLETED' and r.setting_hash = :setting) as here,
                               count(*) filter (where r.status = 'COMPLETED'
                                                  and r.setting_hash is distinct from :setting) as elsewhere
                          from reactivity_run b join run r on r.run_id = b.run_id
                         where b.batch_id = :batch""", params);
        if (((Number) runs.get("recorded")).longValue() == 0) {
            return Optional.of(UNKNOWN_BATCH);
        }
        if (((Number) runs.get("here")).longValue() == 0 || ((Number) runs.get("elsewhere")).longValue() > 0) {
            return Optional.of(BATCH_NOT_IN_SETTING);
        }
        return Optional.empty();
    }

    /** When the published data was complete: the later of the protocol's end and the batch's last record. */
    public Instant measuredAt(String batch, String protocol) {
        Timestamp at = jdbc.queryForObject("""
                        select greatest((select finished_at from measurement_protocol where protocol_id = :protocol),
                                        (select max(recorded_at) from reactivity_run where batch_id = :batch))""",
                new MapSqlParameterSource("batch", batch).addValue("protocol", protocol), Timestamp.class);
        return at == null ? null : at.toInstant();
    }

    /**
     * N-PQ-1: why a publication is refused, and the figure and the source (its batch, or the earlier measurement of
     * the comparison) it is about; both null for the protocol.
     */
    public record Refusal(String reason, String metric, String source) {
    }

    /**
     * N-PQ-1: why the batches and the protocol cannot be published for the setting, naming the figure whose batch is
     * refused (the protocol is checked with each batch); empty when they can.
     */
    public Optional<Refusal> refusal(String setting, PromptQualityView.Batches batches, String protocol) {
        for (Map.Entry<String, String> figure : batches.byMetric().entrySet()) {
            Optional<String> refused = refusal(setting, figure.getValue(), protocol);
            if (refused.isPresent()) {
                boolean ofProtocol = PROTOCOL_REASONS.contains(refused.get());
                return Optional.of(new Refusal(refused.get(), ofProtocol ? null : figure.getKey(),
                        ofProtocol ? null : figure.getValue()));
            }
        }
        return Optional.empty();
    }

    /** N-PQ-1: when the data was complete: the latest of the protocol's end and every batch's last record. */
    public Instant measuredAt(PromptQualityView.Batches batches, String protocol) {
        return batches.byMetric().values().stream().distinct().map(batch -> measuredAt(batch, protocol))
                .filter(Objects::nonNull).max(Comparator.naturalOrder()).orElse(null);
    }

    /** U6-4: why the earlier measurement of the comparison cannot be counted; empty when it can. */
    public Optional<Refusal> baselineRefusal(String protocol) {
        List<Boolean> finished = jdbc.queryForList("""
                        select finished_at is not null from measurement_protocol where protocol_id = :protocol""",
                new MapSqlParameterSource("protocol", protocol), Boolean.class);
        return baselineRefusal(protocol, finished.isEmpty() ? null : finished.get(0));
    }

    /** U6-4: an unknown (finished null) or unfinished earlier measurement is refused for the comparison. */
    static Optional<Refusal> baselineRefusal(String protocol, Boolean finished) {
        if (finished == null) {
            return Optional.of(new Refusal(UNKNOWN_PROTOCOL, "comparison", protocol));
        }
        return finished ? Optional.empty() : Optional.of(new Refusal(PROTOCOL_UNFINISHED, "comparison", protocol));
    }

    /** Publishes the view of a setting, replacing the one published before. */
    public void publish(String setting, String batch, String protocol, String quality, Instant at) {
        jdbc.update("""
                        insert into prompt_quality_publication (setting_hash, batch_id, protocol_id, quality,
                                                                published_at)
                        values (:setting, :batch, :protocol, cast(:quality as jsonb), :at)
                        on conflict (setting_hash) do update set batch_id = excluded.batch_id,
                            protocol_id = excluded.protocol_id, quality = excluded.quality,
                            published_at = excluded.published_at""",
                new MapSqlParameterSource("setting", setting).addValue("batch", batch).addValue("protocol", protocol)
                        .addValue("quality", quality).addValue("at", Timestamp.from(at)));
    }

    /**
     * The view published for a setting, or the latest one published when none is named; empty before any. U6-5: the
     * screen's read, without the raw data the record keeps (the database leaves it out, so it is not sent here).
     */
    public Optional<String> published(String setting) {
        return stored(setting, "(quality - 'raw')::text");
    }

    /** U6-5: the published record with its raw data, for the tab's raw data download; empty before any. */
    public Optional<String> publishedWithRaw(String setting) {
        return stored(setting, "quality::text");
    }

    /** The stored record of a setting (the latest when none is named) as the given column expression reads it. */
    private Optional<String> stored(String setting, String column) {
        String sql = "select " + column + " from prompt_quality_publication"
                + " where cast(:setting as varchar) is null or setting_hash = :setting"
                + " order by published_at desc limit 1";
        return jdbc.queryForList(sql, new MapSqlParameterSource("setting", setting), String.class).stream()
                .findFirst();
    }
}
