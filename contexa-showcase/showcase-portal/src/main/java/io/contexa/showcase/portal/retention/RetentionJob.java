package io.contexa.showcase.portal.retention;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.combination.CombinationCatalog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Date;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Deletes what the retention periods say (plan section 1, docs/showcase/P5-설계.md section 6, approval Q-08,
 * docs/showcase/개인정보-데이터목록.md) and records how many rows each step deleted (P5-PRV-02). A visitor's hash
 * leaves every table when the visitor's 30 days are over; runs are kept as the operations record, with their live-run
 * flag but without the hash, for 13 months unless a recording or a combination record still shows them. Retired and
 * old draft recordings and retired or failed templates go after 90 days (docs/showcase/계획대조-검수.md N-7).
 */
public class RetentionJob {

    private static final Logger log = LoggerFactory.getLogger(RetentionJob.class);

    /** Retention periods; the values are the plan's. */
    /**
     * @param retiredMaterial retired or old draft recordings and retired or failed templates
     * @param runEvidence     runs no recording or combination record shows, and the model usage ledger (13 months)
     */
    public record Periods(Duration visitor, Duration dailyQuota, Duration allotmentAlert, Duration shareCard,
                          Duration supersededCombination, Duration retentionLog, Duration retiredMaterial,
                          Duration runEvidence) {

        public static Periods plan() {
            return new Periods(Duration.ofDays(30), Duration.ofDays(7), Duration.ofDays(90), Duration.ofDays(90),
                    Duration.ofDays(90), Duration.ofDays(400), Duration.ofDays(90), Duration.ofDays(396));
        }
    }

    public record Pass(Instant runAt, Map<String, Integer> deleted) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;
    private final Periods periods;
    private final Clock clock;

    public RetentionJob(NamedParameterJdbcTemplate jdbc, TransactionTemplate transactions, ObjectMapper json,
                        Periods periods, Clock clock) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.json = json;
        this.periods = periods;
        this.clock = clock;
    }

    /** One pass over every table; each step runs in its own transaction and a failed step does not stop the rest. */
    public synchronized Pass run() {
        Instant now = clock.instant();
        LocalDate today = LocalDate.ofInstant(now, ZoneOffset.UTC);
        Map<String, Integer> deleted = new LinkedHashMap<>();
        step(deleted, "visitors", () -> jdbc.update("delete from visitor where last_seen_at < :cutoff",
                before(now, periods.visitor())));
        step(deleted, "runVisitorHashes", () -> jdbc.update("""
                update run r set live_visitor_hash = null
                 where r.live_visitor_hash is not null
                   and not exists (select 1 from visitor v where v.visitor_hash = r.live_visitor_hash)""",
                new MapSqlParameterSource()));
        step(deleted, "combinationVisitorHashes", () -> jdbc.update("""
                update combination_record c set visitor_hash = null
                 where c.visitor_hash is not null
                   and not exists (select 1 from visitor v where v.visitor_hash = c.visitor_hash)""",
                new MapSqlParameterSource()));
        step(deleted, "dailyQuota", () -> jdbc.update("delete from live_quota where day < :day",
                new MapSqlParameterSource("day", Date.valueOf(today.minusDays(periods.dailyQuota().toDays())))));
        step(deleted, "allotmentAlerts", () -> jdbc.update("delete from live_allotment_alert where day < :day",
                new MapSqlParameterSource("day", Date.valueOf(today.minusDays(periods.allotmentAlert().toDays())))));
        step(deleted, "shareCards", () -> jdbc.update("delete from share_card where last_shared_at < :cutoff",
                before(now, periods.shareCard())));
        step(deleted, "supersededCombinations", () -> jdbc.update("""
                delete from combination_record c
                 where c.recorded_at < :cutoff
                   and (c.catalog_version <> :catalog
                        or exists (select 1 from combination_record n
                                    where n.combo_key = c.combo_key and n.catalog_version = c.catalog_version
                                      and n.version_key <> c.version_key and n.recorded_at > c.recorded_at))""",
                before(now, periods.supersededCombination()).addValue("catalog", CombinationCatalog.VERSION)));
        step(deleted, "retiredRecordings", () -> jdbc.update("""
                delete from replay_record
                 where (status = 'RETIRED' and retired_at < :cutoff)
                    or (status = 'DRAFT' and recorded_at < :cutoff)""", before(now, periods.retiredMaterial())));
        step(deleted, "oldRuns", () -> jdbc.update("""
                delete from run r
                 where coalesce(r.finished_at, r.started_at) < :cutoff and r.status <> 'RUNNING'
                   and not exists (select 1 from replay_record p where p.representative_run_id = r.run_id)
                   and not exists (select 1 from replay_run p where p.run_id = r.run_id)
                   and not exists (select 1 from combination_record c where c.run_id = r.run_id)""",
                before(now, periods.runEvidence())));
        step(deleted, "costLedger", () -> jdbc.update("delete from cost_ledger where recorded_at < :cutoff",
                before(now, periods.runEvidence())));
        step(deleted, "retiredTemplates", () -> jdbc.update("""
                delete from engine_template t
                 where ((t.status = 'RETIRED' and t.retired_at < :cutoff)
                        or (t.status = 'FAILED' and t.created_at < :cutoff))
                   and not exists (select 1 from run r where r.template_id = t.template_id)""",
                before(now, periods.retiredMaterial())));
        step(deleted, "retentionLog", () -> jdbc.update("delete from retention_log where run_at < :cutoff",
                before(now, periods.retentionLog())));
        try {
            jdbc.update("insert into retention_log (run_at, deleted) values (:at, cast(:deleted as jsonb))",
                    new MapSqlParameterSource("at", Timestamp.from(now))
                            .addValue("deleted", json.writeValueAsString(deleted)));
        } catch (JsonProcessingException | RuntimeException e) {
            log.error("Could not record the retention pass of {}", now, e);
        }
        return new Pass(now, deleted);
    }

    public List<Map<String, Object>> recent(int limit) {
        return jdbc.queryForList("select run_at, deleted::text as deleted from retention_log order by run_at desc "
                + "limit :limit", new MapSqlParameterSource("limit", limit));
    }

    private void step(Map<String, Integer> deleted, String name, Step step) {
        try {
            Integer rows = transactions.execute(status -> step.rows());
            deleted.put(name, rows == null ? 0 : rows);
        } catch (RuntimeException e) {
            deleted.put(name, -1);
            log.error("Retention step {} failed", name, e);
        }
    }

    private static MapSqlParameterSource before(Instant now, Duration period) {
        return new MapSqlParameterSource("cutoff", Timestamp.from(now.minus(period)));
    }

    @FunctionalInterface
    private interface Step {
        int rows();
    }
}
