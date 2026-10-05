package io.contexa.showcase.portal.live;

import io.contexa.showcase.portal.orchestrator.Measurements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Date;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.Map;

/**
 * The daily credit allotment of live runs (deck p.28, plan 1절): the monthly budget divided by the days of the month,
 * no carry-over. Today's spend is the model usage of today's live runs at the configured prices. At 80 percent the
 * operators are alerted once a day; at 100 percent new live runs stop and visitors are led to stored runs.
 */
public class LiveAllotment {

    private static final Logger log = LoggerFactory.getLogger(LiveAllotment.class);
    static final double ALERT_RATIO = 0.8;

    public record State(LocalDate day, double allotmentUsd, double spentUsd, boolean alerted, boolean exhausted) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final Measurements.Prices prices;
    private final double monthlyBudgetUsd;
    private final Clock clock;

    public LiveAllotment(NamedParameterJdbcTemplate jdbc, Measurements.Prices prices, double monthlyBudgetUsd,
                         Clock clock) {
        this.jdbc = jdbc;
        this.prices = prices;
        this.monthlyBudgetUsd = monthlyBudgetUsd;
        this.clock = clock;
    }

    public State state() {
        LocalDate day = LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
        double allotment = monthlyBudgetUsd / YearMonth.from(day).lengthOfMonth();
        Map<String, Object> usage = jdbc.queryForMap("""
                        select coalesce(sum(c.prompt_tokens) filter (where c.kind = 'CHAT'), 0) as chat_in,
                               coalesce(sum(c.completion_tokens) filter (where c.kind = 'CHAT'), 0) as chat_out,
                               coalesce(sum(c.prompt_tokens) filter (where c.kind = 'EMBEDDING'), 0) as embedding_in
                          from cost_ledger c join run r on r.run_id = c.run_id
                         where r.live_visitor_hash is not null and c.recorded_at >= :from and c.recorded_at < :to""",
                new MapSqlParameterSource("from", Timestamp.from(day.atStartOfDay().toInstant(ZoneOffset.UTC)))
                        .addValue("to", Timestamp.from(day.plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC))));
        double spent = (number(usage.get("chat_in")) * prices.chatInput()
                + number(usage.get("chat_out")) * prices.chatOutput()
                + number(usage.get("embedding_in")) * prices.embeddingInput()) / 1_000_000d;
        boolean alerted = spent >= allotment * ALERT_RATIO && alert(day, spent, allotment);
        return new State(day, allotment, spent, alerted, spent >= allotment);
    }

    /** Raises the 80 percent alert once a day; true when it has been raised today. */
    private boolean alert(LocalDate day, double spent, double allotment) {
        int inserted = jdbc.update("insert into live_allotment_alert (day) values (:day) on conflict do nothing",
                new MapSqlParameterSource("day", Date.valueOf(day)));
        if (inserted == 1) {
            log.error("Live allotment alert: day={}, spentUsd={}, allotmentUsd={}", day, spent, allotment);
        }
        return true;
    }

    private static double number(Object value) {
        return value instanceof Number number ? number.doubleValue() : 0d;
    }
}
