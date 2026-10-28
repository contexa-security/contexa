package io.contexa.showcase.portal.live;

import io.contexa.showcase.portal.orchestrator.Measurements;
import io.contexa.showcase.portal.orchestrator.ModelPricing;
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
import java.util.List;
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
    private final ModelPricing pricing;
    private final double monthlyBudgetUsd;
    private final Clock clock;

    /** docs/agent Agent중심-화면 AC-1: each model's tokens are counted by that model's own price. */
    public LiveAllotment(NamedParameterJdbcTemplate jdbc, ModelPricing pricing, double monthlyBudgetUsd, Clock clock) {
        this.jdbc = jdbc;
        this.pricing = pricing;
        this.monthlyBudgetUsd = monthlyBudgetUsd;
        this.clock = clock;
    }

    /** One price for every model, as before AC-1; kept for the tests that name their own price. */
    public LiveAllotment(NamedParameterJdbcTemplate jdbc, Measurements.Prices prices, double monthlyBudgetUsd,
                         Clock clock) {
        this(jdbc, ModelPricing.single(prices), monthlyBudgetUsd, clock);
    }

    public State state() {
        LocalDate day = LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
        double allotment = monthlyBudgetUsd / YearMonth.from(day).lengthOfMonth();
        // The model of each call is kept in the ledger, so each model is counted by its own price (AC-1).
        List<Map<String, Object>> usage = jdbc.queryForList("""
                        select c.kind, c.model, coalesce(sum(c.prompt_tokens), 0) as prompt_tokens,
                               coalesce(sum(c.cached_prompt_tokens), 0) as cached_prompt_tokens,
                               coalesce(sum(c.completion_tokens), 0) as completion_tokens
                          from cost_ledger c join run r on r.run_id = c.run_id
                         where r.live_run and c.recorded_at >= :from and c.recorded_at < :to
                         group by c.kind, c.model""",
                new MapSqlParameterSource("from", Timestamp.from(day.atStartOfDay().toInstant(ZoneOffset.UTC)))
                        .addValue("to", Timestamp.from(day.plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC))));
        double spent = 0d;
        for (Map<String, Object> row : usage) {
            spent += pricing.usd((String) row.get("kind"), (String) row.get("model"),
                    (long) number(row.get("prompt_tokens")), (long) number(row.get("cached_prompt_tokens")),
                    (long) number(row.get("completion_tokens")));
        }
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
