package io.contexa.showcase.portal.orchestrator;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * P1-OPS-01 measurement over stored runs and templates: model calls and tokens per decision, analysis time, the
 * unresolved share (P1-BE-07), the engine's decision mix, and the cost of runs and template learning at the configured
 * prices (plan section 1: the monthly budget is set from this measurement). Runs that used a development-only
 * forced decision are left out.
 */
public class Measurements {

    /**
     * Prices in US dollars per one million tokens, with the date they were read from the provider's price list.
     */
    public record Prices(double chatInput, double chatOutput, double embeddingInput, String source) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final Prices prices;

    public Measurements(NamedParameterJdbcTemplate jdbc, Prices prices) {
        this.jdbc = jdbc;
        this.prices = prices;
    }

    public Map<String, Object> since(Instant since) {
        MapSqlParameterSource window = new MapSqlParameterSource("since", Timestamp.from(since));
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("since", since.toString());
        report.put("prices", prices);
        report.put("runs", jdbc.queryForList("""
                select scenario_key, status, count(*) as runs from run
                 where started_at >= :since and forced_action is null
                 group by scenario_key, status order by scenario_key, status""", window));
        report.put("decisions", jdbc.queryForMap("""
                select count(*) filter (where d.final_action is not null) as decisions,
                       count(*) filter (where d.unresolved) as unresolved,
                       count(*) filter (where d.applied = 'NONE') as without_record,
                       round(avg(d.model_calls) filter (where d.final_action is not null), 2) as avg_model_calls,
                       max(d.model_calls) as max_model_calls,
                       round(avg(d.prompt_tokens) filter (where d.final_action is not null)) as avg_prompt_tokens,
                       round(avg(d.completion_tokens) filter (where d.final_action is not null)) as avg_completion_tokens,
                       percentile_cont(0.5) within group (order by d.total_analysis_ms) as p50_analysis_ms,
                       percentile_cont(0.95) within group (order by d.total_analysis_ms) as p95_analysis_ms,
                       percentile_cont(0.5) within group (order by d.llm_latency_ms) as p50_llm_ms,
                       percentile_cont(0.95) within group (order by d.llm_latency_ms) as p95_llm_ms
                  from run_decision d join run r on r.run_id = d.run_id
                 where r.started_at >= :since and r.forced_action is null and d.applied <> 'NONE'""", window));
        report.put("engineActions", jdbc.queryForList("""
                select d.final_action, d.unresolved, count(*) as decisions
                  from run_decision d join run r on r.run_id = d.run_id
                 where r.started_at >= :since and r.forced_action is null and d.final_action is not null
                 group by d.final_action, d.unresolved order by d.final_action""", window));
        report.put("controlLatency", jdbc.queryForList("""
                select a.control,
                       percentile_cont(0.5) within group (order by a.elapsed_ms) as p50_ms,
                       percentile_cont(0.95) within group (order by a.elapsed_ms) as p95_ms,
                       count(*) as requests
                  from run_arm_result a join run r on r.run_id = a.run_id
                 where r.started_at >= :since and r.forced_action is null group by a.control order by a.control""", window));
        report.put("runCost", cost("""
                select c.kind, sum(c.prompt_tokens) as prompt_tokens, sum(c.completion_tokens) as completion_tokens,
                       count(distinct c.run_id) as subjects
                  from cost_ledger c join run r on r.run_id = c.run_id
                 where r.started_at >= :since and r.forced_action is null group by c.kind""", window));
        report.put("templateCost", cost("""
                select c.kind, sum(c.prompt_tokens) as prompt_tokens, sum(c.completion_tokens) as completion_tokens,
                       count(distinct c.template_id) as subjects
                  from cost_ledger c join engine_template t on t.template_id = c.template_id
                 where t.created_at >= :since group by c.kind""", window));
        return report;
    }

    private Map<String, Object> cost(String sql, MapSqlParameterSource window) {
        List<Map<String, Object>> rows = jdbc.queryForList(sql, window);
        BigDecimal total = BigDecimal.ZERO;
        long subjects = 0;
        for (Map<String, Object> row : rows) {
            long prompt = number(row.get("prompt_tokens"));
            long completion = number(row.get("completion_tokens"));
            double dollars = "EMBEDDING".equals(row.get("kind"))
                    ? prompt * prices.embeddingInput() / 1_000_000d
                    : prompt * prices.chatInput() / 1_000_000d + completion * prices.chatOutput() / 1_000_000d;
            row.put("usd", BigDecimal.valueOf(dollars).setScale(6, RoundingMode.HALF_UP));
            total = total.add(BigDecimal.valueOf(dollars));
            subjects = Math.max(subjects, number(row.get("subjects")));
        }
        Map<String, Object> cost = new LinkedHashMap<>();
        cost.put("byKind", rows);
        cost.put("totalUsd", total.setScale(6, RoundingMode.HALF_UP));
        cost.put("subjects", subjects);
        cost.put("usdPerSubject", subjects == 0 ? BigDecimal.ZERO
                : total.divide(BigDecimal.valueOf(subjects), 6, RoundingMode.HALF_UP));
        return cost;
    }

    private static long number(Object value) {
        return value instanceof Number number ? number.longValue() : 0L;
    }
}
