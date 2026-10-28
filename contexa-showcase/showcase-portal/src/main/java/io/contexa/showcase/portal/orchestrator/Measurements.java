package io.contexa.showcase.portal.orchestrator;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
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
    private final ModelPricing pricing;

    /** docs/agent Agent중심-화면 AC-1: the cost report counts each model by its own price. */
    public Measurements(NamedParameterJdbcTemplate jdbc, ModelPricing pricing) {
        this.jdbc = jdbc;
        this.pricing = pricing;
    }

    /** One price for every model, as before AC-1; kept for the tests that name their own price. */
    public Measurements(NamedParameterJdbcTemplate jdbc, Prices prices) {
        this(jdbc, ModelPricing.single(prices));
    }

    public Map<String, Object> since(Instant since) {
        MapSqlParameterSource window = new MapSqlParameterSource("since", Timestamp.from(since));
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("since", since.toString());
        report.put("prices", pricing.describe());
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
                select c.kind, c.model, sum(c.prompt_tokens) as prompt_tokens,
                       coalesce(sum(c.cached_prompt_tokens), 0) as cached_prompt_tokens,
                       sum(c.completion_tokens) as completion_tokens, count(distinct c.run_id) as subjects
                  from cost_ledger c join run r on r.run_id = c.run_id
                 where r.started_at >= :since and r.forced_action is null group by c.kind, c.model""", window));
        report.put("templateCost", cost("""
                select c.kind, c.model, sum(c.prompt_tokens) as prompt_tokens,
                       coalesce(sum(c.cached_prompt_tokens), 0) as cached_prompt_tokens,
                       sum(c.completion_tokens) as completion_tokens, count(distinct c.template_id) as subjects
                  from cost_ledger c join engine_template t on t.template_id = c.template_id
                 where t.created_at >= :since group by c.kind, c.model""", window));
        return report;
    }

    private Map<String, Object> cost(String sql, MapSqlParameterSource window) {
        List<Map<String, Object>> modelRows = jdbc.queryForList(sql, window);
        BigDecimal total = BigDecimal.ZERO;
        long subjects = 0;
        // Priced by each model's own price, then shown per kind as the report always did.
        Map<String, Map<String, Object>> byKind = new LinkedHashMap<>();
        for (Map<String, Object> row : modelRows) {
            long prompt = number(row.get("prompt_tokens"));
            long cached = number(row.get("cached_prompt_tokens"));
            long completion = number(row.get("completion_tokens"));
            String kind = String.valueOf(row.get("kind"));
            double dollars = pricing.usd(kind, (String) row.get("model"), prompt, cached, completion);
            total = total.add(BigDecimal.valueOf(dollars));
            subjects = Math.max(subjects, number(row.get("subjects")));
            Map<String, Object> kindRow = byKind.computeIfAbsent(kind, key -> {
                Map<String, Object> created = new LinkedHashMap<>();
                created.put("kind", key);
                created.put("prompt_tokens", 0L);
                created.put("cached_prompt_tokens", 0L);
                created.put("completion_tokens", 0L);
                created.put("subjects", 0L);
                created.put("usd", BigDecimal.ZERO);
                return created;
            });
            kindRow.put("prompt_tokens", number(kindRow.get("prompt_tokens")) + prompt);
            kindRow.put("cached_prompt_tokens", number(kindRow.get("cached_prompt_tokens")) + cached);
            kindRow.put("completion_tokens", number(kindRow.get("completion_tokens")) + completion);
            kindRow.put("subjects", Math.max(number(kindRow.get("subjects")), number(row.get("subjects"))));
            kindRow.put("usd", ((BigDecimal) kindRow.get("usd")).add(BigDecimal.valueOf(dollars)));
        }
        List<Map<String, Object>> rows = new ArrayList<>(byKind.values());
        for (Map<String, Object> kindRow : rows) {
            kindRow.put("usd", ((BigDecimal) kindRow.get("usd")).setScale(6, RoundingMode.HALF_UP));
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
