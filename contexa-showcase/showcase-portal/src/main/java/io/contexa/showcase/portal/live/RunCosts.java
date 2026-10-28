package io.contexa.showcase.portal.live;

import io.contexa.showcase.portal.orchestrator.ModelPricing;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** What runs cost in dollars, from the cost ledger by each model's own price (the one rule of docs/agent AC-1). */
public final class RunCosts {

    private RunCosts() {
    }

    /** The cost of each of the runs; a run with no ledger row costs 0. */
    public static Map<String, Double> byRun(NamedParameterJdbcTemplate jdbc, ModelPricing pricing,
                                            Collection<String> runIds) {
        Map<String, Double> costs = new LinkedHashMap<>();
        runIds.forEach(runId -> costs.put(runId, 0d));
        if (runIds.isEmpty()) {
            return costs;
        }
        List<Map<String, Object>> rows = jdbc.queryForList("""
                        select run_id, kind, model, coalesce(sum(prompt_tokens), 0) as prompt_tokens,
                               coalesce(sum(cached_prompt_tokens), 0) as cached,
                               coalesce(sum(completion_tokens), 0) as completion
                          from cost_ledger where run_id in (:runs) group by run_id, kind, model""",
                new MapSqlParameterSource("runs", runIds));
        for (Map<String, Object> row : rows) {
            costs.merge((String) row.get("run_id"), pricing.usd((String) row.get("kind"), (String) row.get("model"),
                    ((Number) row.get("prompt_tokens")).longValue(), ((Number) row.get("cached")).longValue(),
                    ((Number) row.get("completion")).longValue()), Double::sum);
        }
        return costs;
    }

    /** The cost of the latest finished agent runs of visitors, newest first. */
    public static List<Double> latestVisitorAgentRuns(NamedParameterJdbcTemplate jdbc, ModelPricing pricing, int count) {
        List<String> runIds = jdbc.queryForList("""
                        select r.run_id from run r join run_agent_task t on t.run_id = r.run_id
                         where r.live_run and r.status in ('COMPLETED', 'CONFIRMING')
                         order by r.started_at desc limit :count""", new MapSqlParameterSource("count", count),
                String.class);
        Map<String, Double> costs = byRun(jdbc, pricing, runIds);
        return runIds.stream().map(costs::get).toList();
    }
}
