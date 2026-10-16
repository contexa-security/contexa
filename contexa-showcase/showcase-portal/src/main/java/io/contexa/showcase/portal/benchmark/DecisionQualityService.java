package io.contexa.showcase.portal.benchmark;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * W6-2 (P6-CHANGE-3): the decision quality of a measurement protocol, from the same raw data as the benchmark (the
 * protocol's decisions and the case definitions they ran) and, for the reason codes, the latest inspection control D
 * gives for each sealed decision.
 */
public class DecisionQualityService {

    private final NamedParameterJdbcTemplate jdbc;
    private final WorkloadAdmin admin;
    private final ObjectMapper json;

    public DecisionQualityService(NamedParameterJdbcTemplate jdbc, WorkloadAdmin admin, ObjectMapper json) {
        this.jdbc = jdbc;
        this.admin = admin;
        this.json = json;
    }

    public DecisionQuality of(String protocolId) throws IOException {
        List<DecisionQuality.Decision> decisions = new ArrayList<>();
        jdbc.query("""
                        select d.request_id::text, r.scenario_key, d.step_no, d.final_action,
                               r.scenario_definition->'oracle'->'allowedEngineActions', r.forced_action is not null
                          from run_decision d join run r on r.run_id = d.run_id
                         where r.protocol_id = :protocol order by d.run_id, d.step_no""",
                new MapSqlParameterSource("protocol", protocolId), rs -> {
                    decisions.add(new DecisionQuality.Decision(rs.getString(1), rs.getString(2), rs.getInt(3),
                            rs.getString(4), allowed(rs.getString(5)), rs.getBoolean(6)));
                });
        Map<String, DecisionQuality.ReasonMatch> reasons = new HashMap<>();
        for (DecisionQuality.Decision decision : decisions) {
            if (decision.forced()) {
                continue;
            }
            Optional<JsonNode> facts = admin.promptFacts(decision.requestId());
            if (facts.isEmpty()) {
                continue;
            }
            for (JsonNode check : facts.get().path("inspection").path("checks")) {
                if ("REASON_MATCH".equals(check.path("code").asText())) {
                    reasons.put(decision.requestId(), new DecisionQuality.ReasonMatch(check.path("matched").asInt(),
                            check.path("mismatched").asInt()));
                }
            }
        }
        return DecisionQuality.of(decisions, reasons);
    }

    private List<String> allowed(String value) {
        if (value == null) {
            return null;
        }
        try {
            List<String> actions = new ArrayList<>();
            json.readTree(value).forEach(action -> actions.add(action.asText()));
            return List.copyOf(actions);
        } catch (IOException e) {
            throw new IllegalStateException("The case definition's allowed actions are unreadable: " + value, e);
        }
    }
}
