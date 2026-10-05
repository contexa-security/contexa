package io.contexa.showcase.workload.plain.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.work.BusinessRequest;
import io.contexa.showcase.business.work.WorkDatabase;
import io.contexa.showcase.workload.plain.rules.RuleDecision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.UUID;

/**
 * Stores every authorization decision of a plain control in {@code rule_decision_log}, with the facts the rules
 * looked up. A failed write is logged and does not change the decision.
 */
public class DecisionRecorder {

    private static final Logger log = LoggerFactory.getLogger(DecisionRecorder.class);

    private final WorkDatabase database;
    private final ObjectMapper json;
    private final Clock clock;

    public DecisionRecorder(WorkDatabase database, ObjectMapper json, Clock clock) {
        this.database = database;
        this.json = json;
        this.clock = clock;
    }

    public void record(BusinessRequest request, String operation, RuleDecision decision) {
        try {
            database.jdbc().update("""
                            insert into rule_decision_log (decision_id, run_id, request_id, control, username, operation,
                                                           rule_id, outcome, reason, facts, decided_at)
                            values (:id, :run, :request, :control, :user, :operation, :rule, :outcome, :reason,
                                    cast(:facts as jsonb), :at)""",
                    new MapSqlParameterSource("id", UUID.randomUUID()).addValue("run", request.runId())
                            .addValue("request", request.requestId()).addValue("control", request.control())
                            .addValue("user", request.username()).addValue("operation", operation)
                            .addValue("rule", decision.ruleId()).addValue("outcome", decision.allowed() ? "ALLOW" : "DENY")
                            .addValue("reason", decision.reason()).addValue("facts", json.writeValueAsString(decision.facts()))
                            .addValue("at", Timestamp.from(clock.instant())));
        } catch (JsonProcessingException | RuntimeException e) {
            log.error("Failed to record a rule decision: control={}, requestId={}, rule={}", request.control(),
                    request.requestId(), decision.ruleId(), e);
        }
    }
}
