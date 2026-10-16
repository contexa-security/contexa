package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.MissingNode;
import io.contexa.showcase.portal.live.DecisionReadCache;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.io.IOException;
import java.time.Clock;
import java.util.List;
import java.util.Optional;

/**
 * W7-13: the sealed prompt of a run step as control D gives it (WorkloadAdmin.promptFacts), for the visitor views. The
 * step's request is its first decision, as the harness metrics read it (ReactivityService). Control D's answer is kept
 * for a short while like its decision records (DecisionReadCache): a seal with its inspection does not change any
 * more and is kept until evicted; a missing seal or one not yet inspected is read again after a second.
 */
public class SealedPrompts {

    private static final Logger log = LoggerFactory.getLogger(SealedPrompts.class);

    /** The run has no decision of control D at the step. */
    public static final String NO_STEP = "NO_STEP";
    /** Control D sealed no prompt for the step's decision. */
    public static final String NOT_SEALED = "NOT_SEALED";
    /** Control D could not be read. */
    public static final String NO_ENGINE = "NO_ENGINE";

    /**
     * A step's sealed prompt as control D gives it, or why there is none (the facts are null then).
     *
     * @param requestId the step's request; null when the step has no decision
     */
    public record Read(String requestId, JsonNode facts, String reason) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final DecisionReadCache cache;

    public SealedPrompts(NamedParameterJdbcTemplate jdbc, WorkloadAdmin admin, Clock clock) {
        this.jdbc = jdbc;
        this.cache = new DecisionReadCache(requestId -> admin.promptFacts(requestId).orElse(MissingNode.getInstance()),
                SealedPrompts::settled, clock);
    }

    public Read step(String runId, int stepNo) {
        List<String> requests = jdbc.queryForList("""
                        select request_id::text from run_decision
                         where run_id = :run and step_no = :step order by decided_at limit 1""",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo), String.class);
        if (requests.isEmpty()) {
            return new Read(null, null, NO_STEP);
        }
        try {
            return facts(requests.get(0)).map(found -> new Read(requests.get(0), found, null))
                    .orElseGet(() -> new Read(requests.get(0), null, NOT_SEALED));
        } catch (IOException e) {
            log.error("Sealed prompt unreadable from control D: runId={}, stepNo={}", runId, stepNo, e);
            return new Read(requests.get(0), null, NO_ENGINE);
        }
    }

    /** The sealed prompt of a decision; empty when control D sealed none. */
    public Optional<JsonNode> facts(String requestId) throws IOException {
        JsonNode facts = cache.get(requestId);
        return facts.isMissingNode() ? Optional.empty() : Optional.of(facts);
    }

    /** A seal with its inspection: control D's answer does not change any more. */
    static boolean settled(JsonNode facts) {
        return !facts.isMissingNode() && facts.path("inspection").isObject();
    }
}
