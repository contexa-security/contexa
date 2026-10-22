package io.contexa.showcase.portal.replay;

import io.contexa.showcase.portal.anatomy.SealedPromptViews;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * What each approach actually answered to the same request of a step (최종화면-구현계획 EV-1): the request line, when it
 * was sent, the HTTP status, how many items went out, how long the answer took and the start of the answer's body as
 * the run stored it. An approach that let an export through answered with the documents themselves, so the screen
 * shows a real answer, not a figure. Credentials in a body (session identifiers, tokens) are masked. Stored records
 * of the virtual company only; nothing is computed here.
 */
@RestController
public class RunResponsesController {

    /** A JSON value whose name says it carries a credential: a session, token, cookie, secret, password or CSRF value. */
    static final Pattern CREDENTIAL = Pattern.compile(
            "(\"[A-Za-z_]*(?i:session|token|cookie|secret|password|csrf)[A-Za-z_]*\"\\s*:\\s*)\"[^\"]*\"");
    private static final String MASKED = "\"<SESSION>\"";

    /**
     * One approach's answer.
     *
     * @param excerpt the start of the answer's body as stored (at most 2,000 characters), credentials masked
     */
    public record StepResponse(String control, String method, String path, Instant sentAt, Integer httpStatus,
                               int deliveredItems, Long elapsedMs, String excerpt) {
    }

    private final NamedParameterJdbcTemplate jdbc;

    public RunResponsesController(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/api/runs/{runId}/steps/{stepNo}/responses")
    public ResponseEntity<List<StepResponse>> responses(@PathVariable("runId") String runId,
                                                        @PathVariable("stepNo") int stepNo) {
        if (!RunStepController.RUN_ID.matcher(runId).matches() || stepNo < 1) {
            return ResponseEntity.notFound().build();
        }
        List<StepResponse> responses = jdbc.query("""
                        select control, method, path, sent_at, http_status, delivered_items, elapsed_ms,
                               response_excerpt
                          from run_arm_result
                         where run_id = :run and step_no = :step
                         order by control""",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo),
                (row, index) -> {
                    Timestamp sent = row.getTimestamp("sent_at");
                    Number elapsed = (Number) row.getObject("elapsed_ms");
                    return new StepResponse(row.getString("control"), row.getString("method"), row.getString("path"),
                            sent == null ? null : sent.toInstant(), (Integer) row.getObject("http_status"),
                            row.getInt("delivered_items"), elapsed == null ? null : elapsed.longValue(),
                            masked(row.getString("response_excerpt")));
                });
        return responses.isEmpty() ? ResponseEntity.notFound().build() : ResponseEntity.ok(responses);
    }

    /** A body with credentials masked: named credential values, then HTTP session identifiers as the anatomy masks them. */
    static String masked(String excerpt) {
        if (excerpt == null) {
            return null;
        }
        String named = CREDENTIAL.matcher(excerpt).replaceAll("$1" + Matcher.quoteReplacement(MASKED));
        return SealedPromptViews.masked(named);
    }
}
