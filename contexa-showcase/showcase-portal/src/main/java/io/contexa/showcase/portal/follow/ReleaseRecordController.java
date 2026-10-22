package io.contexa.showcase.portal.follow;

import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

/**
 * The latest block that was actually released (최종화면-구현계획 FU-4): which run and step, the case, and whether the
 * block was a development-only forced decision. The screen reads the release itself (its steps, the engine's record
 * of the block, the request sent again and what was learned) from that step's stored anatomy. A forced block is named
 * as such, never passed off as the engine's own judgment.
 */
@RestController
public class ReleaseRecordController {

    /**
     * The latest released block.
     *
     * @param forcedAction the decision forced on control D for the run (development only), null for the engine's own
     */
    public record ReleaseRecord(String runId, int stepNo, String scenarioKey, String forcedAction,
                                Instant approvedAt) {
    }

    private final NamedParameterJdbcTemplate jdbc;

    public ReleaseRecordController(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/api/follow/release")
    public ResponseEntity<ReleaseRecord> latest() {
        List<ReleaseRecord> records = jdbc.query("""
                        select x.run_id, x.step_no, r.scenario_key, r.forced_action, x.approved_at
                          from run_release x join run r on r.run_id = x.run_id
                         where x.released and r.status = 'COMPLETED'
                         order by x.approved_at desc nulls last
                         limit 1""",
                new MapSqlParameterSource(),
                (row, index) -> {
                    Timestamp approved = row.getTimestamp("approved_at");
                    return new ReleaseRecord(row.getString("run_id"), row.getInt("step_no"),
                            row.getString("scenario_key"), row.getString("forced_action"),
                            approved == null ? null : approved.toInstant());
                });
        return records.isEmpty() ? ResponseEntity.notFound().build() : ResponseEntity.ok(records.get(0));
    }
}
