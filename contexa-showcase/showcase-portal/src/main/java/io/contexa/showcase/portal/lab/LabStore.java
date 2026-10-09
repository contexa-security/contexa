package io.contexa.showcase.portal.lab;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.io.IOException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * The lab's records (V14, docs/showcase/데모-재설계.md 5A.1, W2-2): the composition and the visitor's call of a lab run,
 * written once the run has its ID, and the visitor's assessment of a decision, once per step and only by the visitor
 * who started the run (V-7).
 */
public class LabStore {

    public static final Set<String> CALLS = Set.of("NORMAL", "ATTACK", "UNSURE");
    public static final Set<String> APPROACH_CALLS = Set.of("BLOCK", "PASS");
    public static final Set<String> VERDICTS = Set.of("SOUND", "UNSOUND", "UNSURE");
    /** Review R-16: a visitor may disagree with the designed case's ground truth itself. */
    public static final Set<String> REASONS = Set.of("MISSED_SIGNAL", "REASON_MISMATCH", "OVERBLOCK",
            "DISAGREE_TRUTH", "OTHER");

    public enum Assessed { STORED, NOT_OWNER, DUPLICATE, NO_STEP }

    /** The visitor's call before sending, kept with the time it was sent. */
    public record Prediction(String call, Map<String, String> approaches, Instant predictedAt) {
    }

    /**
     * A lab run of the visitor, newest first, for the comparison with the previous run (5A.1 ④).
     *
     * @param approaches what the visitor expected of each approach before sending (BLOCK or PASS), when said
     */
    public record RecentRun(String runId, String caseKey, boolean designed, List<String> changed,
                            Map<String, Object> conditions, Instant composedAt, String call,
                            Map<String, String> approaches) {
    }

    /**
     * Other visitors' assessments of the same request (5A.1 ⑤): runs of the same case definition under the same
     * measurement setting, the same step, completed and unforced; only assessments older than the delay count (the
     * benchmark's rule, J-5), and the asking visitor's own are left out.
     */
    public record Peers(long assessments, long assessors, Map<String, Long> verdicts, Map<String, Long> reasons,
                        int delayHours) {
    }

    private static final TypeReference<List<String>> STRINGS = new TypeReference<>() {
    };
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };
    private static final TypeReference<Map<String, String>> CALLS_BY_APPROACH = new TypeReference<>() {
    };

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper json;

    public LabStore(NamedParameterJdbcTemplate jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    public void ran(String runId, LabComposer.Composed composed, String caseKey, Instant composedAt, String visitor,
                    Prediction prediction) {
        jdbc.update("""
                        insert into lab_composition (run_id, case_key, designed, changed, conditions, composed_at)
                        values (:run, :case, :designed, cast(:changed as jsonb), cast(:conditions as jsonb), :at)
                        on conflict (run_id) do nothing""",
                new MapSqlParameterSource("run", runId).addValue("case", caseKey)
                        .addValue("designed", composed.designed()).addValue("changed", write(composed.changed()))
                        .addValue("conditions", write(composed.conditions()))
                        .addValue("at", Timestamp.from(composedAt)));
        if (prediction != null) {
            jdbc.update("""
                            insert into visitor_prediction (run_id, visitor_hash, call, approaches, predicted_at)
                            values (:run, :visitor, :call, cast(:approaches as jsonb), :at)
                            on conflict (run_id) do nothing""",
                    new MapSqlParameterSource("run", runId).addValue("visitor", visitor)
                            .addValue("call", prediction.call()).addValue("approaches", write(prediction.approaches()))
                            .addValue("at", Timestamp.from(prediction.predictedAt())));
        }
    }

    public Assessed assess(String runId, int stepNo, String visitor, String verdict, List<String> reasons) {
        List<String> owners = jdbc.queryForList("""
                        select r.live_visitor_hash from run r
                         where r.run_id = :run
                           and exists (select 1 from run_decision d where d.run_id = r.run_id and d.step_no = :step)""",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo), String.class);
        if (owners.isEmpty()) {
            return Assessed.NO_STEP;
        }
        if (visitor == null || !visitor.equals(owners.get(0))) {
            return Assessed.NOT_OWNER;
        }
        try {
            jdbc.update("""
                            insert into visitor_assessment (run_id, step_no, visitor_hash, verdict, reasons)
                            values (:run, :step, :visitor, :verdict, cast(:reasons as jsonb))""",
                    new MapSqlParameterSource("run", runId).addValue("step", stepNo).addValue("visitor", visitor)
                            .addValue("verdict", verdict).addValue("reasons", write(reasons)));
            return Assessed.STORED;
        } catch (DuplicateKeyException e) {
            return Assessed.DUPLICATE;
        }
    }

    /** The conditions a lab run was composed with, as stored; empty for a run that was not a lab run. */
    public Optional<Map<String, Object>> conditions(String runId) {
        return jdbc.query("select conditions::text from lab_composition where run_id = :run",
                new MapSqlParameterSource("run", runId), (rs, n) -> read(rs.getString(1), MAP)).stream().findFirst();
    }

    public List<RecentRun> recent(String visitor, int limit) {
        return jdbc.query("""
                        select c.run_id, c.case_key, c.designed, c.changed::text, c.conditions::text, c.composed_at,
                               p.call, coalesce(p.approaches::text, '{}')
                          from lab_composition c
                          join run r on r.run_id = c.run_id
                          left join visitor_prediction p on p.run_id = c.run_id
                         where r.live_visitor_hash = :visitor
                         order by c.composed_at desc limit :limit""",
                new MapSqlParameterSource("visitor", visitor).addValue("limit", limit),
                (rs, n) -> new RecentRun(rs.getString(1), rs.getString(2), rs.getBoolean(3),
                        read(rs.getString(4), STRINGS), read(rs.getString(5), MAP), rs.getTimestamp(6).toInstant(),
                        rs.getString(7), read(rs.getString(8), CALLS_BY_APPROACH)));
    }

    /**
     * Other visitors' assessments of the request {@code stepNo} of a run, as {@link Peers}; empty when the run is
     * unknown or recorded no definition hash or setting to compare with.
     *
     * @param visitor the asking visitor, whose own assessments are left out; null leaves none out
     */
    public Optional<Peers> peers(String runId, int stepNo, String visitor, Instant now, int delayHours) {
        List<Map<String, Object>> base = jdbc.queryForList(
                "select scenario_sha256, setting_hash from run where run_id = :run",
                new MapSqlParameterSource("run", runId));
        if (base.isEmpty() || base.get(0).get("scenario_sha256") == null || base.get(0).get("setting_hash") == null) {
            return Optional.empty();
        }
        Map<String, Long> verdicts = new TreeMap<>();
        Map<String, Long> reasons = new TreeMap<>();
        Set<String> assessors = new HashSet<>();
        long[] total = new long[1];
        jdbc.query("""
                        select a.verdict, a.reasons::text, coalesce(a.visitor_hash, a.run_id || ':' || a.step_no)
                          from visitor_assessment a join run r on r.run_id = a.run_id
                         where r.scenario_sha256 = :sha and r.setting_hash = :setting and a.step_no = :step
                           and r.status = 'COMPLETED' and r.forced_action is null and a.assessed_at < :cutoff
                           and (cast(:visitor as varchar) is null or a.visitor_hash is distinct from :visitor)""",
                new MapSqlParameterSource("sha", base.get(0).get("scenario_sha256"))
                        .addValue("setting", base.get(0).get("setting_hash")).addValue("step", stepNo)
                        .addValue("cutoff", Timestamp.from(now.minus(Duration.ofHours(delayHours))))
                        .addValue("visitor", visitor), rs -> {
                    total[0]++;
                    verdicts.merge(rs.getString(1), 1L, Long::sum);
                    read(rs.getString(2), STRINGS).forEach(reason -> reasons.merge(reason, 1L, Long::sum));
                    assessors.add(rs.getString(3));
                });
        return Optional.of(new Peers(total[0], assessors.size(), verdicts, reasons, delayHours));
    }

    private <T> T read(String text, TypeReference<T> type) {
        try {
            return json.readValue(text, type);
        } catch (IOException e) {
            throw new IllegalStateException("Unreadable lab record", e);
        }
    }

    private String write(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unwritable lab record", e);
        }
    }
}
