package io.contexa.showcase.portal.journey;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.TreeSet;

/** A visitor's place in the demo, kept by the visitor's hash only (docs/showcase/개인정보-데이터목록.md). */
public class JourneyStore {

    /**
     * @param differences  the numbers (1 to 6) of the differences the visitor has seen, in order
     * @param predictions  the visitor's calls before sending, by experience (E1, E2) and question
     * @param actsReached  the acts the visitor has reached, so each is counted once in the anonymous counts
     * @param quizAnswered whether the visitor's answers were counted once in the anonymous counts
     */
    public record State(String route, int act, String step, List<Integer> differences,
                        Map<String, Map<String, String>> predictions, List<Integer> actsReached,
                        boolean quizAnswered, Instant updatedAt) {
    }

    /** A visitor run, as the run table records it. */
    public record VisitorRun(String runId, String scenarioKey, String status, Instant startedAt, boolean lab) {
    }

    private static final TypeReference<List<Integer>> INTEGERS = new TypeReference<>() {
    };
    private static final TypeReference<Map<String, Map<String, String>>> PREDICTIONS = new TypeReference<>() {
    };

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper json;

    public JourneyStore(NamedParameterJdbcTemplate jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    public Optional<State> state(String visitor) {
        List<State> rows = jdbc.query("""
                        select route, act, step, differences::text, predictions::text, acts_reached::text,
                               quiz_answered, updated_at
                          from visitor_journey where visitor_hash = :visitor""",
                new MapSqlParameterSource("visitor", visitor),
                (rs, n) -> new State(rs.getString(1), rs.getInt(2), rs.getString(3),
                        read(rs.getString(4), INTEGERS), read(rs.getString(5), PREDICTIONS),
                        read(rs.getString(6), INTEGERS), rs.getBoolean(7), rs.getTimestamp(8).toInstant()));
        return rows.stream().findFirst();
    }

    public void save(String visitor, State state) {
        jdbc.update("""
                        insert into visitor_journey (visitor_hash, route, act, step, differences, predictions,
                                                     acts_reached, quiz_answered, updated_at)
                        values (:visitor, :route, :act, :step, cast(:differences as jsonb), cast(:predictions as jsonb),
                                cast(:acts as jsonb), :quiz, :at)
                        on conflict (visitor_hash) do update set route = excluded.route, act = excluded.act,
                            step = excluded.step, differences = excluded.differences,
                            predictions = excluded.predictions, acts_reached = excluded.acts_reached,
                            quiz_answered = excluded.quiz_answered, updated_at = excluded.updated_at""",
                new MapSqlParameterSource("visitor", visitor).addValue("route", state.route())
                        .addValue("act", state.act()).addValue("step", state.step())
                        .addValue("differences", write(List.copyOf(new TreeSet<>(state.differences()))))
                        .addValue("predictions", write(new TreeMap<>(state.predictions())))
                        .addValue("acts", write(List.copyOf(new TreeSet<>(state.actsReached()))))
                        .addValue("quiz", state.quizAnswered())
                        .addValue("at", Timestamp.from(state.updatedAt())));
    }

    /** The visitor's own runs, live and lab, oldest first. */
    public List<VisitorRun> runs(String visitor) {
        return jdbc.query("""
                        select r.run_id, r.scenario_key, r.status, r.started_at,
                               exists (select 1 from lab_composition l where l.run_id = r.run_id)
                          from run r where r.live_visitor_hash = :visitor and r.forced_action is null
                         order by r.started_at, r.run_id""",
                new MapSqlParameterSource("visitor", visitor),
                (rs, n) -> new VisitorRun(rs.getString(1), rs.getString(2), rs.getString(3),
                        rs.getTimestamp(4).toInstant(), rs.getBoolean(5)));
    }

    private <T> T read(String text, TypeReference<T> type) {
        try {
            return json.readValue(text, type);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unreadable journey record", e);
        }
    }

    private String write(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unwritable journey record", e);
        }
    }
}
