package io.contexa.showcase.portal.hook;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** The designated representative runs of the first screen and the stored facts their designation is checked on. */
public class HookStore {

    /** The two columns of the first screen, each replaying one case (decisions 2 and 14). */
    public enum Slot {
        ATTACKER("A3"), OWNER("A3T");

        private final String caseKey;

        Slot(String caseKey) {
            this.caseKey = caseKey;
        }

        public String caseKey() {
            return caseKey;
        }
    }

    public record Designated(String runId, Instant designatedAt) {
    }

    /**
     * @param firstTextAt when the first model call text of the run's engine decisions was kept; null without any
     */
    public record RunFacts(String runId, String scenarioKey, String status, String forcedAction, String protocolId,
                           Instant startedAt, Instant firstTextAt) {
    }

    private final NamedParameterJdbcTemplate jdbc;

    public HookStore(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Map<Slot, Designated> designated() {
        Map<Slot, Designated> designated = new EnumMap<>(Slot.class);
        jdbc.query("select slot, run_id, designated_at from hook_designation", rs -> {
            designated.put(Slot.valueOf(rs.getString(1)),
                    new Designated(rs.getString(2), rs.getTimestamp(3).toInstant()));
        });
        return designated;
    }

    public Optional<RunFacts> facts(String runId) {
        List<RunFacts> rows = jdbc.query("""
                        select r.run_id, r.scenario_key, r.status, r.forced_action, r.protocol_id, r.started_at,
                               (select min(e.captured_at) from run_model_exchange e
                                  join run_decision d on d.request_id = e.request_id
                                 where d.run_id = r.run_id)
                          from run r where r.run_id = :run""",
                new MapSqlParameterSource("run", runId),
                (rs, n) -> new RunFacts(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5), rs.getTimestamp(6).toInstant(), instant(rs.getTimestamp(7))));
        return rows.stream().findFirst();
    }

    /** The completed, unforced runs of a case in one measurement protocol, oldest first. */
    public List<String> measurementRuns(String protocolId, String caseKey) {
        return jdbc.queryForList("""
                        select run_id from run
                         where protocol_id = :protocol and scenario_key = :case and status = 'COMPLETED'
                           and forced_action is null
                         order by started_at, run_id""",
                new MapSqlParameterSource("protocol", protocolId).addValue("case", caseKey), String.class);
    }

    public void designate(Slot slot, String runId, Instant at) {
        jdbc.update("""
                        insert into hook_designation (slot, run_id, designated_at) values (:slot, :run, :at)
                        on conflict (slot) do update set run_id = excluded.run_id,
                            designated_at = excluded.designated_at""",
                new MapSqlParameterSource("slot", slot.name()).addValue("run", runId)
                        .addValue("at", Timestamp.from(at)));
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}
