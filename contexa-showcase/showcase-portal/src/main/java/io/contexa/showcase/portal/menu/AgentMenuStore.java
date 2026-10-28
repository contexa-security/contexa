package io.contexa.showcase.portal.menu;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.math.BigDecimal;
import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

/**
 * docs/agent Agent중심-화면 AC-4a: what the agent menu keeps: for each combination the run that answers it, and one row
 * a day for the refresh job.
 */
public class AgentMenuStore {

    /**
     * The run that answers a combination, with the hash of the case definition it ran and when.
     *
     * @param choiceKey the delegation choice of the combination in one word; empty for a combination without one
     */
    public record Entry(String caseKey, String path, String choiceKey, String runId, String definitionSha256,
                        Instant ranAt) {
    }

    /** One day of the refresh job. */
    public record Job(LocalDate day, Instant startedAt, Instant finishedAt, int ran, int failed, int skipped,
                      double spentUsd, String stopped) {
    }

    private final NamedParameterJdbcTemplate jdbc;

    public AgentMenuStore(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Keeps the run as the answer of the combination, in place of the one before. */
    public void keep(String caseKey, String path, String choiceKey, String runId, String definitionSha256,
                     Instant ranAt) {
        jdbc.update("""
                        insert into agent_menu (case_key, path, choice_key, run_id, definition_sha, ran_at)
                        values (:case, :path, :choice, :run, :sha, :at)
                        on conflict (case_key, path, choice_key)
                        do update set run_id = :run, definition_sha = :sha, ran_at = :at""",
                new MapSqlParameterSource("case", caseKey).addValue("path", path).addValue("choice", choiceKey)
                        .addValue("run", runId).addValue("sha", definitionSha256).addValue("at", Timestamp.from(ranAt)));
    }

    /** Keeps the run as the answer of a combination without a choice. */
    public void keep(String caseKey, String path, String runId, String definitionSha256, Instant ranAt) {
        keep(caseKey, path, "", runId, definitionSha256, ranAt);
    }

    public Optional<Entry> find(String caseKey, String path, String choiceKey) {
        return jdbc.query("""
                        select case_key, path, choice_key, run_id, definition_sha, ran_at from agent_menu
                         where case_key = :case and path = :path and choice_key = :choice""",
                new MapSqlParameterSource("case", caseKey).addValue("path", path).addValue("choice", choiceKey),
                (rs, n) -> entry(rs)).stream().findFirst();
    }

    /** The answer of a combination without a choice. */
    public Optional<Entry> find(String caseKey, String path) {
        return find(caseKey, path, "");
    }

    public List<Entry> all() {
        return jdbc.query("""
                        select case_key, path, choice_key, run_id, definition_sha, ran_at from agent_menu
                         order by case_key, choice_key, path""", (rs, n) -> entry(rs));
    }

    private static Entry entry(ResultSet rs) throws SQLException {
        return new Entry(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5).trim(),
                rs.getTimestamp(6).toInstant());
    }

    /** Opens the day's row, or reopens it when the job runs again the same day. */
    public void startJob(LocalDate day, Instant at) {
        jdbc.update("""
                        insert into agent_menu_job (day, started_at) values (:day, :at)
                        on conflict (day) do update set started_at = :at, finished_at = null, ran = 0, failed = 0,
                                                        skipped = 0, spent_usd = 0, stopped = null""",
                new MapSqlParameterSource("day", Date.valueOf(day)).addValue("at", Timestamp.from(at)));
    }

    public void finishJob(LocalDate day, Instant at, int ran, int failed, int skipped, double spentUsd, String stopped) {
        jdbc.update("""
                        update agent_menu_job set finished_at = :at, ran = :ran, failed = :failed, skipped = :skipped,
                                                  spent_usd = :spent, stopped = :stopped
                         where day = :day""",
                new MapSqlParameterSource("day", Date.valueOf(day)).addValue("at", Timestamp.from(at))
                        .addValue("ran", ran).addValue("failed", failed).addValue("skipped", skipped)
                        .addValue("spent", BigDecimal.valueOf(spentUsd)).addValue("stopped", stopped));
    }

    /** The latest days of the job, newest first. */
    public List<Job> jobs(int limit) {
        return jdbc.query("""
                        select day, started_at, finished_at, ran, failed, skipped, spent_usd, stopped
                          from agent_menu_job order by day desc limit :limit""",
                new MapSqlParameterSource("limit", limit), (rs, n) -> new Job(rs.getDate(1).toLocalDate(),
                        rs.getTimestamp(2).toInstant(),
                        rs.getTimestamp(3) == null ? null : rs.getTimestamp(3).toInstant(), rs.getInt(4), rs.getInt(5),
                        rs.getInt(6), rs.getBigDecimal(7).doubleValue(), rs.getString(8)));
    }
}
