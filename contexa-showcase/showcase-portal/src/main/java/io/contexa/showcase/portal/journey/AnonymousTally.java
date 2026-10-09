package io.contexa.showcase.portal.journey;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Date;
import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.TreeMap;

/**
 * Anonymous daily counts (works 15 and 18, ADR-35): a day, a metric, an item, a value and a count. Nothing that names
 * or links a visitor is written; the caller counts a visitor once by the visitor's journey.
 */
public class AnonymousTally {

    public static final String QUIZ = "QUIZ";
    public static final String ACT_REACHED = "ACT_REACHED";

    /**
     * @param quiz       per question: answers counted right and in all
     * @param actReached per act: visitors who reached it
     */
    public record Summary(LocalDate from, LocalDate to, Map<String, Rate> quiz, Map<String, Long> actReached) {
    }

    public record Rate(long right, long total) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final Clock clock;

    public AnonymousTally(NamedParameterJdbcTemplate jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    public void count(String metric, String item, String value) {
        jdbc.update("""
                        insert into anonymous_tally (day, metric, item, value, count) values (:day, :metric, :item, :value, 1)
                        on conflict (day, metric, item, value) do update set count = anonymous_tally.count + 1""",
                new MapSqlParameterSource("day", Date.valueOf(today())).addValue("metric", metric)
                        .addValue("item", item).addValue("value", value));
    }

    /** The counts still kept, summed over their days. */
    public Summary summary() {
        Map<String, long[]> quiz = new TreeMap<>();
        Map<String, Long> acts = new TreeMap<>();
        LocalDate[] range = new LocalDate[2];
        jdbc.query("select day, metric, item, value, count from anonymous_tally", new MapSqlParameterSource(), rs -> {
            LocalDate day = rs.getDate(1).toLocalDate();
            range[0] = range[0] == null || day.isBefore(range[0]) ? day : range[0];
            range[1] = range[1] == null || day.isAfter(range[1]) ? day : range[1];
            long count = rs.getLong(5);
            if (QUIZ.equals(rs.getString(2))) {
                long[] rate = quiz.computeIfAbsent(rs.getString(3), ignored -> new long[2]);
                rate[1] += count;
                if ("RIGHT".equals(rs.getString(4))) {
                    rate[0] += count;
                }
            } else {
                acts.merge(rs.getString(3), count, Long::sum);
            }
        });
        Map<String, Rate> rates = new TreeMap<>();
        quiz.forEach((question, rate) -> rates.put(question, new Rate(rate[0], rate[1])));
        return new Summary(range[0], range[1], rates, acts);
    }

    private LocalDate today() {
        return LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
    }
}
