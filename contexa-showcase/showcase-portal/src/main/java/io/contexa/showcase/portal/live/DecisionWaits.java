package io.contexa.showcase.portal.live;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * The "about s seconds" of the decision-waiting state (common-2 of docs/showcase/화면설계서-v2.md), read from records
 * so a screen never estimates by itself: the median time the engine took to decide the same case and step in the
 * current measurement, less the time this request has already waited.
 */
public class DecisionWaits {

    static final Duration CACHE = Duration.ofMinutes(1);

    /**
     * @param medianMs         the median analysis time of the engine's decisions of the same case and step in the
     *                         measurement
     * @param decisions        how many decisions the median is taken from
     * @param settingHash      the measurement setting the decisions belong to
     * @param waitedMs         how long this request has waited since the portal sent it to control D
     * @param remainingSeconds the median less the wait so far, rounded up; null once the wait passed the median
     */
    public record Wait(long medianMs, int decisions, String settingHash, long waitedMs, Integer remainingSeconds) {
    }

    private record Times(String settingHash, List<Long> sorted, Instant at) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final Supplier<Optional<String>> currentSetting;
    private final Clock clock;
    private final Map<String, Times> cache = new HashMap<>();

    /** @param currentSetting the measurement setting the benchmark shows by default */
    public DecisionWaits(NamedParameterJdbcTemplate jdbc, Supplier<Optional<String>> currentSetting, Clock clock) {
        this.jdbc = jdbc;
        this.currentSetting = currentSetting;
        this.clock = clock;
    }

    /** The wait of a request sent at {@code sentAt}; empty without a measured decision of the same case and step. */
    public synchronized Optional<Wait> estimate(String scenario, int stepNo, Instant sentAt) {
        Optional<String> setting = currentSetting.get();
        if (setting.isEmpty()) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        String key = setting.get() + "|" + scenario + "|" + stepNo;
        Times times = cache.get(key);
        if (times == null || !now.isBefore(times.at().plus(CACHE))) {
            times = new Times(setting.get(), jdbc.queryForList("""
                            select d.total_analysis_ms from run_decision d join run r on r.run_id = d.run_id
                             where r.protocol_id is not null and r.status = 'COMPLETED' and r.forced_action is null
                               and r.setting_hash = :setting and r.scenario_key = :scenario and d.step_no = :step
                               and d.final_action is not null and not coalesce(d.unresolved, false)
                               and d.total_analysis_ms is not null
                             order by d.total_analysis_ms""",
                    new MapSqlParameterSource("setting", setting.get()).addValue("scenario", scenario)
                            .addValue("step", stepNo), Long.class), now);
            cache.put(key, times);
        }
        if (times.sorted().isEmpty()) {
            return Optional.empty();
        }
        // The middle value as the benchmark takes it, the upper one of two middles.
        long median = times.sorted().get((int) Math.round(0.5 * (times.sorted().size() - 1)));
        long waited = Math.max(0, Duration.between(sentAt, now).toMillis());
        Integer remaining = waited >= median ? null : (int) ((median - waited + 999) / 1000);
        return Optional.of(new Wait(median, times.sorted().size(), times.settingHash(), waited, remaining));
    }
}
