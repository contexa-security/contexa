package io.contexa.showcase.portal.live;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

/**
 * Watches the cost gate for abuse (deck p.37, P5-SEC-07): counts every outcome since start and the refusals of the
 * current clock hour by reason, and writes one error log in an hour whose refusals reach the alert level, so a burst of
 * refused visitors (a bot, a spent allotment, a full house) reaches the operator. Counts stay in memory; the daily
 * allotment alert is kept in the database by {@link LiveAllotment}. It also counts finished live runs and those whose
 * engine decision stayed unresolved (a technical failure such as the model provider's rate limit, plan section 2 gate
 * of 2%), and writes one error log in an hour whose unresolved runs reach {@link #UNRESOLVED_ALERT_RUNS} or exceed 2% of
 * at least {@link #UNRESOLVED_RATE_MIN_RUNS} finished runs (docs/showcase/계획대조-검수.md N-1).
 */
public class LiveGateWatch {

    private static final Logger log = LoggerFactory.getLogger(LiveGateWatch.class);

    public static final String STARTED = "STARTED";
    public static final String RESUMED = "RESUMED";

    static final int UNRESOLVED_ALERT_RUNS = 5;
    static final int UNRESOLVED_RATE_MIN_RUNS = 20;

    /**
     * @param outcomes             every outcome since start: STARTED, RESUMED and each refusal reason
     * @param refusalsThisHour     refusals by reason in the clock hour starting at {@code hourStart}
     * @param finishedThisHour     live runs that finished in that hour
     * @param unresolvedThisHour   of those, runs with an unresolved engine decision
     */
    public record Status(Instant since, Map<String, Long> outcomes, Instant hourStart, Map<String, Long> refusalsThisHour,
                         long refusalsInHour, int alertPerHour, boolean alertedThisHour, long finishedThisHour,
                         long unresolvedThisHour, boolean unresolvedAlertedThisHour) {
    }

    private final int alertPerHour;
    private final Clock clock;
    private final Instant since;
    private final Map<String, Long> outcomes = new TreeMap<>();
    private final Map<String, Long> refusalsThisHour = new TreeMap<>();
    private Instant hourStart;
    private boolean alertedThisHour;
    private long finishedThisHour;
    private long unresolvedThisHour;
    private boolean unresolvedAlertedThisHour;

    public LiveGateWatch(int alertPerHour, Clock clock) {
        if (alertPerHour < 1) {
            throw new IllegalArgumentException("The refusal alert level must be at least 1 per hour");
        }
        this.alertPerHour = alertPerHour;
        this.clock = clock;
        this.since = clock.instant();
        this.hourStart = since.truncatedTo(ChronoUnit.HOURS);
    }

    public synchronized void passed(String outcome) {
        outcomes.merge(outcome, 1L, Long::sum);
    }

    public synchronized void refused(String reason) {
        outcomes.merge(reason, 1L, Long::sum);
        roll();
        refusalsThisHour.merge(reason, 1L, Long::sum);
        long total = refusalsInHour();
        if (!alertedThisHour && total >= alertPerHour) {
            alertedThisHour = true;
            log.error("Live gate refused {} new runs in the hour from {} (alert level {}): {}", total, hourStart,
                    alertPerHour, new TreeMap<>(refusalsThisHour));
        }
    }

    /** A live run finished; {@code unresolved} when a step's engine decision stayed unresolved. */
    public synchronized void finished(boolean unresolved) {
        roll();
        finishedThisHour++;
        if (unresolved) {
            unresolvedThisHour++;
            outcomes.merge("UNRESOLVED_RUN", 1L, Long::sum);
        }
        boolean many = unresolvedThisHour >= UNRESOLVED_ALERT_RUNS;
        boolean rate = finishedThisHour >= UNRESOLVED_RATE_MIN_RUNS && unresolvedThisHour * 50 > finishedThisHour;
        if (unresolved && !unresolvedAlertedThisHour && (many || rate)) {
            unresolvedAlertedThisHour = true;
            log.error("Live runs without an engine decision: {} of {} in the hour from {} (model rate limit or outage; "
                    + "lower showcase.live.starts-per-minute or raise the provider limit)", unresolvedThisHour,
                    finishedThisHour, hourStart);
        }
    }

    public synchronized Status status() {
        roll();
        return new Status(since, Collections.unmodifiableMap(new TreeMap<>(outcomes)), hourStart,
                Collections.unmodifiableMap(new TreeMap<>(refusalsThisHour)), refusalsInHour(), alertPerHour,
                alertedThisHour, finishedThisHour, unresolvedThisHour, unresolvedAlertedThisHour);
    }

    private void roll() {
        Instant hour = clock.instant().truncatedTo(ChronoUnit.HOURS);
        if (!hour.equals(hourStart)) {
            hourStart = hour;
            refusalsThisHour.clear();
            alertedThisHour = false;
            finishedThisHour = 0;
            unresolvedThisHour = 0;
            unresolvedAlertedThisHour = false;
        }
    }

    private long refusalsInHour() {
        return refusalsThisHour.values().stream().mapToLong(Long::longValue).sum();
    }
}
