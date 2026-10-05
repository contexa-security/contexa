package io.contexa.showcase.business.company;

import java.time.LocalTime;

/**
 * Request time condition of the exploration grid (deck p.13). The deck names the four slots but not their
 * bounds; the bounds and representative times are recorded in ADR-19.
 */
public enum TimeSlot {

    DAWN(LocalTime.of(0, 0), LocalTime.of(3, 17)),
    MORNING(LocalTime.of(6, 0), LocalTime.of(9, 40)),
    AFTERNOON(LocalTime.of(12, 0), LocalTime.of(14, 20)),
    EVENING(LocalTime.of(18, 0), LocalTime.of(20, 30));

    private final LocalTime start;
    private final LocalTime representativeTime;

    TimeSlot(LocalTime start, LocalTime representativeTime) {
        this.start = start;
        this.representativeTime = representativeTime;
    }

    /** First minute of the slot; every slot lasts six hours. */
    public LocalTime start() {
        return start;
    }

    /** Company time a run of this slot uses, so the same combination always sends the same time. */
    public LocalTime representativeTime() {
        return representativeTime;
    }
}
