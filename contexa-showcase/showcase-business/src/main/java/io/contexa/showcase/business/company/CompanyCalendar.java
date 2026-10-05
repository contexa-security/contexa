package io.contexa.showcase.business.company;

import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.time.temporal.TemporalAdjusters;

/**
 * Company clock of the virtual company. The company runs in UTC (ADR-09). A run happens on the anchor date, a
 * Wednesday, and the protagonists' learned history lies in the week before it (ADR-19, ADR-23).
 */
public final class CompanyCalendar {

    private CompanyCalendar() {
    }

    /** The latest Wednesday on or before the given day; a run day is never in the wall-clock future. */
    public static LocalDate anchorFor(LocalDate today) {
        return today.with(TemporalAdjusters.previousOrSame(DayOfWeek.WEDNESDAY));
    }

    /** Company time of a slot on the anchor date. */
    public static Instant at(LocalDate day, TimeSlot slot) {
        return at(day, slot.representativeTime());
    }

    public static Instant at(LocalDate day, LocalTime time) {
        return day.atTime(time).toInstant(ZoneOffset.UTC);
    }

    public static boolean isWorkday(LocalDate day) {
        DayOfWeek dayOfWeek = day.getDayOfWeek();
        return dayOfWeek != DayOfWeek.SATURDAY && dayOfWeek != DayOfWeek.SUNDAY;
    }

    /** Monday of the week the day belongs to. */
    public static LocalDate weekStart(LocalDate day) {
        return day.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
    }
}
