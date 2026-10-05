package io.contexa.showcase.portal.combination;

import io.contexa.showcase.business.company.TimeSlot;

import java.util.List;

/**
 * One cell of the exploration grid (deck p.13): who, when, how many, which ticket and from which device. Only these
 * company facts change; the baseline and the authentication state are read-only. The key names the cell, for
 * example {@code adm-a.DAWN.4831.MATCH.USUAL}.
 */
public record Combination(String employee, TimeSlot slot, int items, Ticket ticket, Device device) {

    /** Employees of the grid (docs/showcase approval Q-25). */
    public static final List<String> EMPLOYEES = List.of("adm-a", "eng-k");

    /** Representative counts of the four count bands: 50 or fewer, 500 or fewer, 5,000 or fewer, more (Q-25). */
    public static final List<Integer> ITEMS = List.of(40, 480, 4831, 6200);

    public enum Ticket { NONE, MISMATCH, MATCH }

    public enum Device { USUAL, NEW }

    public Combination {
        if (!EMPLOYEES.contains(employee) || !ITEMS.contains(items) || slot == null || ticket == null
                || device == null) {
            throw new IllegalArgumentException("Not a cell of the exploration grid");
        }
    }

    public String key() {
        return employee + "." + slot.name() + "." + items + "." + ticket.name() + "." + device.name();
    }

    public static Combination parse(String key) {
        String[] parts = key == null ? new String[0] : key.split("\\.");
        if (parts.length != 5) {
            throw new IllegalArgumentException("Not a combination key: " + key);
        }
        try {
            return new Combination(parts[0], TimeSlot.valueOf(parts[1]), Integer.parseInt(parts[2]),
                    Ticket.valueOf(parts[3]), Device.valueOf(parts[4]));
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Not a combination key: " + key, e);
        }
    }
}
