package io.contexa.showcase.portal.anatomy;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Where the engine input of one request differed between two runs (lab-3, review R-15), compared on the server so the
 * screen only shows it (T-27). The comparison is of what the engine received, not of the conditions the visitor
 * chose, and claims no cause.
 */
public final class InputComparison {

    /** One input that differs: its value in the earlier run and in this one; null where a run did not have it. */
    public record Change(String key, String before, String now) {
    }

    private InputComparison() {
    }

    /** The inputs the screen compares, by key, as the engine received them. */
    static Map<String, String> items(DecisionAnatomy anatomy) {
        Map<String, String> items = new LinkedHashMap<>();
        for (DecisionAnatomy.Comparison row : anatomy.context().usualVsNow()) {
            items.put("dim." + row.dimension(), text(row.now()) + " · " + text(row.inUsual()));
        }
        Map<String, Object> company = anatomy.context().company();
        items.put("ApprovalRequired", text(company == null ? null : company.get("approvalRequired")));
        items.put("ApprovalMissing", text(company == null ? null : company.get("approvalMissing")));
        items.put("ApprovalStatus", text(company == null ? null : company.get("approvalStatus")));
        Map<String, Object> resource = anatomy.context().resource();
        items.put("Sensitivity", text(resource == null ? null : resource.get("sensitivity")));
        Map<String, Object> labels = anatomy.context().labelMatrix();
        items.put("CurrentVsObservedDeltaCount", text(labels == null ? null : labels.get("CurrentVsObservedDeltaCount")));
        return items;
    }

    public static List<Change> changes(DecisionAnatomy before, DecisionAnatomy now) {
        Map<String, String> was = items(before);
        Map<String, String> is = items(now);
        Set<String> keys = new LinkedHashSet<>(was.keySet());
        keys.addAll(is.keySet());
        List<Change> changes = new ArrayList<>();
        for (String key : keys) {
            if (!Objects.equals(was.get(key), is.get(key))) {
                changes.add(new Change(key, was.get(key), is.get(key)));
            }
        }
        return changes;
    }

    private static String text(Object value) {
        return value == null ? "-" : String.valueOf(value);
    }
}
