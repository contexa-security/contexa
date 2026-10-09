package io.contexa.showcase.portal.anatomy;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Values of the work profile summary the engine received ("Window 7d | Observations 25 | ..."), read as written. */
public final class WorkProfileSummary {

    private static final Pattern OBSERVATIONS = Pattern.compile("Observations (\\d+)");
    private static final Pattern WINDOW = Pattern.compile("Window (\\w+)");

    private WorkProfileSummary() {
    }

    /** The work profile observations the engine received for the step; null when the summary does not state them. */
    public static Integer observations(DecisionAnatomy anatomy) {
        String value = find(OBSERVATIONS, summary(anatomy.context()));
        return value == null ? null : Integer.parseInt(value);
    }

    /** The work profile's window as written ("7d"); null when the summary does not state it. */
    public static String window(DecisionAnatomy.Context context) {
        return find(WINDOW, summary(context));
    }

    static Integer observations(DecisionAnatomy.Context context) {
        String value = find(OBSERVATIONS, summary(context));
        return value == null ? null : Integer.parseInt(value);
    }

    private static String summary(DecisionAnatomy.Context context) {
        Object summary = context.usual() == null ? null : context.usual().get("summary");
        return summary == null ? null : summary.toString();
    }

    private static String find(Pattern pattern, String text) {
        if (text == null) {
            return null;
        }
        Matcher matcher = pattern.matcher(text);
        return matcher.find() ? matcher.group(1) : null;
    }
}
