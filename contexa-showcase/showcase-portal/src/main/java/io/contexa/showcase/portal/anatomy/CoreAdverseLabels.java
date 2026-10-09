package io.contexa.showcase.portal.anatomy;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The prompt labels the core's response inspector reads as explicit adverse evidence
 * (SecurityDecisionRawOutputContractInspector, the explicitAdverseEvidence rule and the deny or block authorization
 * effect), read from the prompt the engine sent the way that inspector reads them (docs/showcase/데모-재설계.md 3 ④,
 * W1-4c). The demo makes no rule of its own: CoreAdverseLabelsContractTest fails when the core's list changes. The
 * corroborated canonical attack and the tenant or organization conflict parts of the core's rule are not copied; the
 * anatomy says which labels these are and does not claim more.
 */
public final class CoreAdverseLabels {

    /**
     * @param key       the label as the inspector names it (lower case; the prompt's case does not matter)
     * @param condition TRUE or FALSE (any occurrence with that value), POSITIVE (the last value is a count of at least
     *                  one), DENY_OR_BLOCK (the last value), SIGNAL (the last value is neither none nor unknown)
     */
    public record Rule(String key, String condition) {
    }

    /**
     * @param values every value the prompt rendered for the label, in order; empty when the prompt has none
     * @param met    whether the values meet the inspector's condition
     */
    public record Reading(String label, String condition, List<String> values, boolean met) {
    }

    public static final List<Rule> RULES = List.of(
            new Rule("authorizationeffect", "DENY_OR_BLOCK"),
            new Rule("approvalrequired", "TRUE"),
            new Rule("approvalmissing", "TRUE"),
            new Rule("blockeduser", "TRUE"),
            new Rule("contextbindinghashmismatch", "TRUE"),
            new Rule("currentresourcefamilypresentindeniedrolescope", "TRUE"),
            new Rule("currentactionfamilypresentindeniedrolescope", "TRUE"),
            new Rule("currentresourcefamilypresentinexpectedrolescope", "FALSE"),
            new Rule("currentactionfamilypresentinexpectedrolescope", "FALSE"),
            new Rule("impossibletravel", "TRUE"),
            new Rule("threatcampaignmatchcount", "POSITIVE"),
            new Rule("recentdeniedaccesscount", "POSITIVE"),
            new Rule("recentblockcount", "POSITIVE"),
            new Rule("recentmfafailurecount", "POSITIVE"),
            new Rule("failedloginattempts", "POSITIVE"),
            new Rule("rolescopedeltacount", "POSITIVE"),
            new Rule("observedanomalysignal", "SIGNAL"));

    private static final Pattern LEADING_COUNT = Pattern.compile("^\\d+");

    private CoreAdverseLabels() {
    }

    public static List<Reading> read(String prompt) {
        List<Reading> readings = new ArrayList<>();
        if (prompt == null) {
            return readings;
        }
        for (Rule rule : RULES) {
            List<String> values = values(prompt, rule.key());
            readings.add(new Reading(rule.key(), rule.condition(), values, met(rule.condition(), values)));
        }
        return readings;
    }

    static List<String> values(String prompt, String key) {
        Matcher matcher = Pattern.compile("(?m)^\\s*" + Pattern.quote(key) + "\\s*[:=]\\s*([^\\r\\n]+?)\\s*$",
                Pattern.CASE_INSENSITIVE).matcher(prompt);
        List<String> values = new ArrayList<>();
        while (matcher.find()) {
            values.add(matcher.group(1).trim());
        }
        return values;
    }

    static boolean met(String condition, List<String> values) {
        if (values.isEmpty()) {
            return false;
        }
        String last = values.get(values.size() - 1).toLowerCase(Locale.ROOT);
        return switch (condition) {
            case "TRUE" -> values.stream().anyMatch(value -> "true".equals(value.toLowerCase(Locale.ROOT)));
            case "FALSE" -> values.stream().anyMatch(value -> "false".equals(value.toLowerCase(Locale.ROOT)));
            case "POSITIVE" -> positive(last);
            case "DENY_OR_BLOCK" -> "deny".equals(last) || "block".equals(last);
            case "SIGNAL" -> !last.isBlank() && !"none".equals(last) && !"unknown".equals(last);
            default -> false;
        };
    }

    private static boolean positive(String value) {
        if (value.isBlank() || "unknown".equals(value) || "none".equals(value) || "not_applicable".equals(value)) {
            return false;
        }
        Matcher matcher = LEADING_COUNT.matcher(value);
        if (!matcher.find()) {
            return false;
        }
        try {
            return Integer.parseInt(matcher.group()) >= 1;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
