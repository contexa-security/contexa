package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
     *                  one), DENY_OR_BLOCK (the last value), STATED (the last value is neither blank, unknown, none nor
     *                  not applicable), TRUSTED_SIGNAL (the last value is neither none nor unknown and the last
     *                  AnomalySignalTrust is TRUSTED_VERIFICATION_INPUT)
     */
    public record Rule(String key, String condition) {
    }

    /**
     * @param values every value the prompt rendered for the label, in order; empty when the prompt has none; of a v20
     *               decision what the engine sealed for the condition (N-DEP-2, {@link #sealed})
     * @param met    whether the values meet the inspector's condition
     */
    public record Reading(String label, String condition, List<String> values, boolean met) {
    }

    public static final List<Rule> RULES = List.of(
            new Rule("authorizationeffect", "DENY_OR_BLOCK"),
            new Rule("approvalrequired", "TRUE"),
            new Rule("approvalmissing", "TRUE"),
            new Rule("blockeduser", "TRUE"),
            new Rule("sessiondevicechange", "STATED"),
            new Rule("sessionnetworkchange", "STATED"),
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
            new Rule("observedanomalysignal", "TRUSTED_SIGNAL"));

    /**
     * N-DEP-2: the adverse conditions of the core's v20 inspection (SecurityDecisionFactChecks: the adverse facts of
     * the boundaries' list and a stated policy whose requirement PolicySatisfied does not state as met) that the facts
     * the engine sealed with a v20 decision state, in the core's order. Not copied: the client signals, an impossible
     * travel, a role scope outside the group's facts (the core leaves a provisional scope out), the past denials,
     * threat matches, failed logins and MFA failures of the session, and a required block's categories.
     * CoreAdverseLabelsContractTest fails when the core's list changes.
     */
    public static final List<Rule> SEALED_RULES = List.of(
            new Rule("authorizationeffect", "DENY_OR_BLOCK"),
            new Rule("sessiondevicechange", "STATED"),
            new Rule("sessionnetworkchange", "STATED"),
            new Rule("dataconflicts", "STATED"),
            new Rule("blockeduser", "STATED"),
            new Rule("policysatisfied", "NOT_SATISFIED"));

    private static final Pattern LEADING_COUNT = Pattern.compile("^\\d+");

    private CoreAdverseLabels() {
    }

    /**
     * N-DEP-2: the readings of {@link #SEALED_RULES} for a v20 decision, from its record's metadata (the sealed
     * canonical context): the authorization effect, the session device and network changes and the data conflicts the
     * decision facts state, the blocked user of the session's or the company's record, and a policy the decision facts
     * state, met when PolicySatisfied does not state it as met. The values are what the engine sealed for the
     * condition. Null for a record of another layout or without sealed decision facts (its prompt is read as the v19
     * inspector reads it).
     */
    public static List<Reading> sealed(JsonNode metadata) {
        if (metadata == null
                || !SealedDeviations.V20_LAYOUT.equals(metadata.path("userPromptLayoutVersion").asText(null))) {
            return null;
        }
        JsonNode context = metadata.path("sealedEvidence.canonicalContext");
        JsonNode decisionFacts = context.path("decisionFacts");
        if (!decisionFacts.path("facts").isArray()) {
            return null;
        }
        Map<String, String> facts = new LinkedHashMap<>();
        decisionFacts.path("facts").forEach(fact -> facts.put(fact.path("name").asText(), fact.path("value").asText()));
        String effect = context.path("authorization").path("authorizationEffect").asText(null);
        List<String> effects = effect == null ? List.of() : List.of(effect);
        boolean blocked = context.path("session").path("blockedUser").asBoolean(false)
                || context.path("frictionProfile").path("blockedUser").asBoolean(false);
        JsonNode satisfied = decisionFacts.path("policy").path("satisfied");
        boolean policy = facts.containsKey("Policy");
        boolean unmet = !(facts.containsKey("PolicySatisfied") && satisfied.isBoolean() && satisfied.asBoolean());
        List<Reading> readings = new ArrayList<>();
        readings.add(new Reading("authorizationeffect", "DENY_OR_BLOCK", effects, met("DENY_OR_BLOCK", effects)));
        readings.add(statedReading("sessiondevicechange", facts.get("SessionDeviceChange")));
        readings.add(statedReading("sessionnetworkchange", facts.get("SessionNetworkChange")));
        readings.add(statedReading("dataconflicts", facts.get("DataConflicts")));
        readings.add(new Reading("blockeduser", "STATED", blocked ? List.of("true") : List.of(), blocked));
        readings.add(new Reading("policysatisfied", "NOT_SATISFIED", policy && facts.containsKey("PolicySatisfied")
                ? List.of(facts.get("PolicySatisfied")) : List.of(), policy && unmet));
        return List.copyOf(readings);
    }

    private static Reading statedReading(String label, String value) {
        return new Reading(label, "STATED", value == null ? List.of() : List.of(value), value != null);
    }

    public static List<Reading> read(String prompt) {
        List<Reading> readings = new ArrayList<>();
        if (prompt == null) {
            return readings;
        }
        for (Rule rule : RULES) {
            List<String> values = values(prompt, rule.key());
            boolean met = "TRUSTED_SIGNAL".equals(rule.condition())
                    ? met("SIGNAL", values) && trusted(values(prompt, "anomalysignaltrust"))
                    : met(rule.condition(), values);
            readings.add(new Reading(rule.key(), rule.condition(), values, met));
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
            case "STATED" -> !last.isBlank() && !"none".equals(last) && !"unknown".equals(last)
                    && !"not_applicable".equals(last);
            default -> false;
        };
    }

    private static boolean trusted(List<String> trustValues) {
        return !trustValues.isEmpty() && trustValues.get(trustValues.size() - 1).toLowerCase(Locale.ROOT)
                .startsWith("trusted_verification_input");
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
