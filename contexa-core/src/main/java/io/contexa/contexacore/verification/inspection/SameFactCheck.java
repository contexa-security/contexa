/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.DecisionFactsResolver;
import io.contexa.contexacore.autonomous.context.decision.Deviation;
import io.contexa.contexacore.autonomous.context.decision.DeviationDimension;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.context.support.PastRecordCounts;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDictionary;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One fact the prompt states twice has one value (R1b-8, plan 2 C2). The decision facts line states a dimension of
 * the request the REQUEST and SESSION lines state as well, and says whether it is usual, which the usual lists say as
 * well; the past record state names the candidates the counts line counts. The values those lines drew are the sealed
 * decision facts and past record counts (the decision fact and past record checks compare the drawn lines with them),
 * so each other line is compared with them:
 * <ul>
 *     <li>a dimension the differences line states with its value: the REQUEST or SESSION line's value of it;</li>
 *     <li>a dimension the differences or same line states: whether the usual list holds the request's value;</li>
 *     <li>the past record state's candidates: the total the counts line counts.</li>
 * </ul>
 * Only lines drawn on both sides are compared. Each line keeps to its own source (the fact accuracy check); this check
 * finds two lines that each keep to a source and still tell the model two values of one fact.
 */
public final class SameFactCheck implements PromptInspectionCheck {

    public static final String CODE = "SAME_FACT";

    private static final String DIFFERENCES = DecisionFactsResolver.DEVIATIONS_FROM_BASELINE;
    private static final String SAME = DecisionFactsResolver.SAME_AS_BASELINE;
    private static final String STATE = "PastRecordsState";
    private static final String COUNTS = "PastRecordCounts";
    /** {@code Wed 03:17}: the request's day and hour (RequestLineValues.clock). */
    private static final Pattern CLOCK = Pattern.compile("^(\\S+) (\\d{2}):\\d{2}$");
    /** {@code PASSWORD+ONE_TIME_CODE (PASSWORD)}: the login method with the session's type when it differs. */
    private static final Pattern LOGIN = Pattern.compile("^([^ (,]+)(?: \\(([^()]+)\\))?");
    /** {@code 5 records of 5 candidates}: the past record state's candidates (PastRecordLineValues.STATE_FORMAT). */
    private static final Pattern CANDIDATES = Pattern.compile("^\\d+ records? of (\\d+) candidates");
    /** {@code (seen 9,10,11)}: the hours the usual hours line lists as seen. */
    private static final Pattern SEEN = Pattern.compile("\\(seen ([\\d,]+)\\)");

    @Override
    public String code() {
        return CODE;
    }

    @Override
    public boolean dictionaryPromptOnly() {
        return true;
    }

    @Override
    public void inspect(PromptInspectionTally tally) {
        Map<String, InspectedPrompt.Line> lines = lines(tally.subject().prompt());
        CanonicalSecurityContext context = tally.subject().canonicalContext();
        DecisionFacts facts = context != null ? context.getDecisionFacts() : null;
        if (facts != null) {
            InspectedPrompt.Line differences = lines.get(key(PromptBlock.DECISION_FACTS, DIFFERENCES));
            InspectedPrompt.Line same = lines.get(key(PromptBlock.DECISION_FACTS, SAME));
            for (Deviation deviation : facts.deviations()) {
                if (deviation == null || !deviation.compared() || deviation.current() == null) {
                    continue;
                }
                InspectedPrompt.Line stating = deviation.different() ? differences : same;
                if (stating == null) {
                    continue;
                }
                if (deviation.different()) {
                    value(tally, lines, deviation);
                }
                usual(tally, lines, deviation, stating);
            }
        }
        candidates(tally, lines);
    }

    /** The REQUEST or SESSION line's value of a dimension the differences line states with its value. */
    private static void value(PromptInspectionTally tally, Map<String, InspectedPrompt.Line> lines, Deviation deviation) {
        InspectedPrompt.Line line = switch (deviation.dimension()) {
            case TIME, DAY -> lines.get(key(PromptBlock.REQUEST, "Time"));
            case NETWORK -> lines.get(key(PromptBlock.REQUEST, "Network"));
            case DEVICE -> lines.get(key(PromptBlock.REQUEST, "Device"));
            case LOGIN_METHOD -> lines.get(key(PromptBlock.SESSION, "LoginMethod"));
            case ACTION -> lines.get(key(PromptBlock.REQUEST, "Action"));
            case RESOURCE_CLASS -> lines.get(key(PromptBlock.REQUEST, "ResourceClass"));
            case SIZE -> lines.get(key(PromptBlock.REQUEST, "Size"));
            case TARGET, RATE -> null;
        };
        if (line == null) {
            return;
        }
        String drawn = line.entryLine().value();
        String stated = switch (deviation.dimension()) {
            case TIME -> group(CLOCK, drawn, 2);
            case DAY -> group(CLOCK, drawn, 1);
            case NETWORK -> band(drawn);
            case DEVICE, RESOURCE_CLASS -> head(drawn);
            case LOGIN_METHOD -> loginType(drawn);
            case ACTION -> drawn.split(" ", 2)[0];
            default -> drawn;
        };
        if (stated == null) {
            return;
        }
        if (stated.equals(deviation.current())) {
            tally.matched(line);
            return;
        }
        mismatch(tally, line, deviation.current(), stated, DIFFERENCES,
                "the line states another " + deviation.dimension().label() + " than the differences line");
    }

    /** Whether the usual list holds the request's value as the differences or same line says. */
    private static void usual(PromptInspectionTally tally, Map<String, InspectedPrompt.Line> lines, Deviation deviation,
                              InspectedPrompt.Line stating) {
        String name = switch (deviation.dimension()) {
            case TIME -> "UsualHours";
            case NETWORK -> "UsualNetworks";
            case LOGIN_METHOD -> "UsualLoginMethods";
            case ACTION -> "UsualActions";
            case RESOURCE_CLASS -> "UsualResourceClass";
            default -> null;
        };
        InspectedPrompt.Line line = name != null ? lines.get(key(PromptBlock.USER_BASELINE, name)) : null;
        if (line == null || line.entryLine().value().equals(missingText(name))) {
            return;
        }
        List<String> listed = listed(deviation, line.entryLine().value());
        if (listed == null) {
            return;
        }
        // A login that holds a usual login and more is usual by the usual login it names (P5-변경-17).
        String login = deviation.usual() != null ? deviation.usual() : deviation.current();
        boolean holds = deviation.dimension() == DeviationDimension.LOGIN_METHOD
                ? listed.stream().anyMatch(value -> login.equalsIgnoreCase(
                String.valueOf(SecuritySemanticNormalizer.normalizeAuthenticationType(value))))
                : listed.contains(deviation.current());
        if (holds != deviation.different()) {
            tally.matched(line);
            return;
        }
        String source = stating.entryLine().label();
        mismatch(tally, line, (deviation.different() ? "a list without " : "a list with ") + deviation.current(),
                line.entryLine().value(), source, "the usual list " + (holds ? "holds" : "does not hold") + " the "
                        + deviation.dimension().label() + " the " + (deviation.different() ? "differences" : "same")
                        + " line calls " + (deviation.different() ? "new" : "usual"));
    }

    /** The values of a usual list in the form the comparison states them, or null when the list cannot be read. */
    private static List<String> listed(Deviation deviation, String value) {
        if (deviation.dimension() == DeviationDimension.TIME) {
            Matcher seen = SEEN.matcher(value);
            if (!seen.find()) {
                return null;
            }
            return Arrays.stream(seen.group(1).split(",")).filter(hour -> !hour.isBlank())
                    .map(hour -> String.format(Locale.ROOT, "%02d", Integer.parseInt(hour.trim()))).toList();
        }
        int details = value.indexOf(" (");
        return Arrays.stream((details >= 0 ? value.substring(0, details) : value).split(", "))
                .map(item -> item.trim().split(" ", 2)[0]).filter(item -> !item.isEmpty()).toList();
    }

    /** The past record state's candidates against the total of the sealed counts the counts line drew. */
    private static void candidates(PromptInspectionTally tally, Map<String, InspectedPrompt.Line> lines) {
        InspectedPrompt.Line state = lines.get(key(PromptBlock.PAST_RECORDS, STATE));
        if (state == null || lines.get(key(PromptBlock.PAST_RECORDS, COUNTS)) == null) {
            return;
        }
        Matcher drawn = CANDIDATES.matcher(state.entryLine().value());
        PastRecordCounts counts = PastRecordCounts.fromMetadata(
                tally.subject().executionMetadata().get(PromptExecutionMetadata.PROMPT_PAST_RECORD_COUNTS));
        if (!drawn.find() || counts == null) {
            return;
        }
        if (Long.parseLong(drawn.group(1)) == counts.total()) {
            tally.matched(state);
            return;
        }
        mismatch(tally, state, counts.total() + " candidates", drawn.group(1) + " candidates",
                PromptBlock.PAST_RECORDS.title() + "." + COUNTS,
                "the past record state names another number of candidates than the counts line counts");
    }

    private static void mismatch(PromptInspectionTally tally, InspectedPrompt.Line line, String expected, String actual,
                                 String source, String reason) {
        tally.mismatch(tally.mismatchFinding().block(line.block().title()).entry(line.entryLine().label())
                .factId(line.factId()).lineNumber(line.number()).expected(expected).actual(actual)
                .sourceRef(source.contains(".") ? source : PromptBlock.DECISION_FACTS.title() + "." + source)
                .reason(reason).build());
    }

    /** The first drawn entry line of each block and label. */
    private static Map<String, InspectedPrompt.Line> lines(InspectedPrompt prompt) {
        Map<String, InspectedPrompt.Line> lines = new HashMap<>();
        for (InspectedPrompt.Line line : prompt.lines()) {
            if (line.kind() == InspectedPrompt.Kind.ENTRY && line.block() != null) {
                lines.putIfAbsent(key(line.block(), line.entryLine().label()), line);
            }
        }
        return lines;
    }

    private static String key(PromptBlock block, String label) {
        return block.name() + "." + label;
    }

    /** What the dictionary draws for a usual list without values. */
    private static String missingText(String name) {
        return SecurityDecisionPromptDictionary.ENTRIES.stream()
                .filter(entry -> entry.block() == PromptBlock.USER_BASELINE && entry.name().equals(name))
                .findFirst().map(PromptDictionaryEntry::missingText).orElse(null);
    }

    private static String group(Pattern pattern, String value, int group) {
        Matcher matcher = pattern.matcher(value);
        return matcher.matches() ? matcher.group(group) : null;
    }

    /** The value before its parenthesised details. */
    private static String head(String value) {
        int open = value.indexOf(" (");
        return open >= 0 ? value.substring(0, open) : value;
    }

    /** The band among the network line's details (a CIDR block), or null when the line draws none. */
    private static String band(String value) {
        int open = value.indexOf(" (");
        if (open < 0 || !value.endsWith(")")) {
            return null;
        }
        return Arrays.stream(value.substring(open + 2, value.length() - 1).split(", "))
                .filter(part -> part.contains("/")).findFirst().orElse(null);
    }

    /**
     * The login type the comparison states: the session's type the line draws in parentheses, else the method, read
     * the way the current request snapshot reads them (session type first, then the method).
     */
    private static String loginType(String value) {
        Matcher login = LOGIN.matcher(value);
        if (!login.find()) {
            return null;
        }
        String typed = login.group(2) != null && !login.group(2).startsWith("assurance ") ? login.group(2) : login.group(1);
        Object type = SecuritySemanticNormalizer.normalizeAuthenticationType(typed, login.group(1));
        return type != null ? type.toString() : null;
    }
}
