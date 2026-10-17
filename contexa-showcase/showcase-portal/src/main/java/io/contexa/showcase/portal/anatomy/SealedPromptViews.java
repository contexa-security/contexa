package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * W7-13 (docs/showcase/화면설계-프롬프트신뢰-보강안.md 2, 3.1 to 3.3, 5): what a visitor sees of the sealed prompt of a
 * decision, from the view control D gives of it ({@code /internal/decisions/{requestId}/prompt-facts}: the user prompt
 * read line by line by the OSS prompt parser with each line's dictionary source grades, the bundle the seal names, the
 * sealed reason codes and the latest inspection). The facts come by block in the order the model reads them, each with
 * its source; the quality gives the bundle, the seal, the inspection as control D gives it and the ribbon's counts. The
 * screen counts nothing. HTTP session identifiers are masked in every text. N-SRC-4: a fact's source is the grade of
 * its value: the action line's as control D reads it from the seal, any other line's the first of its entry's grades.
 */
public final class SealedPromptViews {

    /** The v20 blocks in the order the model reads them (design 3.1, the system prompt's decision steps). */
    static final List<String> BLOCK_ORDER = List.of("REQUEST", "SESSION", "USER_BASELINE", "DECISION_FACTS", "UNKNOWN",
            "PAST_RECORDS", "UNTRUSTED_TEXT", "SECOND_PASS");
    /** The source grades of the core's PromptSourceGrade, in their order. */
    static final List<String> SOURCES = List.of("HOST", "LEARNED", "COMPUTED", "INFERRED", "UNTRUSTED");
    /** The block of the facts not known now; its lines are counted apart from the facts. */
    static final String UNKNOWN = "UNKNOWN";
    /** The core inspector's fact accuracy check (FactAccuracyCheck.CODE). */
    static final String FACT_ACCURACY = "FACT_ACCURACY";
    /** The core inspector's check of one fact stated twice with two values (SameFactCheck.CODE). */
    static final String SAME_FACT = "SAME_FACT";
    private static final String SESSION_MASK = "<SESSION>";
    /** N-SRC-4: the field of control D's line that names the grade of the line's own value. */
    private static final String LINE_SOURCE = "source";
    /** N-UI-1 (U1-5): the user baseline lines that state how sufficient their evidence is (dictionary 1.3, S-21). */
    static final Set<String> SUFFICIENCY_LABELS = Set.of("Evidence", "UsualActions");
    private static final String USER_BASELINE = "USER_BASELINE";
    /** The first grade below STRONG a line states is the baseline view's (core BaselineView.EvidenceGrade). */
    private static final Pattern GRADE = Pattern.compile("\\bevidence (LIMITED|WEAK)\\b");
    /** The causes core BaselineViewCalculator writes for such a grade, each read by its words. */
    private static final Pattern ACTION_INFERRED = Pattern.compile(
            "action family inferred from (\\S+(?: \\S+){0,2}?) in (\\d{1,9}) of (\\d{1,9}) observations");
    private static final Pattern FEW_OBSERVATIONS =
            Pattern.compile("only (\\d{1,9}) observations in the window, below the minimum (\\d{1,9})");
    private static final Pattern WIDER_WINDOW = Pattern.compile("the last \\d{1,9} days hold (\\d{1,9}) "
            + "observations, below the minimum \\d{1,9}; the view uses the last (\\d{1,9}) days");
    /** A work profile field the collector marks for caution (core DefaultProtectableWorkProfileCollector). */
    private static final Pattern FIELD_CAUTION = Pattern.compile("(\\S+) needs caution: ");

    private SealedPromptViews() {
    }

    /** The bundle the seal names: version, hash, where it was selected from and the user prompt layout. */
    public record Bundle(String version, String hash, String selectionSource, String layout) {
    }

    /**
     * One entry line of the prompt.
     *
     * @param line        the line's 1-based number in the user prompt
     * @param source      the grade of the line's value: its own source when control D gives one (N-SRC-4: the
     *                    action line's, as the seal states it), else the first of the line's source grades in the
     *                    grade order; null when it has none
     * @param grades      every source grade the line's dictionary entry declares
     * @param sufficiency N-UI-1: how sufficient the evidence behind a user baseline line is, when the line states a
     *                    grade below STRONG; null otherwise
     */
    public record Fact(int line, String factId, String label, String value, String source, List<String> grades,
                       Sufficiency sufficiency) {
    }

    /**
     * N-UI-1 (design 2.1, U1-5): how sufficient the evidence behind a line is, as the line states it, for the grey
     * line under its fact card.
     *
     * @param grade    the grade the baseline view gave below STRONG: LIMITED or WEAK
     * @param causes   the causes the line names, by kind, each once
     * @param cautions how many fields of the work profile the line marks for caution, each once
     */
    public record Sufficiency(String grade, List<Cause> causes, int cautions) {
    }

    /**
     * One cause of a grade below STRONG, as core BaselineViewCalculator writes it.
     *
     * @param kind ACTION_INFERRED: {@code count} of {@code of} observations had their action family inferred from
     *             {@code from}; FEW_OBSERVATIONS: {@code count} observations, below the minimum {@code of};
     *             WIDER_WINDOW: the recent days held {@code count} observations, so the view read the last
     *             {@code of} days
     * @param from the source of the inference; null for the other kinds
     */
    public record Cause(String kind, int count, int of, String from) {
    }

    /** The entry lines of one block, in prompt order. */
    public record Block(String block, List<Fact> facts) {
    }

    /**
     * The facts of a step's sealed prompt.
     *
     * @param reason why there are none: {@link SealedPrompts#NO_STEP}, {@link SealedPrompts#NOT_SEALED} or
     *               {@link SealedPrompts#NO_ENGINE}; null when available
     * @param blocks the blocks with lines in {@link #BLOCK_ORDER}, then any other block in prompt order
     */
    public record FactsView(String runId, int stepNo, boolean available, String reason, Bundle bundle,
                            List<Block> blocks) {
    }

    public record Seal(String packageId, String packageHash, String capturedAt) {
    }

    public record ReasonCode(String code, String fact) {
    }

    /** The fact accuracy check's compared facts: those that matched their sealed source over all compared. */
    public record FactAccuracy(int matched, int total) {
    }

    /**
     * The quality ribbon (design 2.2).
     *
     * @param facts          the entry lines outside the UNKNOWN block
     * @param withSource     of them, the lines with a source grade
     * @param factAccuracy   the fact accuracy check's counts; null without an inspection or that check
     * @param contradictions the same-fact check's mismatches; null without an inspection or that check
     * @param unknown        the entry lines of the UNKNOWN block
     */
    public record Ribbon(int facts, int withSource, FactAccuracy factAccuracy, Integer contradictions, int unknown) {
    }

    /**
     * The quality of a step's sealed prompt.
     *
     * @param inspection the latest inspection as control D gives it (verdict, inspector version, time, checks with
     *                   their mismatches); null when the seal has none yet
     */
    public record QualityView(boolean available, String reason, Bundle bundle, Seal seal, JsonNode inspection,
                              List<ReasonCode> reasonCodes, Ribbon ribbon) {
    }

    /** The facts view of a step; without facts when a reason is given. */
    public static FactsView facts(String runId, int stepNo, String reason, JsonNode facts) {
        if (reason != null || facts == null) {
            return new FactsView(runId, stepNo, false, reason, null, List.of());
        }
        Map<String, List<Fact>> byBlock = new LinkedHashMap<>();
        BLOCK_ORDER.forEach(block -> byBlock.put(block, new ArrayList<>()));
        for (JsonNode line : facts.path("lines")) {
            byBlock.computeIfAbsent(text(line.path("block")), block -> new ArrayList<>()).add(fact(line));
        }
        List<Block> blocks = new ArrayList<>();
        byBlock.forEach((block, lines) -> {
            if (!lines.isEmpty()) {
                blocks.add(new Block(block, List.copyOf(lines)));
            }
        });
        return new FactsView(runId, stepNo, true, null, bundle(facts), List.copyOf(blocks));
    }

    /** The quality view of a step; without values when a reason is given. */
    public static QualityView quality(String reason, JsonNode facts) {
        if (reason != null || facts == null) {
            return new QualityView(false, reason, null, null, null, List.of(), null);
        }
        JsonNode inspection = facts.path("inspection").isObject() ? facts.path("inspection") : null;
        List<ReasonCode> codes = new ArrayList<>();
        for (JsonNode code : facts.path("reasonCodes")) {
            codes.add(code.isTextual() ? new ReasonCode(code.asText(), null)
                    : new ReasonCode(text(code.path("code")), text(code.path("fact"))));
        }
        Seal seal = new Seal(text(facts.path("packageId")), text(facts.path("packageHash")),
                text(facts.path("capturedAt")));
        return new QualityView(true, null, bundle(facts), seal, inspection == null ? null : masked(inspection),
                List.copyOf(codes), ribbon(facts.path("lines"), inspection));
    }

    /** The ribbon's counts from the prompt's entry lines and the latest inspection (null without one). */
    static Ribbon ribbon(JsonNode lines, JsonNode inspection) {
        int facts = 0;
        int withSource = 0;
        int unknown = 0;
        for (JsonNode line : lines) {
            if (UNKNOWN.equals(text(line.path("block")))) {
                unknown++;
                continue;
            }
            facts++;
            if (source(line, grades(line)) != null) {
                withSource++;
            }
        }
        JsonNode accuracy = check(inspection, FACT_ACCURACY);
        JsonNode same = check(inspection, SAME_FACT);
        FactAccuracy factAccuracy = accuracy == null ? null : new FactAccuracy(accuracy.path("matched").asInt(),
                accuracy.path("matched").asInt() + accuracy.path("mismatched").asInt());
        return new Ribbon(facts, withSource, factAccuracy, same == null ? null : same.path("mismatched").asInt(),
                unknown);
    }

    /** A text with HTTP session identifiers masked, as the anatomy masks them; null stays null. */
    public static String masked(String text) {
        return text == null ? null : AnatomyBuilder.SESSION_ID.matcher(text).replaceAll(SESSION_MASK);
    }

    /** A copy of a node with HTTP session identifiers masked in every text, at any depth. */
    static JsonNode masked(JsonNode node) {
        JsonNode copy = node.deepCopy();
        mask(copy);
        return copy;
    }

    /** The first of the grades in the grade order; null when none is a known grade. */
    static String source(List<String> grades) {
        return SOURCES.stream().filter(grades::contains).findFirst().orElse(null);
    }

    /**
     * N-SRC-4: the source grade of a line's value. A line control D gives a source of its own for (the request's
     * action, whose entry allows two grades, as the seal states it) takes that one, none when it is null or no source
     * grade; any other line takes the first of its entry's grades in the grade order.
     */
    static String source(JsonNode line, List<String> grades) {
        if (line.has(LINE_SOURCE)) {
            String own = text(line.path(LINE_SOURCE));
            return own != null && SOURCES.contains(own) ? own : null;
        }
        return source(grades);
    }

    private static void mask(JsonNode node) {
        if (node instanceof ObjectNode object) {
            List<String> names = new ArrayList<>();
            object.fieldNames().forEachRemaining(names::add);
            for (String name : names) {
                JsonNode child = object.get(name);
                if (child.isTextual()) {
                    object.put(name, masked(child.asText()));
                } else {
                    mask(child);
                }
            }
        } else if (node instanceof ArrayNode array) {
            for (int index = 0; index < array.size(); index++) {
                JsonNode child = array.get(index);
                if (child.isTextual()) {
                    array.set(index, TextNode.valueOf(masked(child.asText())));
                } else {
                    mask(child);
                }
            }
        }
    }

    private static Fact fact(JsonNode line) {
        List<String> grades = grades(line);
        String label = text(line.path("label"));
        String value = masked(text(line.path("value")));
        return new Fact(line.path("number").asInt(), text(line.path("factId")), label, value, source(line, grades),
                grades, sufficiency(text(line.path("block")), label, value));
    }

    /**
     * N-UI-1 (U1-5): the grade below STRONG a user baseline line states (the block's evidence or the usual actions,
     * dictionary 1.3) and the causes it names; null for any other line, outside text above all, and for a line that
     * states no such grade. A cause the line states twice (a trust profile repeating the view's) counts once; the
     * fields marked for caution are counted, each once, not named.
     */
    static Sufficiency sufficiency(String block, String label, String value) {
        if (!USER_BASELINE.equals(block) || label == null || value == null || !SUFFICIENCY_LABELS.contains(label)) {
            return null;
        }
        Matcher grade = GRADE.matcher(value);
        if (!grade.find()) {
            return null;
        }
        Set<Cause> causes = new LinkedHashSet<>();
        Matcher inferred = ACTION_INFERRED.matcher(value);
        while (inferred.find()) {
            causes.add(new Cause("ACTION_INFERRED", Integer.parseInt(inferred.group(2)),
                    Integer.parseInt(inferred.group(3)), inferred.group(1)));
        }
        Matcher few = FEW_OBSERVATIONS.matcher(value);
        while (few.find()) {
            causes.add(new Cause("FEW_OBSERVATIONS", Integer.parseInt(few.group(1)), Integer.parseInt(few.group(2)),
                    null));
        }
        Matcher wider = WIDER_WINDOW.matcher(value);
        while (wider.find()) {
            causes.add(new Cause("WIDER_WINDOW", Integer.parseInt(wider.group(1)), Integer.parseInt(wider.group(2)),
                    null));
        }
        Set<String> cautions = new LinkedHashSet<>();
        Matcher caution = FIELD_CAUTION.matcher(value);
        while (caution.find()) {
            cautions.add(caution.group(1));
        }
        return new Sufficiency(grade.group(1), List.copyOf(causes), cautions.size());
    }

    private static List<String> grades(JsonNode line) {
        List<String> grades = new ArrayList<>();
        line.path("grades").forEach(grade -> grades.add(grade.asText()));
        return List.copyOf(grades);
    }

    private static Bundle bundle(JsonNode facts) {
        return new Bundle(text(facts.path("promptBundleVersion")), text(facts.path("promptBundleHash")),
                text(facts.path("promptBundleSelectionSource")), text(facts.path("userPromptLayoutVersion")));
    }

    private static JsonNode check(JsonNode inspection, String code) {
        if (inspection == null) {
            return null;
        }
        for (JsonNode check : inspection.path("checks")) {
            if (code.equals(check.path("code").asText())) {
                return check;
            }
        }
        return null;
    }

    private static String text(JsonNode node) {
        return node == null || node.isNull() || node.isMissingNode() ? null : node.asText();
    }
}
