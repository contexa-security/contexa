package io.contexa.showcase.portal.anatomy;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * How long the prompt the engine sent was, counted by the server from the stored texts so the screen never counts
 * (work 19 of docs/showcase/화면설계서-v2-구현계획.md, D-38). One rule everywhere: a line is a line with content, so the
 * bundles add up to the total. A v19 prompt is counted under the seven bundles of the screen design, a v20 prompt
 * under one bundle per dictionary block (W3-10 of docs/showcase/프롬프트-최종-구현계획.md).
 *
 * @param total          content lines of the system and the user prompt together
 * @param system         content lines of the system prompt (the decision rules)
 * @param user           content lines of the user prompt (the situation)
 * @param systemPhysical every line of the system prompt as the raw text shows it, so the line numbers a screen cites
 *                       ("rule lines 66 to 70") and the length it states for the opened text agree
 * @param userPhysical   every line of the user prompt as the raw text shows it
 * @param sections every "=== NAME ===" section of the user prompt in order, with its content lines and its bundle
 * @param bundles        content lines per bundle, a list in the screen's order (a stored anatomy is read back from a
 *                       JSON column that keeps no key order); the user prompt's lines outside any section (the
 *                       closing answer instructions) belong to the rules
 * @param layout         {@link #V19_SECTIONS} or {@link #V20_BLOCKS}: which bundles the prompt is counted under
 */
public record PromptLines(int total, int system, int user, int systemPhysical, int userPhysical,
                          List<Section> sections, List<Bundle> bundles, String layout) {

    public record Section(String name, String bundle, int lines) {
    }

    public record Bundle(String bundle, int lines) {
    }

    /** A v19 user prompt: the core's sections, counted under the seven bundles of the screen design. */
    public static final String V19_SECTIONS = "V19_SECTIONS";

    /** A v20 user prompt: the core's dictionary blocks (W3-2), counted one bundle per block. */
    public static final String V20_BLOCKS = "V20_BLOCKS";

    /** The bundles of the prompt screen, in order: the rules, then the situation's six parts. */
    public static final List<String> BUNDLES = List.of("RULES", "REQUEST", "IDENTITY", "USUAL", "HISTORY", "COMPANY",
            "UNKNOWN", "OTHER");

    /**
     * The bundles of a v20 prompt, in the screen's order: the rules, the five parts in the order the model reads them
     * (this request, this session, usual behaviour, decision facts, what is not known; 3.1 of
     * docs/showcase/화면설계-프롬프트신뢰-보강안.md), the folded past records and outside text, then the block the
     * Layer2 second pass adds (W3-9).
     */
    public static final List<String> V20_BUNDLES = List.of("RULES", "REQUEST", "SESSION", "USER_BASELINE",
            "DECISION_FACTS", "UNKNOWN", "PAST_RECORDS", "UNTRUSTED_TEXT", "SECOND_PASS", "OTHER");

    /** The core's v20 block titles ({@code PromptBlock}) by bundle; a header may add a qualifier in brackets. */
    static final Map<String, String> V20_BLOCK_BUNDLES = Map.of(
            "USER BASELINE", "USER_BASELINE",
            "SESSION", "SESSION",
            "REQUEST", "REQUEST",
            "DECISION FACTS", "DECISION_FACTS",
            "PAST RECORDS", "PAST_RECORDS",
            "UNKNOWN", "UNKNOWN",
            "UNTRUSTED TEXT", "UNTRUSTED_TEXT",
            "SECOND PASS", "SECOND_PASS");

    /** The core's user prompt sections by bundle (the e1-prompt note of the screen design). */
    static final Map<String, String> SECTION_BUNDLES = Map.ofEntries(
            Map.entry("CURRENT REQUEST AND EVENT", "REQUEST"),
            Map.entry("RESOURCE AND ACTION CONTEXT", "REQUEST"),
            Map.entry("DEVICE CONTEXT", "REQUEST"),
            Map.entry("LOCATION CONTEXT", "REQUEST"),
            Map.entry("IDENTITY AND ROLE CONTEXT", "IDENTITY"),
            Map.entry("AUTHENTICATION AND ASSURANCE CONTEXT", "IDENTITY"),
            Map.entry("BRIDGE RESOLUTION CONTEXT", "IDENTITY"),
            Map.entry("OBSERVED WORK PATTERN CONTEXT", "USUAL"),
            Map.entry("PERSONAL WORK PROFILE", "USUAL"),
            Map.entry("ROLE AND WORK SCOPE CONTEXT", "USUAL"),
            Map.entry("SESSION NARRATIVE CONTEXT", "USUAL"),
            Map.entry("RAG EVIDENCE", "HISTORY"),
            Map.entry("SUPPORTING LEARNING CONTEXT", "HISTORY"),
            Map.entry("FRICTION AND APPROVAL HISTORY", "COMPANY"),
            Map.entry("DELEGATED OBJECTIVE CONTEXT", "UNKNOWN"),
            Map.entry("EXPLICIT MISSING KNOWLEDGE", "UNKNOWN"),
            Map.entry("REQUEST INTENT SIGNAL CONTEXT", "UNKNOWN"),
            Map.entry("CONTEXT COVERAGE", "UNKNOWN"));

    /**
     * Counts the texts as stored. A section runs from its header to the first empty line; a section the table does
     * not name is counted under OTHER, never dropped. A user prompt with a v20 block header is counted under the v20
     * bundles, any other under the v19 ones. Null when neither text was kept.
     */
    public static PromptLines of(String systemPrompt, String userPrompt) {
        if (systemPrompt == null && userPrompt == null) {
            return null;
        }
        int system = contentLines(systemPrompt);
        List<String> names = new ArrayList<>();
        List<Integer> sizes = new ArrayList<>();
        int user = 0;
        int outside = 0;
        String current = null;
        int currentLines = 0;
        for (String line : userPrompt == null ? List.<String>of() : userPrompt.lines().toList()) {
            boolean content = !line.isBlank();
            if (content) {
                user++;
            }
            String header = header(line);
            if (header != null) {
                if (current != null) {
                    names.add(current);
                    sizes.add(currentLines);
                }
                current = header;
                currentLines = 1;
            } else if (current != null && content) {
                currentLines++;
            } else if (current != null) {
                names.add(current);
                sizes.add(currentLines);
                current = null;
            } else if (content) {
                outside++;
            }
        }
        if (current != null) {
            names.add(current);
            sizes.add(currentLines);
        }
        boolean v20 = names.stream().anyMatch(name -> V20_BLOCK_BUNDLES.containsKey(blockTitle(name)));
        Map<String, String> table = v20 ? V20_BLOCK_BUNDLES : SECTION_BUNDLES;
        List<Section> sections = new ArrayList<>();
        for (int index = 0; index < names.size(); index++) {
            String name = names.get(index);
            sections.add(new Section(name, table.getOrDefault(v20 ? blockTitle(name) : name, "OTHER"),
                    sizes.get(index)));
        }
        Map<String, Integer> counts = new LinkedHashMap<>();
        (v20 ? V20_BUNDLES : BUNDLES).forEach(bundle -> counts.put(bundle, 0));
        counts.merge("RULES", system + outside, Integer::sum);
        sections.forEach(section -> counts.merge(section.bundle(), section.lines(), Integer::sum));
        List<Bundle> bundles = new ArrayList<>();
        counts.forEach((bundle, lines) -> bundles.add(new Bundle(bundle, lines)));
        return new PromptLines(system + user, system, user, physicalLines(systemPrompt), physicalLines(userPrompt),
                List.copyOf(sections), List.copyOf(bundles), v20 ? V20_BLOCKS : V19_SECTIONS);
    }

    /** A v20 header's block title: the header without its qualifier in brackets, as the core reads it. */
    private static String blockTitle(String name) {
        int qualifier = name.indexOf('(');
        return (qualifier >= 0 ? name.substring(0, qualifier) : name).trim();
    }

    private static String header(String line) {
        String trimmed = line.trim();
        return trimmed.length() > 8 && trimmed.startsWith("=== ") && trimmed.endsWith(" ===")
                ? trimmed.substring(4, trimmed.length() - 4) : null;
    }

    private static int physicalLines(String text) {
        return text == null ? 0 : (int) text.lines().count();
    }

    private static int contentLines(String text) {
        return text == null ? 0 : (int) text.lines().filter(line -> !line.isBlank()).count();
    }
}
