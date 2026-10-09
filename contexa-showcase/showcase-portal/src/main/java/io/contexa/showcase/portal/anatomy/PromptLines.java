package io.contexa.showcase.portal.anatomy;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * How long the prompt the engine sent was, counted by the server from the stored texts so the screen never counts
 * (work 19 of docs/showcase/화면설계서-v2-구현계획.md, D-38). One rule everywhere: a line is a line with content, so the
 * seven bundles add up to the total.
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
 */
public record PromptLines(int total, int system, int user, int systemPhysical, int userPhysical,
                          List<Section> sections, List<Bundle> bundles) {

    public record Section(String name, String bundle, int lines) {
    }

    public record Bundle(String bundle, int lines) {
    }

    /** The bundles of the prompt screen, in order: the rules, then the situation's six parts. */
    public static final List<String> BUNDLES = List.of("RULES", "REQUEST", "IDENTITY", "USUAL", "HISTORY", "COMPANY",
            "UNKNOWN", "OTHER");

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
     * not name is counted under OTHER, never dropped. Null when neither text was kept.
     */
    public static PromptLines of(String systemPrompt, String userPrompt) {
        if (systemPrompt == null && userPrompt == null) {
            return null;
        }
        int system = contentLines(systemPrompt);
        List<Section> sections = new ArrayList<>();
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
                    sections.add(section(current, currentLines));
                }
                current = header;
                currentLines = 1;
            } else if (current != null && content) {
                currentLines++;
            } else if (current != null) {
                sections.add(section(current, currentLines));
                current = null;
            } else if (content) {
                outside++;
            }
        }
        if (current != null) {
            sections.add(section(current, currentLines));
        }
        Map<String, Integer> counts = new LinkedHashMap<>();
        BUNDLES.forEach(bundle -> counts.put(bundle, 0));
        counts.merge("RULES", system + outside, Integer::sum);
        sections.forEach(section -> counts.merge(section.bundle(), section.lines(), Integer::sum));
        List<Bundle> bundles = new ArrayList<>();
        counts.forEach((bundle, lines) -> bundles.add(new Bundle(bundle, lines)));
        return new PromptLines(system + user, system, user, physicalLines(systemPrompt), physicalLines(userPrompt),
                List.copyOf(sections), List.copyOf(bundles));
    }

    private static Section section(String name, int lines) {
        return new Section(name, SECTION_BUNDLES.getOrDefault(name, "OTHER"), lines);
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
