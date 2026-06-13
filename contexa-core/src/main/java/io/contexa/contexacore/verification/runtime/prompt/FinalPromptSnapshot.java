package io.contexa.contexacore.verification.runtime.prompt;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public record FinalPromptSnapshot(
        String userPrompt,
        String userPromptHash,
        List<FinalPromptSection> sections,
        List<FinalPromptField> fields,
        List<FinalPromptBullet> bullets,
        List<FinalPromptNarrativeLine> narrativeLines,
        List<String> compactMarkers,
        List<FinalPromptUnmappedFact> unmappedFacts,
        List<FinalPromptSemanticGroup> semanticGroups
) {

    public FinalPromptSnapshot {
        sections = sections == null ? List.of() : List.copyOf(sections);
        fields = fields == null ? List.of() : List.copyOf(fields);
        bullets = bullets == null ? List.of() : List.copyOf(bullets);
        narrativeLines = narrativeLines == null ? List.of() : List.copyOf(narrativeLines);
        compactMarkers = compactMarkers == null ? List.of() : List.copyOf(compactMarkers);
        unmappedFacts = unmappedFacts == null ? List.of() : List.copyOf(unmappedFacts);
        semanticGroups = semanticGroups == null ? List.of() : List.copyOf(semanticGroups);
    }

    public FinalPromptSnapshot(
            String userPrompt,
            String userPromptHash,
            List<FinalPromptSection> sections,
            List<FinalPromptField> fields,
            List<FinalPromptBullet> bullets,
            List<FinalPromptNarrativeLine> narrativeLines,
            List<String> compactMarkers,
            List<FinalPromptUnmappedFact> unmappedFacts) {
        this(
                userPrompt,
                userPromptHash,
                sections,
                fields,
                bullets,
                narrativeLines,
                compactMarkers,
                unmappedFacts,
                List.of());
    }

    public FinalPromptSnapshot(
            String userPrompt,
            String userPromptHash,
            List<FinalPromptSection> sections,
            List<FinalPromptField> fields,
            List<FinalPromptBullet> bullets,
            List<FinalPromptNarrativeLine> narrativeLines,
            List<String> compactMarkers) {
        this(userPrompt, userPromptHash, sections, fields, bullets, narrativeLines, compactMarkers, List.of(), List.of());
    }

    public boolean hasSection(String sectionName) {
        if (!hasText(sectionName)) {
            return false;
        }
        String expected = normalizeSection(sectionName);
        return sections.stream().anyMatch(section -> normalizeSection(section.name()).equals(expected));
    }

    public boolean contains(String value) {
        return hasText(userPrompt) && hasText(value)
                && userPrompt.toLowerCase(Locale.ROOT).contains(value.toLowerCase(Locale.ROOT));
    }

    public List<FinalPromptField> fieldsByLabel(String label) {
        if (!hasText(label)) {
            return List.of();
        }
        String expected = normalizeLabel(label);
        return fields.stream()
                .filter(field -> normalizeLabel(field.label()).equals(expected))
                .toList();
    }

    public String firstValue(String... labels) {
        if (labels == null) {
            return null;
        }
        for (String label : labels) {
            List<FinalPromptField> matches = fieldsByLabel(label);
            if (!matches.isEmpty() && hasText(matches.get(0).value())) {
                return matches.get(0).value().trim();
            }
        }
        return null;
    }

    public Map<String, List<String>> valuesByNormalizedLabel() {
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (FinalPromptField field : fields) {
            String key = normalizeLabel(field.label());
            if (!hasText(key)) {
                continue;
            }
            result.computeIfAbsent(key, ignored -> new ArrayList<>()).add(field.value());
        }
        return Map.copyOf(result);
    }

    public boolean hasCompactMarker() {
        return !compactMarkers.isEmpty();
    }

    public boolean hasUnmappedFacts() {
        return !unmappedFacts.isEmpty();
    }

    public List<FinalPromptSemanticGroup> semanticGroupsByLabel(String label) {
        if (!hasText(label)) {
            return List.of();
        }
        String expected = normalizeLabel(label);
        return semanticGroups.stream()
                .filter(group -> normalizeLabel(group.groupLabel()).equals(expected))
                .toList();
    }

    public static String normalizeLabel(String value) {
        if (value == null) {
            return "";
        }
        return value.trim()
                .replaceAll("[^\\p{L}\\p{N}]+", "")
                .toLowerCase(Locale.ROOT);
    }

    static String normalizeSection(String value) {
        return value == null ? "" : value.trim().replaceAll("\\s+", " ").toUpperCase(Locale.ROOT);
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
