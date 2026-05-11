package io.contexa.contexacore.std.components.prompt;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class PromptFieldLineageAnalyzer {

    private static final Pattern SECTION_PATTERN = Pattern.compile("^===\\s*(.+?)\\s*===$");
    private static final int PREVIEW_LIMIT = 160;

    private PromptFieldLineageAnalyzer() {
    }

    public static PromptFieldLineageAnalysis analyze(String rawUserPrompt, String finalUserPrompt) {
        List<PromptFieldSnapshot> rawFields = extract(rawUserPrompt);
        List<PromptFieldSnapshot> finalFields = extract(finalUserPrompt);
        List<PromptFieldDiffRecord> diffs = diff(rawFields, finalFields);

        int missing = 0;
        int changed = 0;
        int added = 0;
        int compactedMarkers = 0;
        int truncatedMarkers = 0;
        for (PromptFieldDiffRecord diff : diffs) {
            if (diff.diffType() == PromptFieldDiffType.MISSING_IN_FINAL) {
                missing++;
            }
            else if (diff.diffType() == PromptFieldDiffType.VALUE_CHANGED) {
                changed++;
            }
            else if (diff.diffType() == PromptFieldDiffType.ADDED_IN_FINAL) {
                added++;
            }
        }
        for (PromptFieldSnapshot field : finalFields) {
            if (field.compactedMarker()) {
                compactedMarkers++;
            }
            if (field.truncatedMarker()) {
                truncatedMarkers++;
            }
        }
        return new PromptFieldLineageAnalysis(
                rawFields,
                finalFields,
                diffs,
                missing,
                changed,
                added,
                compactedMarkers,
                truncatedMarkers);
    }

    static List<PromptFieldSnapshot> extract(String promptText) {
        if (!StringUtils.hasText(promptText)) {
            return List.of();
        }
        String[] lines = promptText.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);
        List<PromptFieldSnapshot> fields = new ArrayList<>();
        Map<String, Integer> keyOccurrences = new LinkedHashMap<>();
        String sectionTitle = "GLOBAL";
        String sectionKey = "GLOBAL";
        int bulletIndex = 0;
        int freeLineIndex = 0;

        for (int i = 0; i < lines.length; i++) {
            String rawLine = lines[i] != null ? lines[i] : "";
            String line = rawLine.strip();
            if (line.isBlank()) {
                continue;
            }
            Matcher sectionMatcher = SECTION_PATTERN.matcher(line);
            if (sectionMatcher.matches()) {
                sectionTitle = sectionMatcher.group(1).strip();
                sectionKey = normalizeKey(sectionTitle);
                bulletIndex = 0;
                freeLineIndex = 0;
                continue;
            }

            String label;
            String value;
            if (line.startsWith("- ")) {
                bulletIndex++;
                label = "bullet." + bulletIndex;
                value = line.substring(2).strip();
            }
            else {
                int colon = line.indexOf(':');
                if (colon > 0) {
                    label = line.substring(0, colon).strip();
                    value = line.substring(colon + 1).strip();
                }
                else {
                    freeLineIndex++;
                    label = "line." + freeLineIndex;
                    value = line;
                }
            }

            String baseFieldKey = sectionKey + "." + normalizeKey(label);
            int occurrence = keyOccurrences.merge(baseFieldKey, 1, Integer::sum);
            String fieldKey = occurrence == 1 ? baseFieldKey : baseFieldKey + "#" + occurrence;
            fields.add(new PromptFieldSnapshot(
                    fieldKey,
                    sectionKey,
                    sectionTitle,
                    label,
                    PromptGovernanceSupport.sha256(value),
                    value.length(),
                    i + 1,
                    preview(value),
                    containsCompactedMarker(label, value),
                    containsTruncatedMarker(value)));
        }
        return List.copyOf(fields);
    }

    private static List<PromptFieldDiffRecord> diff(
            List<PromptFieldSnapshot> rawFields,
            List<PromptFieldSnapshot> finalFields) {
        Map<String, PromptFieldSnapshot> rawByKey = index(rawFields);
        Map<String, PromptFieldSnapshot> finalByKey = index(finalFields);
        Set<String> keys = new LinkedHashSet<>();
        keys.addAll(rawByKey.keySet());
        keys.addAll(finalByKey.keySet());

        List<PromptFieldDiffRecord> diffs = new ArrayList<>();
        for (String key : keys) {
            PromptFieldSnapshot raw = rawByKey.get(key);
            PromptFieldSnapshot fin = finalByKey.get(key);
            if (raw == null && fin != null) {
                diffs.add(diffRecord(key, fin, null, fin, PromptFieldDiffType.ADDED_IN_FINAL,
                        "최종 userPrompt에서 새로 생성된 필드입니다.", false));
            }
            else if (raw != null && fin == null) {
                diffs.add(diffRecord(key, raw, raw, null, PromptFieldDiffType.MISSING_IN_FINAL,
                        "raw userPrompt에는 있으나 최종 LLM userPrompt에는 없습니다.", true));
            }
            else if (raw != null && !raw.valueHash().equals(fin.valueHash())) {
                diffs.add(diffRecord(key, raw, raw, fin, PromptFieldDiffType.VALUE_CHANGED,
                        "raw userPrompt와 최종 LLM userPrompt의 값 해시가 다릅니다.", true));
            }
            else if (fin != null && (fin.compactedMarker() || fin.truncatedMarker())) {
                diffs.add(diffRecord(key, fin, raw, fin, PromptFieldDiffType.SAME,
                        "최종 LLM userPrompt에 압축 또는 생략 마커가 남아 있습니다.", true));
            }
        }
        return List.copyOf(diffs);
    }

    private static PromptFieldDiffRecord diffRecord(
            String key,
            PromptFieldSnapshot representative,
            PromptFieldSnapshot raw,
            PromptFieldSnapshot fin,
            PromptFieldDiffType diffType,
            String reason,
            boolean blockingCandidate) {
        return new PromptFieldDiffRecord(
                key,
                representative.sectionKey(),
                representative.sectionTitle(),
                representative.label(),
                diffType,
                raw != null ? raw.valueHash() : null,
                fin != null ? fin.valueHash() : null,
                raw != null ? raw.lineNumber() : -1,
                fin != null ? fin.lineNumber() : -1,
                reason,
                blockingCandidate);
    }

    private static Map<String, PromptFieldSnapshot> index(List<PromptFieldSnapshot> fields) {
        Map<String, PromptFieldSnapshot> indexed = new LinkedHashMap<>();
        for (PromptFieldSnapshot field : fields) {
            indexed.put(field.fieldKey(), field);
        }
        return indexed;
    }

    private static String normalizeKey(String value) {
        if (!StringUtils.hasText(value)) {
            return "UNKNOWN";
        }
        String normalized = value.strip()
                .replaceAll("([a-z])([A-Z])", "$1_$2")
                .replaceAll("[^\\p{IsAlphabetic}\\p{IsDigit}]+", "_")
                .replaceAll("_+", "_")
                .replaceAll("^_|_$", "")
                .toUpperCase(Locale.ROOT);
        return normalized.isBlank() ? "UNKNOWN" : normalized;
    }

    private static String preview(String value) {
        if (value == null) {
            return "";
        }
        String normalized = value.replaceAll("\\s+", " ").strip();
        if (normalized.length() <= PREVIEW_LIMIT) {
            return normalized;
        }
        return normalized.substring(0, PREVIEW_LIMIT) + "...";
    }

    private static boolean containsCompactedMarker(String label, String value) {
        String haystack = ((label != null ? label : "") + " " + (value != null ? value : "")).toLowerCase(Locale.ROOT);
        return haystack.contains("compactedlinecategories")
                || haystack.contains("additional lines compacted")
                || haystack.contains("additionalcontexttrustwarningscompacted")
                || haystack.contains("additionalconfidencewarningscompacted");
    }

    private static boolean containsTruncatedMarker(String value) {
        return value != null && value.strip().endsWith("...");
    }
}
