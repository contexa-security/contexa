package io.contexa.contexacore.verification.runtime.prompt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FinalPromptParser {

    private static final Pattern SECTION_PATTERN = Pattern.compile("^\\s*={3,}\\s*(.+?)\\s*={3,}\\s*$");
    private static final Pattern FIELD_PATTERN = Pattern.compile(
            "^\\s*([\\p{L}\\p{N}][\\p{L}\\p{N}_.\\- ]{0,120})\\s*:\\s*(.*)$");
    private static final List<String> COMPACT_MARKERS = List.of(
            "CompactedLineCategories",
            "additional lines compacted",
            "AdditionalConfidenceWarningsCompacted",
            "AdditionalContextTrustWarningsCompacted"
    );

    private final FinalPromptMetricContractCatalog contractCatalog;

    public FinalPromptParser() {
        this(null);
    }

    public FinalPromptParser(FinalPromptMetricContractCatalog contractCatalog) {
        this.contractCatalog = contractCatalog;
    }

    public FinalPromptSnapshot parse(String userPrompt) {
        List<FinalPromptSection> sections = new ArrayList<>();
        List<FinalPromptField> fields = new ArrayList<>();
        List<FinalPromptBullet> bullets = new ArrayList<>();
        List<FinalPromptNarrativeLine> narrativeLines = new ArrayList<>();
        List<String> compactMarkers = new ArrayList<>();
        List<FinalPromptUnmappedFact> unmappedFacts = new ArrayList<>();
        Map<String, MutableSemanticGroup> semanticGroups = new LinkedHashMap<>();
        String currentSection = "ROOT";
        String currentParentGroup = "";
        if (userPrompt != null) {
            String[] lines = userPrompt.split("\\R", -1);
            for (int index = 0; index < lines.length; index++) {
                String line = lines[index];
                int lineNumber = index + 1;
                Matcher sectionMatcher = SECTION_PATTERN.matcher(line);
                if (sectionMatcher.matches()) {
                    currentSection = sectionMatcher.group(1).trim();
                    currentParentGroup = "";
                    sections.add(new FinalPromptSection(currentSection, lineNumber));
                    addCompactMarkers(line, compactMarkers);
                    continue;
                }
                String trimmed = line == null ? "" : line.trim();
                if (trimmed.isEmpty()) {
                    currentParentGroup = "";
                    addCompactMarkers(line, compactMarkers);
                    continue;
                }
                if (trimmed.startsWith("- ")) {
                    String bulletText = trimmed.substring(2).trim();
                    String parent = currentParentGroup;
                    String groupLabel = hasText(parent) ? parent : "bullet";
                    String semanticKey = canonicalGroup(currentSection, groupLabel);
                    String role = attackSignalRole(currentSection, groupLabel, bulletText);
                    bullets.add(new FinalPromptBullet(
                            currentSection,
                            bulletText,
                            lineNumber,
                            parent,
                            semanticKey,
                            semanticKey,
                            role));
                    semanticGroup(semanticGroups, currentSection, groupLabel, lineNumber)
                            .addBullet(bulletText, lineNumber);
                    addCompactMarkers(line, compactMarkers);
                    continue;
                }
                Matcher fieldMatcher = FIELD_PATTERN.matcher(line);
                if (fieldMatcher.matches()) {
                    String label = fieldMatcher.group(1).trim();
                    String value = fieldMatcher.group(2).trim();
                    String semanticKey = semanticKey(currentSection, label);
                    boolean mapped = mappedToContract(currentSection, label);
                    String parentGroup = hasText(currentParentGroup) ? currentParentGroup : label;
                    fields.add(new FinalPromptField(
                            currentSection,
                            label,
                            value,
                            lineNumber,
                            semanticKey,
                            semanticKey,
                            mapped,
                            parentGroup,
                            securityRelevance(currentSection, label),
                            attackSignalRole(currentSection, label, value)));
                    semanticGroup(semanticGroups, currentSection, parentGroup, lineNumber)
                            .addField(label, lineNumber);
                    if (!mapped) {
                        unmappedFacts.add(new FinalPromptUnmappedFact(currentSection, label, value, lineNumber, line));
                    }
                    if (!hasText(value)) {
                        currentParentGroup = label;
                    }
                    else {
                        currentParentGroup = "";
                    }
                    addCompactMarkers(line, compactMarkers);
                    continue;
                }
                String groupLabel = hasText(currentParentGroup) ? currentParentGroup : "narrative";
                String semanticKey = canonicalGroup(currentSection, groupLabel);
                String role = attackSignalRole(currentSection, groupLabel, trimmed);
                narrativeLines.add(new FinalPromptNarrativeLine(
                        currentSection,
                        trimmed,
                        lineNumber,
                        semanticKey,
                        semanticKey,
                        role));
                semanticGroup(semanticGroups, currentSection, groupLabel, lineNumber)
                        .addNarrative(trimmed, lineNumber);
                addCompactMarkers(line, compactMarkers);
            }
        }
        return new FinalPromptSnapshot(
                userPrompt,
                sha256Prefixed(userPrompt),
                sections,
                fields,
                bullets,
                narrativeLines,
                compactMarkers,
                unmappedFacts,
                semanticGroups.values().stream()
                        .map(MutableSemanticGroup::toImmutable)
                        .toList());
    }

    private MutableSemanticGroup semanticGroup(
            Map<String, MutableSemanticGroup> groups,
            String section,
            String groupLabel,
            int lineNumber) {
        String label = hasText(groupLabel) ? groupLabel : "group";
        String key = canonicalGroup(section, label);
        return groups.computeIfAbsent(key, ignored -> new MutableSemanticGroup(
                section,
                key,
                label,
                lineNumber,
                securityRelevance(section, label),
                attackSignalRole(section, label, ""),
                contractCatalog != null));
    }

    private String semanticKey(String section, String label) {
        if (contractCatalog != null) {
            return contractCatalog.promptLocation(section, label);
        }
        return FinalPromptSemanticModel.semanticKey(section, label);
    }

    private String canonicalGroup(String section, String label) {
        if (contractCatalog != null) {
            return contractCatalog.canonicalGroup(section, label);
        }
        return FinalPromptSemanticModel.semanticKey(section, label);
    }

    private String securityRelevance(String section, String label) {
        if (contractCatalog != null) {
            return contractCatalog.securityRelevance(section, label);
        }
        return FinalPromptSemanticModel.securityRelevance(section, label);
    }

    private String attackSignalRole(String section, String label, String value) {
        if (contractCatalog != null) {
            return contractCatalog.attackSignalRole(section, label, value);
        }
        return FinalPromptSemanticModel.attackSignalRole(section, label, value);
    }

    private boolean mappedToContract(String section, String label) {
        return contractCatalog == null || contractCatalog.isKnownPromptFact(section, label);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private void addCompactMarkers(String line, List<String> target) {
        if (line == null) {
            return;
        }
        String lower = line.toLowerCase(Locale.ROOT);
        for (String marker : COMPACT_MARKERS) {
            if (lower.contains(marker.toLowerCase(Locale.ROOT))) {
                target.add(marker);
            }
        }
    }

    private String sha256Prefixed(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return "sha256:" + HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 digest is not available.", exception);
        }
    }

    private static final class MutableSemanticGroup {
        private final String section;
        private final String groupKey;
        private final String groupLabel;
        private final int startLineNumber;
        private final String securityRelevance;
        private final String attackSignalRole;
        private final boolean contractBacked;
        private int endLineNumber;
        private final List<String> fieldLabels = new ArrayList<>();
        private final List<String> bulletTexts = new ArrayList<>();
        private final List<String> narrativeTexts = new ArrayList<>();

        private MutableSemanticGroup(
                String section,
                String groupKey,
                String groupLabel,
                int lineNumber,
                String securityRelevance,
                String attackSignalRole,
                boolean contractBacked) {
            this.section = section;
            this.groupKey = groupKey;
            this.groupLabel = groupLabel;
            this.startLineNumber = lineNumber;
            this.endLineNumber = lineNumber;
            this.securityRelevance = securityRelevance;
            this.attackSignalRole = attackSignalRole;
            this.contractBacked = contractBacked;
        }

        private void addField(String label, int lineNumber) {
            if (label != null && !label.isBlank()) {
                fieldLabels.add(label);
            }
            endLineNumber = Math.max(endLineNumber, lineNumber);
        }

        private void addBullet(String text, int lineNumber) {
            if (text != null && !text.isBlank()) {
                bulletTexts.add(text);
            }
            endLineNumber = Math.max(endLineNumber, lineNumber);
        }

        private void addNarrative(String text, int lineNumber) {
            if (text != null && !text.isBlank()) {
                narrativeTexts.add(text);
            }
            endLineNumber = Math.max(endLineNumber, lineNumber);
        }

        private FinalPromptSemanticGroup toImmutable() {
            return new FinalPromptSemanticGroup(
                    section,
                    groupKey,
                    groupLabel,
                    startLineNumber,
                    endLineNumber,
                    fieldLabels,
                    bulletTexts,
                    narrativeTexts,
                    contractBacked ? securityRelevance : FinalPromptSemanticModel.securityRelevance(section, groupLabel),
                    contractBacked ? attackSignalRole : FinalPromptSemanticModel.attackSignalRole(
                            section,
                            groupLabel,
                            String.join(" ", bulletTexts)));
        }
    }
}
