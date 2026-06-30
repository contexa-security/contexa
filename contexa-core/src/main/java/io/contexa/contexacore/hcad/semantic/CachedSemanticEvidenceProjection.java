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
package io.contexa.contexacore.hcad.semantic;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public record CachedSemanticEvidenceProjection(
        List<HcadSemanticEvidenceEntry> entries,
        List<String> evidenceGapCodes) {

    public CachedSemanticEvidenceProjection {
        entries = entries == null ? List.of() : List.copyOf(entries);
        evidenceGapCodes = evidenceGapCodes == null ? List.of() : List.copyOf(new LinkedHashSet<>(evidenceGapCodes));
    }

    public static CachedSemanticEvidenceProjection unavailable(String gapCode) {
        return new CachedSemanticEvidenceProjection(List.of(), List.of(gapCode));
    }

    public static CachedSemanticEvidenceProjection of(List<HcadSemanticEvidenceEntry> entries) {
        List<String> gaps = new ArrayList<>();
        if (entries != null) {
            for (HcadSemanticEvidenceEntry entry : entries) {
                if (entry != null) {
                    gaps.addAll(entry.evidenceGapCodes());
                    if (!entry.usableForScoring()) {
                        gaps.add(entry.status().name());
                    }
                    if (!entry.usableForScoring() && entry.status().sourceAbsent()) {
                        gaps.add("SOURCE_ABSENT");
                    }
                }
            }
        }
        return new CachedSemanticEvidenceProjection(entries, gaps);
    }

    public boolean hasUsableEvidence() {
        return entries.stream().anyMatch(HcadSemanticEvidenceEntry::usableForScoring);
    }

    public boolean hasFreshHit() {
        return entries.stream()
                .anyMatch(entry -> entry != null
                        && entry.usableForScoring()
                        && entry.status() == HcadSemanticEvidenceCacheStatus.HIT);
    }

    public boolean hasStaleHit() {
        return entries.stream()
                .anyMatch(entry -> entry != null
                        && entry.status() == HcadSemanticEvidenceCacheStatus.STALE_HIT);
    }

    public double maxSimilarityToRisk() {
        return entries.stream()
                .filter(HcadSemanticEvidenceEntry::usableForScoring)
                .map(HcadSemanticEvidenceEntry::similarityToRisk)
                .filter(value -> value != null)
                .mapToDouble(Double::doubleValue)
                .max()
                .orElse(0.0d);
    }

    public double maxSimilarityToNormal() {
        return entries.stream()
                .filter(HcadSemanticEvidenceEntry::usableForScoring)
                .map(HcadSemanticEvidenceEntry::similarityToNormal)
                .filter(value -> value != null)
                .mapToDouble(Double::doubleValue)
                .max()
                .orElse(0.0d);
    }

    public double maxMismatchScore() {
        return entries.stream()
                .filter(HcadSemanticEvidenceEntry::usableForScoring)
                .map(HcadSemanticEvidenceEntry::mismatchScore)
                .filter(value -> value != null)
                .mapToDouble(Double::doubleValue)
                .max()
                .orElse(0.0d);
    }

    public boolean hasRiskSimilarityAtLeast(double threshold) {
        return hasUsableEvidence() && maxSimilarityToRisk() >= threshold;
    }

    public boolean hasMismatchAtLeast(double threshold) {
        return hasUsableEvidence() && maxMismatchScore() >= threshold;
    }

    public Map<String, Object> snapshot() {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("semanticEvidenceAvailable", hasUsableEvidence());
        snapshot.put("semanticEvidenceFreshHit", hasFreshHit());
        snapshot.put("semanticEvidenceStaleHit", hasStaleHit());
        snapshot.put("semanticEvidenceGapCodes", evidenceGapCodes);
        snapshot.put("semanticSimilarityToNormal", maxSimilarityToNormal());
        snapshot.put("semanticSimilarityToRisk", maxSimilarityToRisk());
        snapshot.put("semanticMismatchScore", maxMismatchScore());
        snapshot.put("semanticEvidenceEntries", entries.stream().map(this::entrySnapshot).toList());
        return snapshot;
    }

    private Map<String, Object> entrySnapshot(HcadSemanticEvidenceEntry entry) {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("type", entry.key().type().name());
        snapshot.put("status", entry.status().name());
        snapshot.put("sourceVersion", entry.sourceVersion());
        snapshot.put("sourceTable", textFromSummary(entry.summaryJson(), "sourceTable"));
        snapshot.put("evidenceVersion", entry.evidenceVersion());
        snapshot.put("embeddingModel", entry.embeddingModel());
        snapshot.put("dimension", entry.dimension());
        snapshot.put("similarityToNormal", entry.similarityToNormal());
        snapshot.put("similarityToRisk", entry.similarityToRisk());
        snapshot.put("mismatchScore", entry.mismatchScore());
        snapshot.put("sampleCount", numberFromSummary(entry.summaryJson(), "sampleCount"));
        snapshot.put("evidenceKind", textFromSummary(entry.summaryJson(), "evidenceKind"));
        snapshot.put("actionFamily", textFromSummary(entry.summaryJson(), "actionFamily"));
        snapshot.put("avgRisk", numberFromSummary(entry.summaryJson(), "avgRisk"));
        snapshot.put("avgConfidence", numberFromSummary(entry.summaryJson(), "avgConfidence"));
        snapshot.put("lastDecisionAt", textFromSummary(entry.summaryJson(), "lastDecisionAt"));
        snapshot.put("summaryJson", entry.summaryJson());
        snapshot.put("gapCodes", entry.evidenceGapCodes());
        return snapshot;
    }

    private static Number numberFromSummary(String summaryJson, String field) {
        String value = summaryValue(summaryJson, field, false);
        if (value == null) {
            return null;
        }
        try {
            if (value.contains(".")) {
                return Double.parseDouble(value);
            }
            return Long.parseLong(value);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static String textFromSummary(String summaryJson, String field) {
        return summaryValue(summaryJson, field, true);
    }

    private static String summaryValue(String summaryJson, String field, boolean quoted) {
        if (summaryJson == null || summaryJson.isBlank() || field == null || field.isBlank()) {
            return null;
        }
        String pattern = quoted
                ? "\\\"" + Pattern.quote(field) + "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\""
                : "\\\"" + Pattern.quote(field) + "\\\"\\s*:\\s*(-?[0-9]+(?:\\.[0-9]+)?)";
        Matcher matcher = Pattern.compile(pattern).matcher(summaryJson);
        return matcher.find() ? matcher.group(1) : null;
    }
}
