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
package io.contexa.contexacore.autonomous.context.collector;

import io.contexa.contexacore.autonomous.baseline.BaselineView;
import io.contexa.contexacore.autonomous.baseline.BaselineViewCalculator;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.context.support.ActionFamilyResolver;
import io.contexa.contexacore.autonomous.context.support.MetadataValueResolver;
import io.contexa.contexacommon.domain.EventTimeZone;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.StringJoiner;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;

import io.contexa.contexacore.autonomous.context.model.ContextEvidenceRecord;
import io.contexa.contexacore.autonomous.context.model.ContextFieldTrustRecord;
import io.contexa.contexacore.autonomous.context.model.ContextQualityGrade;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;
import io.contexa.contexacore.autonomous.context.policy.ContextSemanticBoundaryPolicy;
import io.contexa.contexacore.autonomous.context.policy.PromptRelevantRequestPathPolicy;

public class DefaultProtectableWorkProfileCollector implements ProtectableWorkProfileCollector {

    private static final int HISTORY_SCAN_LIMIT = 5_000;
    private static final int TOP_RESOURCE_LIMIT = 6;
    private static final int TOP_ACTION_LIMIT = 6;
    private static final int TOP_SENSITIVITY_LIMIT = 4;
    private static final int MAX_EVIDENCE_RECORDS = 4;
    private static final int MAX_FIELD_EVIDENCE_IDS = 6;
    private static final int PROVISIONAL_OBSERVATION_THRESHOLD = 3;
    private static final String NULL_TOKEN = "~";
    private static final String SERIALIZATION_VERSION_V2 = "v2";
    private static final String SERIALIZATION_VERSION_V3 = "v3";
    private static final String SERIALIZATION_VERSION_V4 = "v4";
    private static final String PROFILE_KEY = "PERSONAL_WORK_PROFILE";
    private static final String COLLECTOR_ID = "PROTECTABLE_WORK_PROFILE_COLLECTOR";

    private final SecurityContextDataStore dataStore;
    private final ContextObservationRecorder recorder;

    /** A collector that records through a recorder of its own, committed by whoever holds it. */
    public DefaultProtectableWorkProfileCollector(SecurityContextDataStore dataStore) {
        this(dataStore, new ContextObservationRecorder(dataStore));
    }

    public DefaultProtectableWorkProfileCollector(SecurityContextDataStore dataStore,
                                                  ContextObservationRecorder recorder) {
        this.dataStore = dataStore;
        this.recorder = recorder;
    }

    public ContextObservationRecorder recorder() {
        return recorder;
    }

    /**
     * The subject's work profile before this request. The collector only reads; the request's observation joins the
     * usual behaviour only when an enforced decision allows the request (W2-7, A-15), and resolving the same request
     * again records nothing more.
     */
    @Override
    public Optional<ProtectableWorkProfileSnapshot> collect(SecurityEvent event) {
        if (event == null || !StringUtils.hasText(event.getUserId())) {
            return Optional.empty();
        }
        Optional<ProtectableWorkProfileSnapshot> resolved = recorder.resolved(event,
                ContextObservationRecorder.WORK_PROFILE, ProtectableWorkProfileSnapshot.class);
        if (resolved.isPresent()) {
            return resolved;
        }

        WorkProfileObservation currentObservation = createObservation(event);
        if (currentObservation == null) {
            return Optional.empty();
        }

        String tenantId = resolveTenantId(event);
        String userId = event.getUserId().trim();
        // The usual behaviour is compared with the activity period of this request, so it leaves that period out.
        List<WorkProfileObservation> history = BaselineViewCalculator.withoutCurrentSessionPeriod(
                loadHistory(tenantId, userId, currentObservation.timestampMs()),
                WorkProfileObservation::timestampMs,
                WorkProfileObservation::sessionKey,
                sessionKeysOf(event, currentObservation.sessionKey()),
                currentObservation.timestampMs());
        // The snapshot and its usual-behaviour view describe the same window (W2-3, A-19).
        List<WorkProfileObservation> baseline = BaselineViewCalculator.windowed(
                history, WorkProfileObservation::timestampMs, currentObservation.timestampMs());
        BaselineView view = BaselineViewCalculator.calculate(
                history.stream().map(this::viewObservation).toList(),
                currentObservation.timestampMs(),
                EventTimeZone.get());
        Optional<ProtectableWorkProfileSnapshot> snapshot = buildSnapshot(tenantId, userId, baseline, view);

        String observation = shouldPersist(currentObservation) ? serialize(currentObservation) : null;
        recorder.stage(event, ContextObservationRecorder.WORK_PROFILE, snapshot.orElse(null), commit -> {
            if (observation != null && commit.learnable()) {
                commit.dataStore().addWorkProfileObservation(tenantId, userId, observation);
            }
        });
        return snapshot;
    }

    private List<WorkProfileObservation> loadHistory(String tenantId, String userId, long currentTimestampMs) {
        List<String> rawObservations = dataStore.getRecentWorkProfileObservations(tenantId, userId, HISTORY_SCAN_LIMIT);
        if (rawObservations.isEmpty()) {
            return List.of();
        }

        long fallbackWindowStart = currentTimestampMs - BaselineViewCalculator.FALLBACK_WINDOW_DAYS * 24L * 60L * 60L * 1_000L;
        Map<String, WorkProfileObservation> deduplicated = new LinkedHashMap<>();
        for (String raw : rawObservations) {
            WorkProfileObservation observation = deserialize(raw);
            if (observation == null) {
                continue;
            }
            if (observation.timestampMs() > currentTimestampMs) {
                continue;
            }
            if (observation.timestampMs() >= fallbackWindowStart) {
                deduplicated.putIfAbsent(observation.observationId(), observation);
            }
        }
        return List.copyOf(deduplicated.values());
    }

    private BaselineViewCalculator.Observation viewObservation(WorkProfileObservation observation) {
        return new BaselineViewCalculator.Observation(
                observation.timestampMs(),
                observation.actionFamily(),
                observation.actionFamilySourceKey(),
                observation.actionFamilyFallback(),
                firstText(observation.sensitivity(), observation.resourceFamily()),
                observation.pathTemplate(),
                observation.requestPath(),
                observation.sessionKey(),
                "ALLOWED".equals(observation.decisionState()),
                observation.requestedItems());
    }

    private Optional<ProtectableWorkProfileSnapshot> buildSnapshot(
            String tenantId,
            String userId,
            List<WorkProfileObservation> observations,
            BaselineView view) {
        if (observations == null || observations.isEmpty()) {
            return Optional.empty();
        }

        Map<String, Integer> protectableResourceCounts = new LinkedHashMap<>();
        Map<String, Integer> sensitivityCounts = new LinkedHashMap<>();

        int protectableCount = 0;
        int knownProtectableCount = 0;
        for (WorkProfileObservation observation : observations) {
            if (observation.protectable() != null) {
                knownProtectableCount++;
            }

            if (Boolean.TRUE.equals(observation.protectable())) {
                protectableCount++;
                if (StringUtils.hasText(observation.requestPath())) {
                    protectableResourceCounts.merge(observation.requestPath(), 1, Integer::sum);
                }
                if (StringUtils.hasText(observation.sensitivity())) {
                    sensitivityCounts.merge(observation.sensitivity(), 1, Integer::sum);
                }
            }
        }

        // Time, action and rate come from the usual-behaviour view, so that the work profile and the user profile say
        // the same usual hours (W2-3, B-9).
        int observationCount = observations.size();
        int daysCovered = view.daysCovered();
        int windowDays = view.windowDays();
        List<String> frequentProtectableResources = topStringKeys(protectableResourceCounts, TOP_RESOURCE_LIMIT);
        List<String> frequentActionFamilies = topStringKeys(view.actionCounts(), TOP_ACTION_LIMIT);
        List<Integer> normalAccessHours = view.usualHours();
        List<Integer> normalAccessDays = view.usualDays();
        Double normalRequestRate = view.requestsPerActiveHour();
        Double protectableInvocationDensity = knownProtectableCount == 0
                ? null
                : round(totalAsDouble(protectableCount) / knownProtectableCount, 4);
        List<String> protectableResourceHeatmap = topHeatmap(protectableResourceCounts, TOP_RESOURCE_LIMIT);
        List<String> frequentSensitiveResourceCategories = topStringKeys(sensitivityCounts, TOP_SENSITIVITY_LIMIT);
        String normalReadWriteExportRatio = view.readWriteExportRatio();

        ContextTrustProfile trustProfile = buildTrustProfile(
                observations,
                observationCount,
                daysCovered,
                windowDays,
                frequentProtectableResources,
                frequentActionFamilies,
                protectableInvocationDensity);
        return Optional.of(ProtectableWorkProfileSnapshot.builder()
                .tenantId(tenantId)
                .userId(userId)
                .observationCount(observationCount)
                .windowDays(windowDays)
                .frequentProtectableResources(frequentProtectableResources)
                .frequentActionFamilies(frequentActionFamilies)
                .normalAccessHours(normalAccessHours)
                .normalAccessDays(normalAccessDays)
                .normalRequestRate(normalRequestRate)
                .protectableInvocationDensity(protectableInvocationDensity)
                .protectableResourceHeatmap(protectableResourceHeatmap)
                .frequentSensitiveResourceCategories(frequentSensitiveResourceCategories)
                .normalReadWriteExportRatio(normalReadWriteExportRatio)
                .summary(buildSummary(
                        observationCount,
                        windowDays,
                        frequentProtectableResources,
                        frequentActionFamilies,
                        protectableInvocationDensity,
                        normalAccessHours,
                        view.counts().dayObservations()))
                .trustProfile(trustProfile)
                .baselineView(withFieldCautions(view, trustProfile))
                .build());
    }

    /**
     * The view with the trust profile's other cautions as causes of its grade, so that the evidence state and the
     * cautions of the same work profile never disagree (W2-3, B-2). The action field's caution is the view's own
     * inference cause when it has one.
     */
    private BaselineView withFieldCautions(BaselineView view, ContextTrustProfile trustProfile) {
        boolean actionCauseStated = view.evidenceCauses().stream()
                .anyMatch(cause -> cause.startsWith("action family inferred"));
        List<String> causes = new ArrayList<>();
        for (ContextFieldTrustRecord fieldRecord : trustProfile.getFieldRecords()) {
            if (fieldRecord == null || !ContextSemanticBoundaryPolicy.requiresEvidenceCaution(fieldRecord)
                    || actionCauseStated && "workProfile.frequentActionFamilies".equals(fieldRecord.getFieldPath())) {
                continue;
            }
            causes.add(fieldRecord.getFieldPath() + " needs caution: " + fieldRecord.getQualitySummary()
                    + (fieldRecord.getFallbackSourceKeys().isEmpty()
                    ? "" : " | fallbackSources=" + String.join(",", fieldRecord.getFallbackSourceKeys())));
        }
        return view.withAdditionalCauses(causes);
    }

    private ContextTrustProfile buildTrustProfile(
            List<WorkProfileObservation> observations,
            int observationCount,
            int daysCovered,
            int windowDays,
            List<String> frequentProtectableResources,
            List<String> frequentActionFamilies,
            Double protectableInvocationDensity) {
        ContextFieldTrustRecord resourceField = buildFieldRecord(
                "workProfile.frequentProtectableResources",
                "Protectable resources this subject actually reached through allowed post-auth requests.",
                "Compare the current resource against prior protectable access scope.",
                observations,
                observation -> Boolean.TRUE.equals(observation.protectable()),
                WorkProfileObservation::requestPath,
                WorkProfileObservation::requestPathSourceKey,
                WorkProfileObservation::requestPathFallback,
                true);
        ContextFieldTrustRecord actionField = buildFieldRecord(
                "workProfile.frequentActionFamilies",
                "Canonical action families previously exercised by this subject.",
                "Compare the current action family against prior business operation patterns.",
                observations,
                observation -> true,
                WorkProfileObservation::actionFamily,
                WorkProfileObservation::actionFamilySourceKey,
                WorkProfileObservation::actionFamilyFallback,
                true);
        ContextFieldTrustRecord accessWindowField = buildFieldRecord(
                "workProfile.normalAccessWindow",
                "Observed access-hour and access-day envelope for this subject.",
                "Use as timing context, not as a standalone anomaly rule.",
                observations,
                observation -> true,
                observation -> Long.toString(observation.timestampMs()),
                observation -> "event.timestamp",
                observation -> false,
                false);
        ContextFieldTrustRecord densityField = buildFieldRecord(
                "workProfile.protectableInvocationDensity",
                "Share of observations that were explicitly classified as protectable.",
                "Estimate how much of the subject's recent workload touches protectable scope.",
                observations,
                observation -> true,
                observation -> observation.protectable() == null ? null : observation.protectable().toString(),
                WorkProfileObservation::protectableSourceKey,
                WorkProfileObservation::protectableFallback,
                true);

        List<ContextFieldTrustRecord> fieldRecords = List.of(resourceField, actionField, accessWindowField, densityField);
        int overallScore = averageQualityScore(fieldRecords);
        if (resourceField.getQualityGrade() == ContextQualityGrade.REJECTED
                || actionField.getQualityGrade() == ContextQualityGrade.REJECTED) {
            overallScore = Math.min(overallScore, 30);
        }
        else if (ContextSemanticBoundaryPolicy.requiresEvidenceCaution(resourceField)
                || ContextSemanticBoundaryPolicy.requiresEvidenceCaution(actionField)
                || ContextSemanticBoundaryPolicy.requiresEvidenceCaution(densityField)) {
            overallScore = Math.min(overallScore, 55);
        }
        ContextQualityGrade overallGrade = resolveGrade(overallScore);

        List<String> qualityWarnings = new ArrayList<>();
        appendQualityWarning(qualityWarnings, resourceField);
        appendQualityWarning(qualityWarnings, actionField);
        appendQualityWarning(qualityWarnings, densityField);
        if (observationCount < 10) {
            qualityWarnings.add("Work profile baseline is thin; treat pattern claims as provisional until more allowed observations accumulate.");
        }
        if (!actionField.getFallbackSourceKeys().isEmpty()) {
            qualityWarnings.add("Action family baseline includes fallback-derived signals; do not treat it as a standalone indicator of user intent.");
        }
        qualityWarnings.add("This profile describes enacted post-auth access behavior, not approved business intent, approval lineage, or delegated objective.");

        List<ContextEvidenceRecord> evidenceRecords = observations.stream()
                .sorted((left, right) -> Long.compare(right.timestampMs(), left.timestampMs()))
                .limit(MAX_EVIDENCE_RECORDS)
                .map(this::toEvidenceRecord)
                .toList();

        return ContextTrustProfile.builder()
                .profileKey(PROFILE_KEY)
                .collectorId(COLLECTOR_ID)
                .summary(buildTrustProfileSummary(
                        overallGrade,
                        observationCount,
                        daysCovered,
                        frequentProtectableResources,
                        frequentActionFamilies,
                        protectableInvocationDensity))
                .provenanceSummary(buildTrustProfileProvenanceSummary(
                        observationCount,
                        daysCovered,
                        windowDays,
                        resourceField,
                        actionField))
                .overallQualityGrade(overallGrade)
                .overallQualityScore(overallScore)
                .scopeLimitations(List.of(
                        "Use this profile to understand enacted work patterns after authorization, not to infer business objective by itself.",
                        "Approval lineage, delegated intent, and human purpose require friction, delegation, or enterprise memory context."))
                .qualityWarnings(qualityWarnings)
                .fieldRecords(fieldRecords)
                .evidenceRecords(evidenceRecords)
                .build();
    }

    private ContextFieldTrustRecord buildFieldRecord(
            String fieldPath,
            String semanticMeaning,
            String intendedUse,
            List<WorkProfileObservation> observations,
            Predicate<WorkProfileObservation> observationFilter,
            Function<WorkProfileObservation, String> valueExtractor,
            Function<WorkProfileObservation, String> sourceExtractor,
            Predicate<WorkProfileObservation> fallbackExtractor,
            boolean strictSemanticRequirement) {
        List<WorkProfileObservation> relevantObservations = observations.stream()
                .filter(observationFilter)
                .toList();
        Set<LocalDate> coveredDays = new LinkedHashSet<>();
        Set<String> sourceKeys = new LinkedHashSet<>();
        Set<String> fallbackSourceKeys = new LinkedHashSet<>();
        List<String> evidenceIds = new ArrayList<>();
        int knownValueCount = 0;
        int unknownValueCount = 0;
        int fallbackValueCount = 0;

        for (WorkProfileObservation observation : relevantObservations) {
            coveredDays.add(toLocalDate(observation.timestampMs()));
            String value = valueExtractor.apply(observation);
            if (!StringUtils.hasText(value) || "UNKNOWN".equalsIgnoreCase(value)) {
                unknownValueCount++;
                continue;
            }

            knownValueCount++;
            String sourceKey = sourceExtractor.apply(observation);
            if (StringUtils.hasText(sourceKey)) {
                sourceKeys.add(sourceKey.trim());
            }
            if (fallbackExtractor.test(observation)) {
                fallbackValueCount++;
                if (StringUtils.hasText(sourceKey)) {
                    fallbackSourceKeys.add(sourceKey.trim());
                }
            }
            if (evidenceIds.size() < MAX_FIELD_EVIDENCE_IDS) {
                evidenceIds.add(observation.observationId());
            }
        }

        double fallbackRate = knownValueCount == 0 ? 1.0d : round(totalAsDouble(fallbackValueCount) / knownValueCount, 4);
        double unknownRate = relevantObservations.isEmpty()
                ? 1.0d
                : round(totalAsDouble(unknownValueCount) / relevantObservations.size(), 4);
        int qualityScore = assessQualityScore(relevantObservations.size(), coveredDays.size(), fallbackRate, unknownRate, strictSemanticRequirement);
        ContextQualityGrade qualityGrade = resolveGrade(qualityScore);

        return ContextFieldTrustRecord.builder()
                .fieldPath(fieldPath)
                .semanticMeaning(semanticMeaning)
                .intendedUse(intendedUse)
                .provenanceSummary(buildFieldProvenanceSummary(
                        relevantObservations.size(),
                        coveredDays.size(),
                        sourceKeys,
                        fallbackSourceKeys,
                        fallbackRate,
                        unknownRate))
                .observationCount(relevantObservations.size())
                .daysCovered(coveredDays.size())
                .fallbackRate(fallbackRate)
                .unknownRate(unknownRate)
                .qualityGrade(qualityGrade)
                .qualityScore(qualityScore)
                .qualitySummary(buildQualitySummary(qualityGrade, relevantObservations.size(), coveredDays.size(), fallbackRate, unknownRate))
                .sourceKeys(new ArrayList<>(sourceKeys))
                .fallbackSourceKeys(new ArrayList<>(fallbackSourceKeys))
                .evidenceIds(evidenceIds)
                .build();
    }

    private int assessQualityScore(
            int observationCount,
            int daysCovered,
            double fallbackRate,
            double unknownRate,
            boolean strictSemanticRequirement) {
        if (observationCount == 0) {
            return 0;
        }

        int score = 100;
        if (observationCount < 5) {
            score -= 40;
        }
        else if (observationCount < 10) {
            score -= 25;
        }
        else if (observationCount < 20) {
            score -= 10;
        }

        if (daysCovered < 2) {
            score -= 20;
        }
        else if (daysCovered < 4) {
            score -= 10;
        }

        if (fallbackRate >= 0.5d) {
            score -= 35;
        }
        else if (fallbackRate >= 0.25d) {
            score -= 20;
        }
        else if (fallbackRate > 0.0d) {
            score -= 8;
        }

        if (unknownRate >= 0.5d) {
            score -= 40;
        }
        else if (unknownRate >= 0.25d) {
            score -= 20;
        }
        else if (unknownRate > 0.0d) {
            score -= 8;
        }

        if (strictSemanticRequirement && fallbackRate > 0.65d) {
            score = Math.min(score, 35);
        }
        if (strictSemanticRequirement && unknownRate > 0.65d) {
            score = Math.min(score, 25);
        }
        return Math.max(0, score);
    }

    private ContextQualityGrade resolveGrade(int score) {
        if (score >= 80) {
            return ContextQualityGrade.STRONG;
        }
        if (score >= 60) {
            return ContextQualityGrade.MODERATE;
        }
        if (score >= 40) {
            return ContextQualityGrade.WEAK;
        }
        return ContextQualityGrade.REJECTED;
    }

    private int averageQualityScore(List<ContextFieldTrustRecord> fieldRecords) {
        if (fieldRecords.isEmpty()) {
            return 0;
        }
        return (int) Math.round(fieldRecords.stream()
                .map(ContextFieldTrustRecord::getQualityScore)
                .filter(score -> score != null)
                .mapToInt(Integer::intValue)
                .average()
                .orElse(0.0d));
    }

    private void appendQualityWarning(List<String> warnings, ContextFieldTrustRecord fieldRecord) {
        if (!ContextSemanticBoundaryPolicy.requiresEvidenceCaution(fieldRecord)) {
            return;
        }
        warnings.add(fieldRecord.getFieldPath()
                + " has thin or fallback-heavy evidence; " + fieldRecord.getQualitySummary());
    }

    private String buildTrustProfileSummary(
            ContextQualityGrade overallGrade,
            int observationCount,
            int daysCovered,
            List<String> frequentProtectableResources,
            List<String> frequentActionFamilies,
            Double protectableInvocationDensity) {
        StringJoiner joiner = new StringJoiner(" | ");
        joiner.add("Observations " + observationCount);
        joiner.add("Days covered " + daysCovered);
        if (!frequentProtectableResources.isEmpty()) {
            joiner.add("Resources " + String.join(", ", frequentProtectableResources));
        }
        if (!frequentActionFamilies.isEmpty()) {
            joiner.add("Actions " + String.join(", ", frequentActionFamilies));
        }
        if (protectableInvocationDensity != null) {
            joiner.add(String.format(Locale.ROOT, "Protectable density %.2f", protectableInvocationDensity));
        }
        return joiner.toString();
    }

    private String buildTrustProfileProvenanceSummary(
            int observationCount,
            int daysCovered,
            int windowDays,
            ContextFieldTrustRecord resourceField,
            ContextFieldTrustRecord actionField) {
        return String.format(
                Locale.ROOT,
                "collector=%s,window=%dd,observations=%d,daysCovered=%d,resourceSources=%s,actionSources=%s,resourceFallback=%.0f%%,actionFallback=%.0f%%",
                COLLECTOR_ID,
                windowDays,
                observationCount,
                daysCovered,
                joinStrings(resourceField.getSourceKeys()),
                joinStrings(actionField.getSourceKeys()),
                percentage(resourceField.getFallbackRate()),
                percentage(actionField.getFallbackRate()));
    }

    private String buildFieldProvenanceSummary(
            int observationCount,
            int daysCovered,
            Collection<String> sourceKeys,
            Collection<String> fallbackSourceKeys,
            double fallbackRate,
            double unknownRate) {
        return String.format(
                Locale.ROOT,
                "observations=%d,daysCovered=%d,sources=%s,fallbackSources=%s,fallback=%.0f%%,unknown=%.0f%%",
                observationCount,
                daysCovered,
                joinStrings(sourceKeys),
                joinStrings(fallbackSourceKeys),
                percentage(fallbackRate),
                percentage(unknownRate));
    }

    private String buildQualitySummary(
            ContextQualityGrade qualityGrade,
            int observationCount,
            int daysCovered,
            double fallbackRate,
            double unknownRate) {
        StringJoiner joiner = new StringJoiner(" | ");
        joiner.add("observations=" + observationCount);
        joiner.add("daysCovered=" + daysCovered);
        joiner.add(String.format(Locale.ROOT, "fallback=%.0f%%", percentage(fallbackRate)));
        joiner.add(String.format(Locale.ROOT, "unknown=%.0f%%", percentage(unknownRate)));
        joiner.add("evidenceState=" + ContextSemanticBoundaryPolicy.describeEvidenceState(
                qualityGrade,
                observationCount,
                daysCovered,
                fallbackRate,
                unknownRate));
        return joiner.toString();
    }

    private ContextEvidenceRecord toEvidenceRecord(WorkProfileObservation observation) {
        Map<String, String> sourceKeys = new LinkedHashMap<>();
        putIfText(sourceKeys, "requestPath", observation.requestPathSourceKey());
        putIfText(sourceKeys, "resourceFamily", observation.resourceFamilySourceKey());
        putIfText(sourceKeys, "actionFamily", observation.actionFamilySourceKey());
        putIfText(sourceKeys, "sensitivity", observation.sensitivitySourceKey());
        putIfText(sourceKeys, "protectable", observation.protectableSourceKey());

        List<String> flags = new ArrayList<>();
        appendFlag(flags, "requestPathFallback", observation.requestPathFallback());
        appendFlag(flags, "resourceFamilyFallback", observation.resourceFamilyFallback());
        appendFlag(flags, "actionFamilyFallback", observation.actionFamilyFallback());
        appendFlag(flags, "sensitivityFallback", observation.sensitivityFallback());
        appendFlag(flags, "protectableFallback", observation.protectableFallback());

        return ContextEvidenceRecord.builder()
                .evidenceId(observation.observationId())
                .observedAt(Instant.ofEpochMilli(observation.timestampMs()).toString())
                .summary(buildEvidenceSummary(observation))
                .decisionState(observation.decisionState())
                .protectable(observation.protectable())
                .sourceKeys(sourceKeys)
                .flags(flags)
                .build();
    }

    private String buildEvidenceSummary(WorkProfileObservation observation) {
        StringJoiner joiner = new StringJoiner(" | ");
        joiner.add(Instant.ofEpochMilli(observation.timestampMs()).toString());
        if (StringUtils.hasText(observation.decisionState())) {
            joiner.add(observation.decisionState());
        }
        if (observation.protectable() != null) {
            joiner.add(Boolean.TRUE.equals(observation.protectable()) ? "protectable" : "non-protectable");
        }
        if (StringUtils.hasText(observation.actionFamily())) {
            joiner.add(observation.actionFamily());
        }
        if (StringUtils.hasText(observation.requestPath())) {
            joiner.add(observation.requestPath());
        }
        if (StringUtils.hasText(observation.resourceFamily())) {
            joiner.add("resourceFamily=" + observation.resourceFamily());
        }
        if (StringUtils.hasText(observation.sensitivity())) {
            joiner.add("sensitivity=" + observation.sensitivity());
        }
        return joiner.toString();
    }

    private WorkProfileObservation createObservation(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        long timestampMs = resolveTimestamp(event);
        ResolvedSignal requestPath = resolveRequestPath(metadata);
        if (StringUtils.hasText(requestPath.value())
                && !PromptRelevantRequestPathPolicy.isPromptRelevantPath(requestPath.value())) {
            return null;
        }
        ResolvedSignal resourceFamily = resolveResourceFamily(metadata);
        ResolvedSignal actionFamily = resolveActionFamily(event);
        ResolvedSignal sensitivity = resolveSensitivity(metadata);
        String decisionState = resolveDecisionState(event);
        ResolvedBoolean protectable = resolveProtectable(metadata);

        if (requestPath.value() == null
                && resourceFamily.value() == null
                && actionFamily.value() == null
                && sensitivity.value() == null
                && protectable.value() == null) {
            return null;
        }

        return new WorkProfileObservation(
                resolveObservationId(event, timestampMs, requestPath.value(), actionFamily.value(), decisionState),
                timestampMs,
                requestPath.value(),
                requestPath.sourceKey(),
                requestPath.fallback(),
                resourceFamily.value(),
                resourceFamily.sourceKey(),
                resourceFamily.fallback(),
                actionFamily.value(),
                actionFamily.sourceKey(),
                actionFamily.fallback(),
                sensitivity.value(),
                sensitivity.sourceKey(),
                sensitivity.fallback(),
                decisionState,
                protectable.value(),
                protectable.sourceKey(),
                protectable.fallback(),
                resolvePathTemplate(metadata),
                resolveSessionKey(event),
                resolveRequestedItems(metadata));
    }

    /** How many items the request asks for, as the host counted them; null when it did not say (W2-6). */
    private Integer resolveRequestedItems(Map<String, Object> metadata) {
        Object value = metadata != null ? metadata.get("requestItems") : null;
        if (value instanceof Number number) {
            return number.intValue() > 0 ? number.intValue() : null;
        }
        if (value != null && StringUtils.hasText(value.toString())) {
            try {
                int items = Integer.parseInt(value.toString().trim());
                return items > 0 ? items : null;
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    /** The URL template the host matched for this request, kept to bind the request's targets (W2-3). */
    private String resolvePathTemplate(Map<String, Object> metadata) {
        return firstText(
                metadata != null ? metadata.get("protectableResourceUrl") : null,
                metadata != null ? metadata.get("resourceUrlTemplate") : null);
    }

    /** A key of the request's session; the session id itself is not stored with the observations. */
    private String resolveSessionKey(SecurityEvent event) {
        return sessionKey(event.getSessionId());
    }

    private static String sessionKey(String sessionId) {
        if (!StringUtils.hasText(sessionId)) {
            return null;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(sessionId.trim().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 12);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * The keys the request's session is observed under: its current key and the keys of the ids it had before its
     * id was replaced (P2 correction 5), so the activity period being judged is left out whole.
     */
    private List<String> sessionKeysOf(SecurityEvent event, String currentKey) {
        if (currentKey == null) {
            return List.of();
        }
        List<String> keys = new ArrayList<>();
        keys.add(currentKey);
        List<String> previous = dataStore != null ? dataStore.getSessionPreviousIds(event.getSessionId()) : null;
        if (previous != null) {
            previous.stream().map(DefaultProtectableWorkProfileCollector::sessionKey)
                    .filter(key -> key != null && !keys.contains(key)).forEach(keys::add);
        }
        return keys;
    }

    private long resolveTimestamp(SecurityEvent event) {
        if (event.getTimestamp() != null) {
            return event.getTimestamp().toEpochMilli();
        }
        return System.currentTimeMillis();
    }

    private String resolveTenantId(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        return firstText(
                metadata != null ? metadata.get("tenantId") : null,
                metadata != null ? metadata.get("tenant_id") : null,
                metadata != null ? metadata.get("organizationId") : null,
                metadata != null ? metadata.get("orgId") : null);
    }

    private String resolveObservationId(SecurityEvent event, long timestampMs, String requestPath, String actionFamily, String decisionState) {
        Map<String, Object> metadata = event.getMetadata();
        String fingerprint = String.join("|",
                safeText(firstText(event.getEventId(),
                        metadata != null ? metadata.get("correlationId") : null,
                        metadata != null ? metadata.get("executionId") : null,
                        event.getSessionId(),
                        event.getUserId(),
                        resolveTenantId(event),
                        Long.toString(timestampMs))),
                safeText(requestPath),
                safeText(actionFamily),
                safeText(decisionState),
                safeText(event.getDescription()));
        return UUID.nameUUIDFromBytes(fingerprint.getBytes(StandardCharsets.UTF_8)).toString();
    }

    private ResolvedSignal resolveRequestPath(Map<String, Object> metadata) {
        return resolveSignal(metadata,
                false,
                "requestPath",
                "protectableResource",
                true, "targetResource",
                true, "httpUri");
    }

    private ResolvedSignal resolveResourceFamily(Map<String, Object> metadata) {
        return resolveSignal(metadata,
                true,
                "currentResourceFamily",
                "resourceFamily",
                true, "resourceType",
                true, "resourceCategory");
    }

    /** The request's action family as the context gives it; a family the host did not declare is a fallback. */
    private ResolvedSignal resolveActionFamily(SecurityEvent event) {
        ActionFamilyResolver.Resolution action = ActionFamilyResolver.resolve(event.getMetadata());
        if (action.family() == ActionFamily.UNKNOWN) {
            return new ResolvedSignal(null, null, false);
        }
        return new ResolvedSignal(action.family().name(), action.sourceKey(), action.inferred());
    }

    private ResolvedSignal resolveSensitivity(Map<String, Object> metadata) {
        return resolveSignal(metadata,
                true,
                "resourceSensitivity",
                "sensitivity",
                true, "sensitivityLevel");
    }

    private ResolvedBoolean resolveProtectable(Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return new ResolvedBoolean(null, null, false);
        }

        Boolean explicitFlag = resolveBoolean(
                metadata.get("isProtectable"),
                metadata.get("protectable"),
                metadata.get("protectableRequest"));
        if (explicitFlag != null) {
            return new ResolvedBoolean(explicitFlag, "isProtectable", false);
        }

        if (metadata.get("protectableResource") != null) {
            return new ResolvedBoolean(true, "protectableResource", true);
        }

        if (metadata.containsKey("granted")
                && (metadata.containsKey("className") || metadata.containsKey("methodName"))) {
            return new ResolvedBoolean(true, "className+methodName", true);
        }

        Boolean sensitivityBased = resolveBoolean(
                metadata.get("isSensitiveResource"),
                metadata.get("privileged"),
                metadata.get("exportSensitive"));
        if (sensitivityBased != null) {
            return new ResolvedBoolean(sensitivityBased, "isSensitiveResource", true);
        }
        return new ResolvedBoolean(null, null, false);
    }

    private ResolvedSignal resolveSignal(Map<String, Object> metadata, boolean normalizeValueAsToken, Object... candidates) {
        if (metadata == null || candidates == null || candidates.length == 0) {
            return new ResolvedSignal(null, null, false);
        }
        for (int index = 0; index < candidates.length; index++) {
            Object candidate = candidates[index];
            if (!(candidate instanceof String key)) {
                continue;
            }
            boolean fallback = false;
            if (index > 0 && candidates[index - 1] instanceof Boolean previousFlag) {
                fallback = previousFlag;
            }
            String text = firstText(metadata.get(key));
            if (!StringUtils.hasText(text)) {
                continue;
            }
            return new ResolvedSignal(
                    normalizeValueAsToken ? normalizeToken(text) : text.trim(),
                    key,
                    fallback);
        }
        return new ResolvedSignal(null, null, false);
    }

    private String resolveDecisionState(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        if (event.isBlocked()) {
            return "DENIED";
        }

        Boolean granted = resolveBoolean(metadata != null ? metadata.get("granted") : null);
        if (granted != null) {
            return granted ? "ALLOWED" : "DENIED";
        }

        String decision = normalizeToken(firstText(
                metadata != null ? metadata.get("decisionResult") : null,
                metadata != null ? metadata.get("authorizationEffect") : null,
                metadata != null ? metadata.get("decision") : null));
        if (!StringUtils.hasText(decision)) {
            return "UNKNOWN";
        }
        if (decision.contains("ALLOW") || decision.contains("GRANT") || decision.contains("PERMIT")) {
            return "ALLOWED";
        }
        if (decision.contains("CHALLENGE") || decision.contains("ESCALATE") || decision.contains("REVIEW")) {
            return "REVIEW";
        }
        if (decision.contains("DENY") || decision.contains("BLOCK") || decision.contains("REJECT")) {
            return "DENIED";
        }
        return decision;
    }

    private boolean shouldPersist(WorkProfileObservation observation) {
        if (observation == null) {
            return false;
        }
        return switch (observation.decisionState()) {
            case "DENIED", "REVIEW" -> false;
            default -> true;
        };
    }

    private String serialize(WorkProfileObservation observation) {
        return SERIALIZATION_VERSION_V4
                + "|" + encodeNullable(observation.observationId())
                + "|" + observation.timestampMs()
                + "|" + encodeNullableBoolean(observation.protectable())
                + "|" + encodeNullable(observation.decisionState())
                + "|" + encodeNullable(observation.requestPath())
                + "|" + encodeNullable(observation.requestPathSourceKey())
                + "|" + encodeBoolean(observation.requestPathFallback())
                + "|" + encodeNullable(observation.resourceFamily())
                + "|" + encodeNullable(observation.resourceFamilySourceKey())
                + "|" + encodeBoolean(observation.resourceFamilyFallback())
                + "|" + encodeNullable(observation.actionFamily())
                + "|" + encodeNullable(observation.actionFamilySourceKey())
                + "|" + encodeBoolean(observation.actionFamilyFallback())
                + "|" + encodeNullable(observation.sensitivity())
                + "|" + encodeNullable(observation.sensitivitySourceKey())
                + "|" + encodeBoolean(observation.sensitivityFallback())
                + "|" + encodeNullable(observation.protectableSourceKey())
                + "|" + encodeBoolean(observation.protectableFallback())
                + "|" + encodeNullable(observation.pathTemplate())
                + "|" + encodeNullable(observation.sessionKey())
                + "|" + encodeNullable(observation.requestedItems() != null
                ? observation.requestedItems().toString() : null);
    }

    private WorkProfileObservation deserialize(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String[] parts = raw.split("\\|", -1);
        try {
            // v3 adds the URL template and the session key, v4 the item count; older observations read without them.
            boolean v4 = SERIALIZATION_VERSION_V4.equals(parts[0]) && parts.length == 22;
            boolean v3 = v4 || SERIALIZATION_VERSION_V3.equals(parts[0]) && parts.length == 21;
            if (v3 || SERIALIZATION_VERSION_V2.equals(parts[0]) && parts.length == 19) {
                return new WorkProfileObservation(
                        decodeNullable(parts[1]),
                        Long.parseLong(parts[2]),
                        decodeNullable(parts[5]),
                        decodeNullable(parts[6]),
                        decodeBoolean(parts[7]),
                        decodeNullable(parts[8]),
                        decodeNullable(parts[9]),
                        decodeBoolean(parts[10]),
                        ActionFamily.nameOrRaw(decodeNullable(parts[11])),
                        decodeNullable(parts[12]),
                        decodeBoolean(parts[13]),
                        decodeNullable(parts[14]),
                        decodeNullable(parts[15]),
                        decodeBoolean(parts[16]),
                        decodeNullable(parts[4]),
                        decodeNullableBoolean(parts[3]),
                        decodeNullable(parts[17]),
                        decodeBoolean(parts[18]),
                        v3 ? decodeNullable(parts[19]) : null,
                        v3 ? decodeNullable(parts[20]) : null,
                        v4 ? decodeItems(decodeNullable(parts[21])) : null);
            }
            if (parts.length == 7) {
                String fingerprint = String.join("|", parts);
                return new WorkProfileObservation(
                        UUID.nameUUIDFromBytes(fingerprint.getBytes(StandardCharsets.UTF_8)).toString(),
                        Long.parseLong(parts[0]),
                        decodeNullable(parts[3]),
                        "legacy",
                        false,
                        decodeNullable(parts[4]),
                        "legacy",
                        false,
                        ActionFamily.nameOrRaw(decodeNullable(parts[5])),
                        "legacy",
                        false,
                        decodeNullable(parts[6]),
                        "legacy",
                        false,
                        parts[2],
                        decodeNullableBoolean(parts[1]),
                        "legacy",
                        false,
                        null,
                        null,
                        null);
            }
        } catch (RuntimeException ignored) {
            return null;
        }
        return null;
    }

    private String encodeNullable(String value) {
        if (!StringUtils.hasText(value)) {
            return NULL_TOKEN;
        }
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private String decodeNullable(String value) {
        if (!StringUtils.hasText(value) || NULL_TOKEN.equals(value)) {
            return null;
        }
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    private String encodeBoolean(boolean value) {
        return value ? "1" : "0";
    }

    private boolean decodeBoolean(String value) {
        return "1".equals(value);
    }

    private String encodeNullableBoolean(Boolean value) {
        if (value == null) {
            return NULL_TOKEN;
        }
        return value ? "1" : "0";
    }

    private Boolean decodeNullableBoolean(String value) {
        if (!StringUtils.hasText(value) || NULL_TOKEN.equals(value)) {
            return null;
        }
        return "1".equals(value);
    }

    private List<String> topStringKeys(Map<String, Integer> counts, int limit) {
        if (counts.isEmpty()) {
            return List.of();
        }
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed()
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(limit)
                .map(Map.Entry::getKey)
                .toList();
    }

    private List<String> topHeatmap(Map<String, Integer> counts, int limit) {
        if (counts.isEmpty()) {
            return List.of();
        }
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed()
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(limit)
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .toList();
    }

    private String buildSummary(
            int observationCount,
            int windowDays,
            List<String> frequentProtectableResources,
            List<String> frequentActionFamilies,
            Double protectableInvocationDensity,
            List<Integer> normalAccessHours,
            int dayObservations) {
        StringJoiner joiner = new StringJoiner(" | ");
        joiner.add("Window " + windowDays + "d");
        joiner.add("Observations " + observationCount);
        if (windowDays != BaselineViewCalculator.DAY_OF_WEEK_DAYS) {
            // The usual days of the week read several weeks, so the prompt says which observations they count.
            joiner.add("Days of week from " + BaselineViewCalculator.DAY_OF_WEEK_DAYS + "d, " + dayObservations
                    + " observations");
        }
        boolean provisionalEvidence = observationCount < PROVISIONAL_OBSERVATION_THRESHOLD;
        if (provisionalEvidence) {
            joiner.add("Evidence state PROVISIONAL");
        }
        if (!frequentProtectableResources.isEmpty()) {
            joiner.add((provisionalEvidence ? "Observed protectable resources " : "Frequent protectable resources ")
                    + String.join(", ", frequentProtectableResources));
        }
        if (!frequentActionFamilies.isEmpty()) {
            joiner.add((provisionalEvidence ? "Observed action families " : "Frequent action families ")
                    + String.join(", ", frequentActionFamilies));
        }
        if (!normalAccessHours.isEmpty()) {
            joiner.add((provisionalEvidence ? "Observed access hours " : "Normal access hours ")
                    + joinIntegers(normalAccessHours));
        }
        if (protectableInvocationDensity != null) {
            joiner.add(String.format(Locale.ROOT, "Protectable density %.2f", protectableInvocationDensity));
        }
        return joiner.toString();
    }

    private String joinIntegers(Collection<Integer> values) {
        if (values == null || values.isEmpty()) {
            return "";
        }
        StringJoiner joiner = new StringJoiner(", ");
        for (Integer value : values) {
            if (value != null) {
                joiner.add(Integer.toString(value));
            }
        }
        return joiner.toString();
    }

    private String joinStrings(Collection<String> values) {
        if (values == null || values.isEmpty()) {
            return "none";
        }
        return String.join(", ", values);
    }

    private double percentage(Double rate) {
        if (rate == null) {
            return 0.0d;
        }
        return rate * 100.0d;
    }

    private Double round(double value, int scale) {
        double factor = Math.pow(10, scale);
        return Math.round(value * factor) / factor;
    }

    private double totalAsDouble(int value) {
        return value;
    }

    private LocalDate toLocalDate(long timestampMs) {
        return Instant.ofEpochMilli(timestampMs)
                .atZone(EventTimeZone.get())
                .toLocalDate();
    }

    private void putIfText(Map<String, String> values, String key, String value) {
        if (StringUtils.hasText(key) && StringUtils.hasText(value)) {
            values.put(key, value);
        }
    }

    private void appendFlag(List<String> flags, String flag, boolean enabled) {
        if (enabled) {
            flags.add(flag);
        }
    }

    private String normalizeToken(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        return value.trim()
                .replace(' ', '_')
                .replace('-', '_')
                .toUpperCase(Locale.ROOT);
    }

    private String firstText(Object... candidates) {
        if (candidates == null) {
            return null;
        }
        for (Object candidate : candidates) {
            if (candidate == null) {
                continue;
            }
            if (candidate instanceof Collection<?> collection && !collection.isEmpty()) {
                Object first = collection.iterator().next();
                if (first != null && StringUtils.hasText(first.toString())) {
                    return first.toString().trim();
                }
                continue;
            }
            String text = candidate.toString().trim();
            if (StringUtils.hasText(text)) {
                return text;
            }
        }
        return null;
    }

    private String safeText(String value) {
        return StringUtils.hasText(value) ? value : "";
    }

    private Boolean resolveBoolean(Object... candidates) {
        return MetadataValueResolver.resolveBoolean(candidates);
    }

    private record ResolvedSignal(String value, String sourceKey, boolean fallback) {
    }

    private record ResolvedBoolean(Boolean value, String sourceKey, boolean fallback) {
    }

    private record WorkProfileObservation(
            String observationId,
            long timestampMs,
            String requestPath,
            String requestPathSourceKey,
            boolean requestPathFallback,
            String resourceFamily,
            String resourceFamilySourceKey,
            boolean resourceFamilyFallback,
            String actionFamily,
            String actionFamilySourceKey,
            boolean actionFamilyFallback,
            String sensitivity,
            String sensitivitySourceKey,
            boolean sensitivityFallback,
            String decisionState,
            Boolean protectable,
            String protectableSourceKey,
            boolean protectableFallback,
            String pathTemplate,
            String sessionKey,
            Integer requestedItems) {
    }

    private static Integer decodeItems(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        try {
            return Integer.valueOf(value);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }
}
