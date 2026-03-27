package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Comparator;
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

public class DefaultRoleScopeCollector implements RoleScopeCollector {

    private static final int HISTORY_SCAN_LIMIT = 5_000;
    private static final int PERMISSION_CHANGE_SCAN_LIMIT = 200;
    private static final int TOP_FAMILY_LIMIT = 6;
    private static final int TOP_PATTERN_LIMIT = 4;
    private static final int TOP_PERMISSION_CHANGE_LIMIT = 5;
    private static final int ROLE_SCOPE_WINDOW_DAYS = 30;
    private static final int DEFAULT_ELEVATED_WINDOW_MINUTES = 60;
    private static final int MAX_EVIDENCE_RECORDS = 4;
    private static final int MAX_FIELD_EVIDENCE_IDS = 6;
    private static final String NULL_TOKEN = "~";
    private static final String OBSERVATION_VERSION_V1 = "v1";
    private static final String PERMISSION_CHANGE_VERSION_V1 = "p1";
    private static final String AUTHORIZATION_STATE_VERSION_V1 = "a1";
    private static final String PROFILE_KEY = "ROLE_SCOPE_PROFILE";
    private static final String COLLECTOR_ID = "ROLE_SCOPE_COLLECTOR";

    private final SecurityContextDataStore dataStore;

    public DefaultRoleScopeCollector(SecurityContextDataStore dataStore) {
        this.dataStore = dataStore;
    }

    @Override
    public Optional<RoleScopeSnapshot> collect(SecurityEvent event) {
        if (event == null || !StringUtils.hasText(event.getUserId())) {
            return Optional.empty();
        }

        AuthorizationScopeState authorizationScopeState = resolveAuthorizationScopeState(event.getMetadata());
        if (authorizationScopeState == null || !authorizationScopeState.hasMaterialIdentity()) {
            return Optional.empty();
        }

        RoleScopeObservation currentObservation = createObservation(event, authorizationScopeState);
        if (currentObservation == null) {
            return Optional.empty();
        }

        String tenantId = resolveTenantId(event);
        String userId = event.getUserId().trim();
        long currentTimestampMs = currentObservation.timestampMs();

        List<RoleScopeObservation> history = loadHistory(tenantId, authorizationScopeState.scopeKey(), currentTimestampMs);
        List<PermissionChangeObservation> storedPermissionChanges = loadPermissionChanges(tenantId, userId, currentTimestampMs);
        CurrentRoleScopeHints currentHints = resolveCurrentHints(event);
        List<PermissionChangeObservation> currentPermissionChanges = detectCurrentPermissionChanges(
                event,
                authorizationScopeState,
                currentHints,
                storedPermissionChanges,
                tenantId,
                userId,
                currentTimestampMs);
        List<PermissionChangeObservation> effectivePermissionChanges = mergePermissionChanges(storedPermissionChanges, currentPermissionChanges);

        Optional<RoleScopeSnapshot> snapshot = buildSnapshot(
                currentObservation,
                history,
                effectivePermissionChanges,
                authorizationScopeState,
                currentHints,
                currentTimestampMs);

        if (shouldPersist(currentObservation)) {
            dataStore.addRoleScopeObservation(tenantId, authorizationScopeState.scopeKey(), serializeObservation(currentObservation));
        }
        for (PermissionChangeObservation permissionChange : currentPermissionChanges) {
            dataStore.addPermissionChangeObservation(tenantId, userId, serializePermissionChange(permissionChange));
        }
        dataStore.setAuthorizationScopeState(tenantId, userId, serializeAuthorizationState(authorizationScopeState));

        return snapshot;
    }

    private Optional<RoleScopeSnapshot> buildSnapshot(
            RoleScopeObservation currentObservation,
            List<RoleScopeObservation> history,
            List<PermissionChangeObservation> permissionChanges,
            AuthorizationScopeState authorizationScopeState,
            CurrentRoleScopeHints currentHints,
            long currentTimestampMs) {
        List<RoleScopeObservation> allowedObservations = history.stream()
                .filter(observation -> "ALLOWED".equals(observation.decisionState()))
                .toList();
        List<RoleScopeObservation> deniedObservations = history.stream()
                .filter(observation -> "DENIED".equals(observation.decisionState()))
                .toList();

        List<String> expectedResourceFamilies = mergeDistinct(
                topStringKeys(allowedObservations, RoleScopeObservation::resourceFamily, TOP_FAMILY_LIMIT),
                currentHints.expectedResourceFamilies());
        List<String> expectedActionFamilies = mergeDistinct(
                topStringKeys(allowedObservations, RoleScopeObservation::actionFamily, TOP_FAMILY_LIMIT),
                currentHints.expectedActionFamilies());
        List<String> forbiddenResourceFamilies = mergeDistinct(
                topStringKeys(deniedObservations, RoleScopeObservation::resourceFamily, TOP_FAMILY_LIMIT),
                currentHints.forbiddenResourceFamilies());
        List<String> forbiddenActionFamilies = mergeDistinct(
                topStringKeys(deniedObservations, RoleScopeObservation::actionFamily, TOP_FAMILY_LIMIT),
                currentHints.forbiddenActionFamilies());
        List<String> normalApprovalPatterns = mergeDistinct(
                topStringKeys(allowedObservations, RoleScopeObservation::approvalPattern, TOP_PATTERN_LIMIT),
                currentHints.normalApprovalPatterns());
        List<String> normalEscalationPatterns = mergeDistinct(
                topStringKeys(history, RoleScopeObservation::escalationPattern, TOP_PATTERN_LIMIT),
                currentHints.normalEscalationPatterns());
        List<String> recentPermissionChanges = permissionChanges.stream()
                .sorted(Comparator.comparingLong(PermissionChangeObservation::timestampMs).reversed())
                .map(PermissionChangeObservation::summary)
                .filter(StringUtils::hasText)
                .distinct()
                .limit(TOP_PERMISSION_CHANGE_LIMIT)
                .toList();

        Boolean resourceFamilyDrift = computeComparisonMismatch(currentObservation.resourceFamily(), expectedResourceFamilies, forbiddenResourceFamilies);
        Boolean actionFamilyDrift = computeComparisonMismatch(currentObservation.actionFamily(), expectedActionFamilies, forbiddenActionFamilies);
        PermissionChangeObservation activePermissionChange = resolveActivePermissionChange(permissionChanges, currentTimestampMs);
        Boolean temporaryElevation = firstNonNull(currentHints.temporaryElevation(), activePermissionChange != null ? Boolean.TRUE : null);
        Boolean elevatedPrivilegeWindowActive = activePermissionChange != null;
        String temporaryElevationReason = firstText(
                currentHints.temporaryElevationReason(),
                activePermissionChange != null ? activePermissionChange.reason() : null,
                activePermissionChange != null ? activePermissionChange.summary() : null);
        String elevationWindowSummary = buildElevationWindowSummary(activePermissionChange, currentTimestampMs);

        if (expectedResourceFamilies.isEmpty()
                && expectedActionFamilies.isEmpty()
                && forbiddenResourceFamilies.isEmpty()
                && forbiddenActionFamilies.isEmpty()
                && recentPermissionChanges.isEmpty()
                && !StringUtils.hasText(currentObservation.resourceFamily())
                && !StringUtils.hasText(currentObservation.actionFamily())) {
            return Optional.empty();
        }

        ContextTrustProfile trustProfile = buildTrustProfile(
                allowedObservations,
                deniedObservations,
                permissionChanges,
                currentHints,
                authorizationScopeState,
                expectedResourceFamilies,
                expectedActionFamilies,
                forbiddenResourceFamilies,
                forbiddenActionFamilies,
                recentPermissionChanges,
                currentTimestampMs);

        return Optional.of(RoleScopeSnapshot.builder()
                .summary(buildSummary(
                        authorizationScopeState.scopeSummary(),
                        currentObservation.resourceFamily(),
                        currentObservation.actionFamily(),
                        expectedResourceFamilies,
                        expectedActionFamilies,
                        forbiddenResourceFamilies,
                        forbiddenActionFamilies,
                        recentPermissionChanges,
                        elevatedPrivilegeWindowActive))
                .currentResourceFamily(currentObservation.resourceFamily())
                .currentActionFamily(currentObservation.actionFamily())
                .expectedResourceFamilies(expectedResourceFamilies)
                .expectedActionFamilies(expectedActionFamilies)
                .forbiddenResourceFamilies(forbiddenResourceFamilies)
                .forbiddenActionFamilies(forbiddenActionFamilies)
                .normalApprovalPatterns(normalApprovalPatterns)
                .normalEscalationPatterns(normalEscalationPatterns)
                .recentPermissionChanges(recentPermissionChanges)
                .resourceFamilyDrift(resourceFamilyDrift)
                .actionFamilyDrift(actionFamilyDrift)
                .temporaryElevation(temporaryElevation)
                .temporaryElevationReason(temporaryElevationReason)
                .elevatedPrivilegeWindowActive(elevatedPrivilegeWindowActive)
                .elevationWindowSummary(elevationWindowSummary)
                .trustProfile(trustProfile)
                .build());
    }

    private ContextTrustProfile buildTrustProfile(
            List<RoleScopeObservation> allowedObservations,
            List<RoleScopeObservation> deniedObservations,
            List<PermissionChangeObservation> permissionChanges,
            CurrentRoleScopeHints currentHints,
            AuthorizationScopeState authorizationScopeState,
            List<String> expectedResourceFamilies,
            List<String> expectedActionFamilies,
            List<String> forbiddenResourceFamilies,
            List<String> forbiddenActionFamilies,
            List<String> recentPermissionChanges,
            long currentTimestampMs) {
        ContextFieldTrustRecord expectedResourceField = buildRoleScopeFieldRecord(
                "roleScope.expectedResourceFamilies",
                "Resource families exercised under the current authorization scope.",
                "Compare the current resource family against role-scoped historical reach.",
                allowedObservations,
                RoleScopeObservation::resourceFamily,
                RoleScopeObservation::resourceFamilySourceKey,
                RoleScopeObservation::resourceFamilyFallback,
                currentHints.expectedResourceFamilies(),
                currentHints.expectedResourceFamiliesSourceKey(),
                currentHints.expectedResourceFamiliesFallback(),
                true);
        ContextFieldTrustRecord expectedActionField = buildRoleScopeFieldRecord(
                "roleScope.expectedActionFamilies",
                "Action families exercised under the current authorization scope.",
                "Compare the current action family against role-scoped historical execution.",
                allowedObservations,
                RoleScopeObservation::actionFamily,
                RoleScopeObservation::actionFamilySourceKey,
                RoleScopeObservation::actionFamilyFallback,
                currentHints.expectedActionFamilies(),
                currentHints.expectedActionFamiliesSourceKey(),
                currentHints.expectedActionFamiliesFallback(),
                true);
        ContextFieldTrustRecord forbiddenResourceField = buildRoleScopeFieldRecord(
                "roleScope.forbiddenResourceFamilies",
                "Resource families explicitly denied or blocked under the same authorization scope.",
                "Use as negative scope evidence, not as a complete tenant policy graph.",
                deniedObservations,
                RoleScopeObservation::resourceFamily,
                RoleScopeObservation::resourceFamilySourceKey,
                RoleScopeObservation::resourceFamilyFallback,
                currentHints.forbiddenResourceFamilies(),
                currentHints.forbiddenResourceFamiliesSourceKey(),
                currentHints.forbiddenResourceFamiliesFallback(),
                false);
        ContextFieldTrustRecord forbiddenActionField = buildRoleScopeFieldRecord(
                "roleScope.forbiddenActionFamilies",
                "Action families explicitly denied or blocked under the same authorization scope.",
                "Use as negative scope evidence, not as a complete tenant policy graph.",
                deniedObservations,
                RoleScopeObservation::actionFamily,
                RoleScopeObservation::actionFamilySourceKey,
                RoleScopeObservation::actionFamilyFallback,
                currentHints.forbiddenActionFamilies(),
                currentHints.forbiddenActionFamiliesSourceKey(),
                currentHints.forbiddenActionFamiliesFallback(),
                false);
        ContextFieldTrustRecord permissionChangeField = buildPermissionChangeFieldRecord(
                permissionChanges,
                recentPermissionChanges,
                currentHints,
                currentTimestampMs);

        List<ContextFieldTrustRecord> fieldRecords = List.of(
                expectedResourceField,
                expectedActionField,
                forbiddenResourceField,
                forbiddenActionField,
                permissionChangeField);
        int overallScore = averageQualityScore(fieldRecords);
        if (ContextSemanticBoundaryPolicy.requiresEvidenceCaution(expectedResourceField)
                || ContextSemanticBoundaryPolicy.requiresEvidenceCaution(expectedActionField)) {
            overallScore = Math.min(overallScore, 55);
        }
        if (expectedResourceField.getQualityGrade() == ContextQualityGrade.REJECTED
                || expectedActionField.getQualityGrade() == ContextQualityGrade.REJECTED) {
            overallScore = Math.min(overallScore, 30);
        }
        ContextQualityGrade overallGrade = resolveGrade(overallScore);

        List<String> qualityWarnings = new ArrayList<>();
        appendQualityWarning(qualityWarnings, expectedResourceField);
        appendQualityWarning(qualityWarnings, expectedActionField);
        appendQualityWarning(qualityWarnings, permissionChangeField);
        if (allowedObservations.size() < 3 && currentHints.expectedResourceFamilies().isEmpty() && currentHints.expectedActionFamilies().isEmpty()) {
            qualityWarnings.add("Role scope baseline is thin; treat expected scope as provisional until more authorized observations accumulate.");
        }
        if (!forbiddenResourceFamilies.isEmpty() || !forbiddenActionFamilies.isEmpty()) {
            qualityWarnings.add("Forbidden families reflect observed denied scope or explicit blocked hints, not the complete tenant authorization graph.");
        }
        if (!expectedActionField.getFallbackSourceKeys().isEmpty()) {
            qualityWarnings.add("Expected action family baseline includes fallback-derived semantics; confirm intent with approval lineage or delegated objective.");
        }
        qualityWarnings.add("This profile describes enacted or denied authorization scope after authentication, not the full tenant policy graph or business objective by itself.");

        return ContextTrustProfile.builder()
                .profileKey(PROFILE_KEY)
                .collectorId(COLLECTOR_ID)
                .summary(buildTrustSummary(
                        overallGrade,
                        allowedObservations.size(),
                        deniedObservations.size(),
                        expectedResourceFamilies,
                        expectedActionFamilies,
                        recentPermissionChanges))
                .provenanceSummary(buildProvenanceSummary(
                        authorizationScopeState,
                        allowedObservations.size(),
                        deniedObservations.size(),
                        permissionChanges.size()))
                .overallQualityGrade(overallGrade)
                .overallQualityScore(overallScore)
                .scopeLimitations(List.of(
                        "Use this profile to understand role-scoped reach and recent permission-change evidence after authorization, not to infer human purpose by itself.",
                        "Approval lineage, delegated objective, and business intent still require friction, delegation, or enterprise memory context."))
                .qualityWarnings(qualityWarnings)
                .fieldRecords(fieldRecords)
                .evidenceRecords(buildEvidenceRecords(
                        allowedObservations,
                        deniedObservations,
                        permissionChanges,
                        authorizationScopeState))
                .build();
    }

    private ContextFieldTrustRecord buildRoleScopeFieldRecord(
            String fieldPath,
            String semanticMeaning,
            String intendedUse,
            List<RoleScopeObservation> observations,
            Function<RoleScopeObservation, String> valueExtractor,
            Function<RoleScopeObservation, String> sourceExtractor,
            Predicate<RoleScopeObservation> fallbackExtractor,
            List<String> explicitValues,
            String explicitSourceKey,
            boolean explicitFallback,
            boolean strictSemanticRequirement) {
        Set<LocalDate> coveredDays = new LinkedHashSet<>();
        Set<String> sourceKeys = new LinkedHashSet<>();
        Set<String> fallbackSourceKeys = new LinkedHashSet<>();
        List<String> evidenceIds = new ArrayList<>();
        int knownValueCount = 0;
        int unknownValueCount = 0;
        int fallbackValueCount = 0;

        for (RoleScopeObservation observation : observations) {
            coveredDays.add(toLocalDate(observation.timestampMs()));
            String value = valueExtractor.apply(observation);
            if (!StringUtils.hasText(value) || "UNKNOWN".equalsIgnoreCase(value)) {
                unknownValueCount++;
                continue;
            }
            knownValueCount++;
            addIfText(sourceKeys, sourceExtractor.apply(observation));
            if (fallbackExtractor.test(observation)) {
                fallbackValueCount++;
                addIfText(fallbackSourceKeys, sourceExtractor.apply(observation));
            }
            if (evidenceIds.size() < MAX_FIELD_EVIDENCE_IDS) {
                evidenceIds.add(observation.observationId());
            }
        }

        if (!explicitValues.isEmpty()) {
            knownValueCount++;
            addIfText(sourceKeys, explicitSourceKey);
            if (explicitFallback) {
                fallbackValueCount++;
                addIfText(fallbackSourceKeys, explicitSourceKey);
            }
            if (evidenceIds.size() < MAX_FIELD_EVIDENCE_IDS) {
                evidenceIds.add("current-explicit");
            }
        }

        int observationCount = observations.size() + (!explicitValues.isEmpty() ? 1 : 0);
        if (observationCount == 0) {
            observationCount = 1;
            unknownValueCount = 1;
        }

        double fallbackRate = (double) fallbackValueCount / observationCount;
        double unknownRate = (double) unknownValueCount / observationCount;
        int qualityScore = 82;
        if (observations.size() < 3) {
            qualityScore -= 18;
        }
        if (coveredDays.size() < 2) {
            qualityScore -= 10;
        }
        if (unknownRate > 0.5d) {
            qualityScore -= 30;
        }
        else if (unknownRate > 0.2d) {
            qualityScore -= 15;
        }
        if (fallbackRate > 0.5d) {
            qualityScore -= 20;
        }
        else if (fallbackRate > 0.2d) {
            qualityScore -= 10;
        }
        if (!explicitValues.isEmpty() && !explicitFallback) {
            qualityScore += 8;
        }
        if (strictSemanticRequirement && knownValueCount == 0) {
            qualityScore = 20;
        }
        qualityScore = Math.max(0, Math.min(95, qualityScore));
        ContextQualityGrade qualityGrade = resolveGrade(qualityScore);

        return ContextFieldTrustRecord.builder()
                .fieldPath(fieldPath)
                .semanticMeaning(semanticMeaning)
                .intendedUse(intendedUse)
                .provenanceSummary(buildFieldProvenanceSummary(
                        observations.size(),
                        coveredDays.size(),
                        sourceKeys,
                        explicitSourceKey,
                        !explicitValues.isEmpty()))
                .observationCount(observationCount)
                .daysCovered(Math.max(coveredDays.size(), !explicitValues.isEmpty() ? 1 : 0))
                .fallbackRate(round(fallbackRate, 2))
                .unknownRate(round(unknownRate, 2))
                .qualityGrade(qualityGrade)
                .qualityScore(qualityScore)
                .qualitySummary(buildQualitySummary(qualityGrade, observationCount, coveredDays.size(), fallbackRate, unknownRate))
                .sourceKeys(List.copyOf(sourceKeys))
                .fallbackSourceKeys(List.copyOf(fallbackSourceKeys))
                .evidenceIds(List.copyOf(evidenceIds))
                .build();
    }

    private ContextFieldTrustRecord buildPermissionChangeFieldRecord(
            List<PermissionChangeObservation> permissionChanges,
            List<String> recentPermissionChanges,
            CurrentRoleScopeHints currentHints,
            long currentTimestampMs) {
        Set<LocalDate> coveredDays = new LinkedHashSet<>();
        Set<String> sourceKeys = new LinkedHashSet<>();
        Set<String> fallbackSourceKeys = new LinkedHashSet<>();
        List<String> evidenceIds = new ArrayList<>();
        int explicitCount = 0;
        int fallbackCount = 0;

        for (PermissionChangeObservation permissionChange : permissionChanges) {
            coveredDays.add(toLocalDate(permissionChange.timestampMs()));
            addCsvValues(sourceKeys, permissionChange.sourceKeySummary());
            if (permissionChange.fallback()) {
                fallbackCount++;
                addCsvValues(fallbackSourceKeys, permissionChange.sourceKeySummary());
            }
            if ("EXPLICIT".equals(permissionChange.changeType())) {
                explicitCount++;
            }
            if (evidenceIds.size() < MAX_FIELD_EVIDENCE_IDS) {
                evidenceIds.add(permissionChange.changeId());
            }
        }

        if (StringUtils.hasText(currentHints.temporaryElevationReason())) {
            explicitCount++;
            addIfText(sourceKeys, currentHints.temporaryElevationReasonSourceKey());
            if (currentHints.temporaryElevationReasonFallback()) {
                fallbackCount++;
                addIfText(fallbackSourceKeys, currentHints.temporaryElevationReasonSourceKey());
            }
        }

        int observationCount = Math.max(permissionChanges.size(), recentPermissionChanges.isEmpty() ? 0 : 1);
        if (observationCount == 0) {
            observationCount = 1;
        }
        double fallbackRate = (double) fallbackCount / observationCount;
        double unknownRate = recentPermissionChanges.isEmpty() ? 1.0d : 0.0d;
        int qualityScore = recentPermissionChanges.isEmpty() ? 28 : 78;
        if (!recentPermissionChanges.isEmpty()) {
            if (explicitCount == 0) {
                qualityScore -= 12;
            }
            if (coveredDays.isEmpty()) {
                qualityScore -= 8;
            }
            if (fallbackRate > 0.4d) {
                qualityScore -= 10;
            }
            PermissionChangeObservation activeChange = resolveActivePermissionChange(permissionChanges, currentTimestampMs);
            if (activeChange != null && "AUTH_SCOPE_CHANGE".equals(activeChange.changeType())) {
                qualityScore += 5;
            }
        }
        qualityScore = Math.max(0, Math.min(95, qualityScore));
        ContextQualityGrade qualityGrade = resolveGrade(qualityScore);

        return ContextFieldTrustRecord.builder()
                .fieldPath("roleScope.recentPermissionChanges")
                .semanticMeaning("Recent authorization scope changes that may explain temporary elevation or scope expansion.")
                .intendedUse("Use as recent permission-drift context, not as proof that the current request is legitimate.")
                .provenanceSummary("Permission-change context from explicit request hints or observed authorization-scope fingerprint changes.")
                .observationCount(observationCount)
                .daysCovered(Math.max(coveredDays.size(), recentPermissionChanges.isEmpty() ? 0 : 1))
                .fallbackRate(round(fallbackRate, 2))
                .unknownRate(round(unknownRate, 2))
                .qualityGrade(qualityGrade)
                .qualityScore(qualityScore)
                .qualitySummary(buildQualitySummary(qualityGrade, observationCount, coveredDays.size(), fallbackRate, unknownRate))
                .sourceKeys(List.copyOf(sourceKeys))
                .fallbackSourceKeys(List.copyOf(fallbackSourceKeys))
                .evidenceIds(List.copyOf(evidenceIds))
                .build();
    }

    private List<ContextEvidenceRecord> buildEvidenceRecords(
            List<RoleScopeObservation> allowedObservations,
            List<RoleScopeObservation> deniedObservations,
            List<PermissionChangeObservation> permissionChanges,
            AuthorizationScopeState authorizationScopeState) {
        List<RoleScopeObservation> observations = new ArrayList<>();
        observations.addAll(allowedObservations);
        observations.addAll(deniedObservations);
        observations = observations.stream()
                .sorted(Comparator.comparingLong(RoleScopeObservation::timestampMs).reversed())
                .limit(MAX_EVIDENCE_RECORDS)
                .toList();

        List<ContextEvidenceRecord> evidenceRecords = new ArrayList<>();
        for (RoleScopeObservation observation : observations) {
            Map<String, String> sourceKeys = new LinkedHashMap<>();
            putIfText(sourceKeys, "resourceFamily", observation.resourceFamilySourceKey());
            putIfText(sourceKeys, "actionFamily", observation.actionFamilySourceKey());
            List<String> flags = new ArrayList<>();
            appendFlag(flags, observation.decisionState(), true);
            appendFlag(flags, observation.approvalPattern(), StringUtils.hasText(observation.approvalPattern()));
            appendFlag(flags, observation.escalationPattern(), StringUtils.hasText(observation.escalationPattern()));
            evidenceRecords.add(ContextEvidenceRecord.builder()
                    .evidenceId(observation.observationId())
                    .observedAt(Instant.ofEpochMilli(observation.timestampMs()).toString())
                    .summary(buildObservationEvidenceSummary(observation, authorizationScopeState.scopeSummary()))
                    .decisionState(observation.decisionState())
                    .sourceKeys(sourceKeys)
                    .flags(flags)
                    .build());
        }
        for (PermissionChangeObservation permissionChange : permissionChanges.stream()
                .sorted(Comparator.comparingLong(PermissionChangeObservation::timestampMs).reversed())
                .limit(MAX_EVIDENCE_RECORDS)
                .toList()) {
            Map<String, String> sourceKeys = new LinkedHashMap<>();
            putIfText(sourceKeys, "permissionChange", permissionChange.sourceKeySummary());
            List<String> flags = new ArrayList<>();
            appendFlag(flags, permissionChange.changeType(), true);
            appendFlag(flags, "approval-linked", permissionChange.approvalLinked());
            evidenceRecords.add(ContextEvidenceRecord.builder()
                    .evidenceId(permissionChange.changeId())
                    .observedAt(Instant.ofEpochMilli(permissionChange.timestampMs()).toString())
                    .summary(permissionChange.summary())
                    .decisionState("PERMISSION_CHANGE")
                    .sourceKeys(sourceKeys)
                    .flags(flags)
                    .build());
        }
        return evidenceRecords.stream()
                .sorted((left, right) -> right.getObservedAt().compareTo(left.getObservedAt()))
                .limit(MAX_EVIDENCE_RECORDS)
                .toList();
    }

    private List<PermissionChangeObservation> detectCurrentPermissionChanges(
            SecurityEvent event,
            AuthorizationScopeState authorizationScopeState,
            CurrentRoleScopeHints currentHints,
            List<PermissionChangeObservation> storedPermissionChanges,
            String tenantId,
            String userId,
            long currentTimestampMs) {
        List<PermissionChangeObservation> detected = new ArrayList<>();
        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        long changeTimestampMs = resolveChangeTimestamp(metadata, currentTimestampMs);
        int windowMinutes = currentHints.elevationWindowMinutes() != null
                ? currentHints.elevationWindowMinutes()
                : resolveWindowMinutes(metadata);

        for (String summary : normalizeStrings(metadata.get("recentPermissionChanges"), metadata.get("permissionChangeEvents"))) {
            detected.add(new PermissionChangeObservation(
                    stablePermissionChangeId("explicit:" + summary + ":" + authorizationScopeState.fingerprint()),
                    changeTimestampMs,
                    "EXPLICIT",
                    summary,
                    summary,
                    windowMinutes,
                    joinCsv(List.of("recentPermissionChanges", "permissionChangeEvents")),
                    false,
                    currentHints.approvalLinked()));
        }

        if (Boolean.TRUE.equals(currentHints.temporaryElevation()) && detected.isEmpty()) {
            String reason = firstText(currentHints.temporaryElevationReason(), "Temporary elevation declared for the current authorization scope.");
            detected.add(new PermissionChangeObservation(
                    stablePermissionChangeId("temporaryElevation:" + reason + ":" + authorizationScopeState.fingerprint()),
                    changeTimestampMs,
                    "EXPLICIT",
                    reason,
                    reason,
                    windowMinutes,
                    joinCsv(List.of(currentHints.temporaryElevationSourceKey(), currentHints.temporaryElevationReasonSourceKey())),
                    currentHints.temporaryElevationFallback() || currentHints.temporaryElevationReasonFallback(),
                    currentHints.approvalLinked()));
        }

        AuthorizationScopeState previousState = deserializeAuthorizationState(dataStore.getAuthorizationScopeState(tenantId, userId));
        if (previousState != null && !previousState.fingerprint().equals(authorizationScopeState.fingerprint())) {
            detected.add(new PermissionChangeObservation(
                    stablePermissionChangeId("implicit:" + previousState.fingerprint() + "->" + authorizationScopeState.fingerprint()),
                    currentTimestampMs,
                    "AUTH_SCOPE_CHANGE",
                    buildPermissionChangeSummary(previousState, authorizationScopeState),
                    buildPermissionChangeReason(previousState, authorizationScopeState),
                    windowMinutes,
                    joinCsv(List.of(
                            authorizationScopeState.roleSourceKeySummary(),
                            authorizationScopeState.scopeTagSourceKeySummary(),
                            authorizationScopeState.permissionSourceKeySummary(),
                            authorizationScopeState.privilegedSourceKey())),
                    false,
                    currentHints.approvalLinked()));
        }
        return mergePermissionChanges(storedPermissionChanges, detected).stream()
                .filter(permissionChange -> detected.stream().anyMatch(current -> current.changeId().equals(permissionChange.changeId())))
                .toList();
    }

    private List<RoleScopeObservation> loadHistory(String tenantId, String scopeKey, long currentTimestampMs) {
        List<String> rawObservations = dataStore.getRecentRoleScopeObservations(tenantId, scopeKey, HISTORY_SCAN_LIMIT);
        if (rawObservations.isEmpty()) {
            return List.of();
        }
        long windowStart = currentTimestampMs - ROLE_SCOPE_WINDOW_DAYS * 24L * 60L * 60L * 1_000L;
        Map<String, RoleScopeObservation> deduplicated = new LinkedHashMap<>();
        for (String raw : rawObservations) {
            RoleScopeObservation observation = deserializeObservation(raw);
            if (observation == null || observation.timestampMs() > currentTimestampMs || observation.timestampMs() < windowStart) {
                continue;
            }
            deduplicated.putIfAbsent(observation.observationId(), observation);
        }
        return List.copyOf(deduplicated.values());
    }

    private List<PermissionChangeObservation> loadPermissionChanges(String tenantId, String userId, long currentTimestampMs) {
        List<String> rawObservations = dataStore.getRecentPermissionChangeObservations(tenantId, userId, PERMISSION_CHANGE_SCAN_LIMIT);
        if (rawObservations.isEmpty()) {
            return List.of();
        }
        long windowStart = currentTimestampMs - ROLE_SCOPE_WINDOW_DAYS * 24L * 60L * 60L * 1_000L;
        Map<String, PermissionChangeObservation> deduplicated = new LinkedHashMap<>();
        for (String raw : rawObservations) {
            PermissionChangeObservation observation = deserializePermissionChange(raw);
            if (observation == null || observation.timestampMs() > currentTimestampMs || observation.timestampMs() < windowStart) {
                continue;
            }
            deduplicated.putIfAbsent(observation.changeId(), observation);
        }
        return List.copyOf(deduplicated.values());
    }

    private List<PermissionChangeObservation> mergePermissionChanges(
            List<PermissionChangeObservation> storedPermissionChanges,
            List<PermissionChangeObservation> currentPermissionChanges) {
        Map<String, PermissionChangeObservation> merged = new LinkedHashMap<>();
        for (PermissionChangeObservation permissionChange : storedPermissionChanges) {
            merged.putIfAbsent(permissionChange.changeId(), permissionChange);
        }
        for (PermissionChangeObservation permissionChange : currentPermissionChanges) {
            merged.put(permissionChange.changeId(), permissionChange);
        }
        return merged.values().stream()
                .sorted(Comparator.comparingLong(PermissionChangeObservation::timestampMs).reversed())
                .toList();
    }

    private RoleScopeObservation createObservation(SecurityEvent event, AuthorizationScopeState authorizationScopeState) {
        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        ResolvedSignal resourceFamily = resolveSignal(
                metadata,
                true,
                "currentResourceFamily",
                false, "resourceFamily",
                true, "resourceType",
                true, "resourceCategory");
        ResolvedSignal actionFamily = resolveSignal(
                metadata,
                true,
                "currentActionFamily",
                false, "actionFamily",
                false, "operation",
                true, "httpMethod");
        String approvalPattern = resolveApprovalPattern(metadata);
        String escalationPattern = resolveEscalationPattern(metadata, event);
        if (!StringUtils.hasText(resourceFamily.value())
                && !StringUtils.hasText(actionFamily.value())
                && !StringUtils.hasText(approvalPattern)
                && !StringUtils.hasText(escalationPattern)) {
            return null;
        }

        long timestampMs = toEpochMillis(event.getTimestamp());
        String observationFingerprint = firstText(event.getEventId(), authorizationScopeState.fingerprint(), Long.toString(timestampMs));
        return new RoleScopeObservation(
                stableObservationId(observationFingerprint),
                timestampMs,
                authorizationScopeState.scopeKey(),
                authorizationScopeState.scopeSummary(),
                resourceFamily.value(),
                resourceFamily.sourceKey(),
                resourceFamily.fallback(),
                normalizeActionFamily(actionFamily.value()),
                actionFamily.sourceKey(),
                actionFamily.fallback(),
                resolveDecisionState(event),
                approvalPattern,
                escalationPattern);
    }

    private CurrentRoleScopeHints resolveCurrentHints(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        ResolvedCollection expectedResources = resolveCollectionSignal(metadata, true, "expectedResourceFamilies", true, "allowedResourceFamilies");
        ResolvedCollection expectedActions = resolveCollectionSignal(metadata, true, "expectedActionFamilies", true, "allowedActionFamilies");
        ResolvedCollection forbiddenResources = resolveCollectionSignal(metadata, true, "forbiddenResourceFamilies", true, "blockedResourceFamilies");
        ResolvedCollection forbiddenActions = resolveCollectionSignal(metadata, true, "forbiddenActionFamilies", true, "blockedActionFamilies");
        ResolvedCollection approvalPatterns = resolveCollectionSignal(metadata, false, "normalApprovalPatterns", true, "approvalPatterns");
        ResolvedCollection escalationPatterns = resolveCollectionSignal(metadata, false, "normalEscalationPatterns", true, "escalationPatterns");
        ResolvedBoolean temporaryElevation = resolveBooleanSignal(metadata, "temporaryElevation", "temporary_elevation");
        ResolvedSignal temporaryElevationReason = resolveSignal(metadata, false, "temporaryElevationReason", false, "elevationReason", true, "temporary_elevation_reason");
        ResolvedSignal elevationWindowMinutes = resolveSignal(
                metadata,
                false,
                "temporaryElevationWindowMinutes",
                false, "elevationWindowMinutes",
                true, "permissionChangeWindowMinutes",
                true, "elevatedPrivilegeWindowMinutes");
        return new CurrentRoleScopeHints(
                expectedResources.values(),
                expectedResources.sourceKey(),
                expectedResources.fallback(),
                expectedActions.values(),
                expectedActions.sourceKey(),
                expectedActions.fallback(),
                forbiddenResources.values(),
                forbiddenResources.sourceKey(),
                forbiddenResources.fallback(),
                forbiddenActions.values(),
                forbiddenActions.sourceKey(),
                forbiddenActions.fallback(),
                approvalPatterns.values(),
                escalationPatterns.values(),
                temporaryElevation.value(),
                temporaryElevation.sourceKey(),
                temporaryElevation.fallback(),
                temporaryElevationReason.value(),
                temporaryElevationReason.sourceKey(),
                temporaryElevationReason.fallback(),
                resolvePositiveInteger(elevationWindowMinutes.value()),
                elevationWindowMinutes.sourceKey(),
                elevationWindowMinutes.fallback(),
                Boolean.TRUE.equals(resolveBoolean(metadata.get("approvalRequired"), metadata.get("approval_required"))));
    }

    private AuthorizationScopeState resolveAuthorizationScopeState(Map<String, Object> metadata) {
        if (metadata == null) {
            return null;
        }
        ResolvedCollection roles = resolveCollectionSignal(metadata, true, "effectiveRoles", true, "userRoles", true, "roles", true, "roleSet");
        ResolvedCollection scopeTags = resolveCollectionSignal(metadata, true, "scopeTags", true, "authorizationScope", true, "scope", true, "permissionScopes");
        ResolvedCollection permissions = resolveCollectionSignal(metadata, false, "effectivePermissions", true, "permissions", true, "authorities", true, "grantedAuthorities");
        ResolvedBoolean privileged = resolveBooleanSignal(metadata, "privileged", "privilegedFlow", "isPrivileged");
        String policyId = firstText(metadata.get("policyId"), metadata.get("policy_id"));
        String policyVersion = firstText(metadata.get("policyVersion"), metadata.get("policy_version"));
        if (roles.values().isEmpty()
                && scopeTags.values().isEmpty()
                && permissions.values().isEmpty()
                && privileged.value() == null
                && !StringUtils.hasText(policyId)
                && !StringUtils.hasText(policyVersion)) {
            return null;
        }
        String fingerprintDescriptor = "roles=" + joinStrings(roles.values())
                + "|scopes=" + joinStrings(scopeTags.values())
                + "|permissions=" + joinStrings(permissions.values())
                + "|privileged=" + privileged.value()
                + "|policyId=" + safeText(policyId)
                + "|policyVersion=" + safeText(policyVersion);
        return new AuthorizationScopeState(
                stableScopeId(fingerprintDescriptor),
                List.copyOf(new LinkedHashSet<>(roles.values())),
                List.copyOf(new LinkedHashSet<>(scopeTags.values())),
                List.copyOf(new LinkedHashSet<>(permissions.values())),
                privileged.value(),
                policyId,
                policyVersion,
                roles.sourceKey(),
                scopeTags.sourceKey(),
                permissions.sourceKey(),
                privileged.sourceKey());
    }

    private String buildSummary(
            String scopeSummary,
            String currentResourceFamily,
            String currentActionFamily,
            List<String> expectedResourceFamilies,
            List<String> expectedActionFamilies,
            List<String> forbiddenResourceFamilies,
            List<String> forbiddenActionFamilies,
            List<String> recentPermissionChanges,
            Boolean elevatedPrivilegeWindowActive) {
        StringJoiner joiner = new StringJoiner(" | ");
        if (StringUtils.hasText(scopeSummary)) {
            joiner.add(scopeSummary);
        }
        if (StringUtils.hasText(currentResourceFamily)) {
            joiner.add("Current resource family " + currentResourceFamily);
        }
        if (StringUtils.hasText(currentActionFamily)) {
            joiner.add("Current action family " + currentActionFamily);
        }
        if (expectedResourceFamilies != null && !expectedResourceFamilies.isEmpty()) {
            joiner.add("Expected resource families " + String.join(", ", expectedResourceFamilies));
        }
        if (expectedActionFamilies != null && !expectedActionFamilies.isEmpty()) {
            joiner.add("Expected action families " + String.join(", ", expectedActionFamilies));
        }
        if (forbiddenResourceFamilies != null && !forbiddenResourceFamilies.isEmpty()) {
            joiner.add("Denied resource families " + String.join(", ", forbiddenResourceFamilies));
        }
        if (forbiddenActionFamilies != null && !forbiddenActionFamilies.isEmpty()) {
            joiner.add("Denied action families " + String.join(", ", forbiddenActionFamilies));
        }
        if (!recentPermissionChanges.isEmpty()) {
            joiner.add("Recent permission changes " + String.join(", ", recentPermissionChanges));
        }
        if (Boolean.TRUE.equals(elevatedPrivilegeWindowActive)) {
            joiner.add("Elevated privilege window is active");
        }
        String summary = joiner.toString();
        return StringUtils.hasText(summary) ? summary : null;
    }

    private String buildTrustSummary(
            ContextQualityGrade overallGrade,
            int allowedObservationCount,
            int deniedObservationCount,
            List<String> expectedResourceFamilies,
            List<String> expectedActionFamilies,
            List<String> recentPermissionChanges) {
        StringJoiner joiner = new StringJoiner(" | ");
        joiner.add("Allowed observations " + allowedObservationCount);
        if (deniedObservationCount > 0) {
            joiner.add("Denied observations " + deniedObservationCount);
        }
        if (!expectedResourceFamilies.isEmpty()) {
            joiner.add("Expected resources " + String.join(", ", expectedResourceFamilies));
        }
        if (!expectedActionFamilies.isEmpty()) {
            joiner.add("Expected actions " + String.join(", ", expectedActionFamilies));
        }
        if (!recentPermissionChanges.isEmpty()) {
            joiner.add("Recent permission changes " + recentPermissionChanges.size());
        }
        return joiner.toString();
    }

    private String buildProvenanceSummary(
            AuthorizationScopeState authorizationScopeState,
            int allowedObservationCount,
            int deniedObservationCount,
            int permissionChangeCount) {
        StringJoiner joiner = new StringJoiner(" | ");
        joiner.add(authorizationScopeState.scopeSummary());
        if (StringUtils.hasText(authorizationScopeState.roleSourceKeySummary())) {
            joiner.add("Roles from " + authorizationScopeState.roleSourceKeySummary());
        }
        if (StringUtils.hasText(authorizationScopeState.scopeTagSourceKeySummary())) {
            joiner.add("Scopes from " + authorizationScopeState.scopeTagSourceKeySummary());
        }
        if (StringUtils.hasText(authorizationScopeState.permissionSourceKeySummary())) {
            joiner.add("Permissions from " + authorizationScopeState.permissionSourceKeySummary());
        }
        joiner.add("Allowed role-scope observations " + allowedObservationCount);
        if (deniedObservationCount > 0) {
            joiner.add("Denied role-scope observations " + deniedObservationCount);
        }
        if (permissionChangeCount > 0) {
            joiner.add("Permission-change evidence " + permissionChangeCount);
        }
        return joiner.toString();
    }

    private String buildFieldProvenanceSummary(
            int observationCount,
            int daysCovered,
            Set<String> sourceKeys,
            String explicitSourceKey,
            boolean explicitSourcePresent) {
        StringJoiner joiner = new StringJoiner(" | ");
        joiner.add("Observations " + observationCount);
        if (daysCovered > 0) {
            joiner.add("Days covered " + daysCovered);
        }
        if (!sourceKeys.isEmpty()) {
            joiner.add("Sources " + String.join(", ", sourceKeys));
        }
        if (explicitSourcePresent && StringUtils.hasText(explicitSourceKey)) {
            joiner.add("Current explicit scope hint from " + explicitSourceKey);
        }
        return joiner.toString();
    }

    private String buildQualitySummary(
            ContextQualityGrade qualityGrade,
            int observationCount,
            int daysCovered,
            double fallbackRate,
            double unknownRate) {
        return "observations=" + observationCount
                + " | days=" + daysCovered
                + " | fallbackRate=" + round(fallbackRate, 2)
                + " | unknownRate=" + round(unknownRate, 2)
                + " | evidenceState=" + ContextSemanticBoundaryPolicy.describeEvidenceState(
                qualityGrade,
                observationCount,
                daysCovered,
                fallbackRate,
                unknownRate);
    }

    private String buildObservationEvidenceSummary(RoleScopeObservation observation, String scopeSummary) {
        StringJoiner joiner = new StringJoiner(" | ");
        if (StringUtils.hasText(scopeSummary)) {
            joiner.add(scopeSummary);
        }
        if (StringUtils.hasText(observation.resourceFamily())) {
            joiner.add("resource=" + observation.resourceFamily());
        }
        if (StringUtils.hasText(observation.actionFamily())) {
            joiner.add("action=" + observation.actionFamily());
        }
        joiner.add("decision=" + observation.decisionState());
        if (StringUtils.hasText(observation.approvalPattern())) {
            joiner.add("approval=" + observation.approvalPattern());
        }
        if (StringUtils.hasText(observation.escalationPattern())) {
            joiner.add("escalation=" + observation.escalationPattern());
        }
        return joiner.toString();
    }

    private String buildElevationWindowSummary(PermissionChangeObservation activePermissionChange, long currentTimestampMs) {
        if (activePermissionChange == null) {
            return null;
        }
        long ageMinutes = Math.max(0L, (currentTimestampMs - activePermissionChange.timestampMs()) / 60_000L);
        return "Recent permission change remains inside the elevated scope window: "
                + ageMinutes
                + " minutes elapsed of "
                + activePermissionChange.windowMinutes()
                + " minutes.";
    }

    private String buildPermissionChangeSummary(AuthorizationScopeState previousState, AuthorizationScopeState currentState) {
        StringJoiner joiner = new StringJoiner(" | ");
        if (!previousState.effectiveRoles().equals(currentState.effectiveRoles())) {
            joiner.add("roles " + joinStrings(previousState.effectiveRoles()) + " -> " + joinStrings(currentState.effectiveRoles()));
        }
        if (!previousState.scopeTags().equals(currentState.scopeTags())) {
            joiner.add("scopes " + joinStrings(previousState.scopeTags()) + " -> " + joinStrings(currentState.scopeTags()));
        }
        if (!previousState.effectivePermissions().equals(currentState.effectivePermissions())) {
            joiner.add("permissions changed");
        }
        if (!safeText(previousState.policyId()).equals(safeText(currentState.policyId()))
                || !safeText(previousState.policyVersion()).equals(safeText(currentState.policyVersion()))) {
            joiner.add("policy " + safeText(previousState.policyId()) + "@" + safeText(previousState.policyVersion())
                    + " -> " + safeText(currentState.policyId()) + "@" + safeText(currentState.policyVersion()));
        }
        if (!equalsBoolean(previousState.privileged(), currentState.privileged())) {
            joiner.add("privileged " + previousState.privileged() + " -> " + currentState.privileged());
        }
        return "Authorization scope changed: " + (joiner.length() == 0 ? "fingerprint changed" : joiner.toString());
    }

    private String buildPermissionChangeReason(AuthorizationScopeState previousState, AuthorizationScopeState currentState) {
        return "Observed authorization scope transition from "
                + previousState.scopeSummary()
                + " to "
                + currentState.scopeSummary()
                + ".";
    }

    private PermissionChangeObservation resolveActivePermissionChange(
            List<PermissionChangeObservation> permissionChanges,
            long currentTimestampMs) {
        return permissionChanges.stream()
                .sorted(Comparator.comparingLong(PermissionChangeObservation::timestampMs).reversed())
                .filter(permissionChange -> currentTimestampMs - permissionChange.timestampMs()
                        <= permissionChange.windowMinutes() * 60_000L)
                .findFirst()
                .orElse(null);
    }

    private Boolean computeComparisonMismatch(String currentFamily, List<String> expectedFamilies, List<String> forbiddenFamilies) {
        if (!StringUtils.hasText(currentFamily)) {
            return null;
        }
        if (containsIgnoreCase(forbiddenFamilies, currentFamily)) {
            return true;
        }
        if (expectedFamilies == null || expectedFamilies.isEmpty()) {
            return null;
        }
        return !containsIgnoreCase(expectedFamilies, currentFamily);
    }

    private boolean shouldPersist(RoleScopeObservation observation) {
        return observation != null
                && StringUtils.hasText(observation.scopeKey())
                && (StringUtils.hasText(observation.resourceFamily())
                || StringUtils.hasText(observation.actionFamily())
                || StringUtils.hasText(observation.approvalPattern())
                || StringUtils.hasText(observation.escalationPattern()));
    }

    private int averageQualityScore(List<ContextFieldTrustRecord> fieldRecords) {
        return fieldRecords.stream()
                .map(ContextFieldTrustRecord::getQualityScore)
                .filter(score -> score != null && score >= 0)
                .mapToInt(Integer::intValue)
                .average()
                .stream()
                .mapToInt(value -> (int) Math.round(value))
                .findFirst()
                .orElse(0);
    }

    private void appendQualityWarning(List<String> warnings, ContextFieldTrustRecord fieldRecord) {
        if (!ContextSemanticBoundaryPolicy.requiresEvidenceCaution(fieldRecord)) {
            return;
        }
        warnings.add("Role scope field " + fieldRecord.getFieldPath()
                + " has thin or fallback-heavy evidence; do not use it as a standalone reasoning anchor.");
    }

    private ContextQualityGrade resolveGrade(int qualityScore) {
        if (qualityScore >= 80) {
            return ContextQualityGrade.STRONG;
        }
        if (qualityScore >= 60) {
            return ContextQualityGrade.MODERATE;
        }
        if (qualityScore >= 30) {
            return ContextQualityGrade.WEAK;
        }
        return ContextQualityGrade.REJECTED;
    }

    private List<String> topStringKeys(
            List<RoleScopeObservation> observations,
            Function<RoleScopeObservation, String> extractor,
            int limit) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (RoleScopeObservation observation : observations) {
            String value = extractor.apply(observation);
            if (StringUtils.hasText(value)) {
                counts.merge(value, 1, Integer::sum);
            }
        }
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed()
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(limit)
                .map(Map.Entry::getKey)
                .toList();
    }

    private List<String> mergeDistinct(List<String> primary, List<String> secondary) {
        LinkedHashSet<String> merged = new LinkedHashSet<>();
        addDistinctValues(merged, primary);
        addDistinctValues(merged, secondary);
        return List.copyOf(merged);
    }

    private void addDistinctValues(Set<String> target, Collection<String> values) {
        if (values == null) {
            return;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                target.add(value.trim());
            }
        }
    }

    private boolean containsIgnoreCase(List<String> values, String candidate) {
        if (values == null || values.isEmpty() || !StringUtils.hasText(candidate)) {
            return false;
        }
        return values.stream().anyMatch(value -> candidate.equalsIgnoreCase(value));
    }

    private String resolveTenantId(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        return firstText(metadata.get("tenantId"), metadata.get("tenant_id"), metadata.get("organizationId"));
    }

    private long resolveChangeTimestamp(Map<String, Object> metadata, long currentTimestampMs) {
        String explicitTimestamp = firstText(
                metadata.get("permissionChangedAt"),
                metadata.get("permissionChangeAt"),
                metadata.get("elevationStartedAt"),
                metadata.get("temporaryElevationGrantedAt"));
        if (StringUtils.hasText(explicitTimestamp)) {
            Long parsed = parseTimestamp(explicitTimestamp);
            if (parsed != null) {
                return parsed;
            }
        }
        Integer ageMinutes = resolvePositiveInteger(
                metadata.get("permissionChangeAgeMinutes"),
                metadata.get("approvalDecisionAgeMinutes"),
                metadata.get("elevationAgeMinutes"));
        if (ageMinutes != null) {
            return currentTimestampMs - ageMinutes * 60_000L;
        }
        return currentTimestampMs;
    }

    private int resolveWindowMinutes(Map<String, Object> metadata) {
        Integer windowMinutes = resolvePositiveInteger(
                metadata.get("temporaryElevationWindowMinutes"),
                metadata.get("elevationWindowMinutes"),
                metadata.get("permissionChangeWindowMinutes"),
                metadata.get("elevatedPrivilegeWindowMinutes"));
        return windowMinutes != null ? windowMinutes : DEFAULT_ELEVATED_WINDOW_MINUTES;
    }

    private String resolveApprovalPattern(Map<String, Object> metadata) {
        Boolean approvalRequired = resolveBoolean(metadata.get("approvalRequired"), metadata.get("approval_required"));
        if (!Boolean.TRUE.equals(approvalRequired)) {
            return null;
        }
        String status = normalizeToken(firstText(metadata.get("approvalStatus"), metadata.get("approval_status")));
        return StringUtils.hasText(status) ? "APPROVAL_REQUIRED:" + status : "APPROVAL_REQUIRED";
    }

    private String resolveEscalationPattern(Map<String, Object> metadata, SecurityEvent event) {
        String decisionState = resolveDecisionState(event);
        if ("REVIEW".equals(decisionState) || "ESCALATE".equals(decisionState)) {
            return "ESCALATION_REQUIRED";
        }
        if ("DENIED".equals(decisionState)) {
            return "DENIED";
        }
        return normalizeToken(firstText(metadata.get("escalationPattern"), metadata.get("escalationReason")));
    }

    private String resolveDecisionState(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        if (event.isBlocked()) {
            return "DENIED";
        }
        Boolean granted = resolveBoolean(metadata.get("granted"));
        if (granted != null) {
            return granted ? "ALLOWED" : "DENIED";
        }
        String authorizationEffect = normalizeToken(firstText(
                metadata.get("authorizationEffect"),
                metadata.get("decisionResult"),
                metadata.get("decision"),
                metadata.get("authorizationResult")));
        if (!StringUtils.hasText(authorizationEffect)) {
            return "UNKNOWN";
        }
        if (authorizationEffect.contains("ALLOW") || authorizationEffect.contains("PERMIT") || authorizationEffect.contains("GRANT")) {
            return "ALLOWED";
        }
        if (authorizationEffect.contains("REVIEW") || authorizationEffect.contains("ESCALATE") || authorizationEffect.contains("CHALLENGE")) {
            return "REVIEW";
        }
        if (authorizationEffect.contains("DENY") || authorizationEffect.contains("BLOCK") || authorizationEffect.contains("REJECT")) {
            return "DENIED";
        }
        return authorizationEffect;
    }

    private String serializeObservation(RoleScopeObservation observation) {
        return OBSERVATION_VERSION_V1
                + "|" + encodeNullable(observation.observationId())
                + "|" + observation.timestampMs()
                + "|" + encodeNullable(observation.scopeKey())
                + "|" + encodeNullable(observation.scopeSummary())
                + "|" + encodeNullable(observation.resourceFamily())
                + "|" + encodeNullable(observation.resourceFamilySourceKey())
                + "|" + encodeBoolean(observation.resourceFamilyFallback())
                + "|" + encodeNullable(observation.actionFamily())
                + "|" + encodeNullable(observation.actionFamilySourceKey())
                + "|" + encodeBoolean(observation.actionFamilyFallback())
                + "|" + encodeNullable(observation.decisionState())
                + "|" + encodeNullable(observation.approvalPattern())
                + "|" + encodeNullable(observation.escalationPattern());
    }

    private RoleScopeObservation deserializeObservation(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String[] parts = raw.split("\\|", -1);
        try {
            if (OBSERVATION_VERSION_V1.equals(parts[0]) && parts.length == 14) {
                return new RoleScopeObservation(
                        decodeNullable(parts[1]),
                        Long.parseLong(parts[2]),
                        decodeNullable(parts[3]),
                        decodeNullable(parts[4]),
                        decodeNullable(parts[5]),
                        decodeNullable(parts[6]),
                        decodeBoolean(parts[7]),
                        decodeNullable(parts[8]),
                        decodeNullable(parts[9]),
                        decodeBoolean(parts[10]),
                        decodeNullable(parts[11]),
                        decodeNullable(parts[12]),
                        decodeNullable(parts[13]));
            }
        } catch (RuntimeException ignored) {
            return null;
        }
        return null;
    }

    private String serializePermissionChange(PermissionChangeObservation permissionChange) {
        return PERMISSION_CHANGE_VERSION_V1
                + "|" + encodeNullable(permissionChange.changeId())
                + "|" + permissionChange.timestampMs()
                + "|" + encodeNullable(permissionChange.changeType())
                + "|" + encodeNullable(permissionChange.summary())
                + "|" + encodeNullable(permissionChange.reason())
                + "|" + permissionChange.windowMinutes()
                + "|" + encodeNullable(permissionChange.sourceKeySummary())
                + "|" + encodeBoolean(permissionChange.fallback())
                + "|" + encodeBoolean(permissionChange.approvalLinked());
    }

    private PermissionChangeObservation deserializePermissionChange(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String[] parts = raw.split("\\|", -1);
        try {
            if (PERMISSION_CHANGE_VERSION_V1.equals(parts[0]) && parts.length == 10) {
                return new PermissionChangeObservation(
                        decodeNullable(parts[1]),
                        Long.parseLong(parts[2]),
                        decodeNullable(parts[3]),
                        decodeNullable(parts[4]),
                        decodeNullable(parts[5]),
                        Integer.parseInt(parts[6]),
                        decodeNullable(parts[7]),
                        decodeBoolean(parts[8]),
                        decodeBoolean(parts[9]));
            }
        } catch (RuntimeException ignored) {
            return null;
        }
        return null;
    }

    private String serializeAuthorizationState(AuthorizationScopeState authorizationScopeState) {
        if (authorizationScopeState == null) {
            return null;
        }
        return AUTHORIZATION_STATE_VERSION_V1
                + "|" + encodeNullable(authorizationScopeState.fingerprint())
                + "|" + encodeStringList(authorizationScopeState.effectiveRoles())
                + "|" + encodeStringList(authorizationScopeState.scopeTags())
                + "|" + encodeStringList(authorizationScopeState.effectivePermissions())
                + "|" + encodeNullableBoolean(authorizationScopeState.privileged())
                + "|" + encodeNullable(authorizationScopeState.policyId())
                + "|" + encodeNullable(authorizationScopeState.policyVersion())
                + "|" + encodeNullable(authorizationScopeState.roleSourceKeySummary())
                + "|" + encodeNullable(authorizationScopeState.scopeTagSourceKeySummary())
                + "|" + encodeNullable(authorizationScopeState.permissionSourceKeySummary())
                + "|" + encodeNullable(authorizationScopeState.privilegedSourceKey());
    }

    private AuthorizationScopeState deserializeAuthorizationState(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String[] parts = raw.split("\\|", -1);
        try {
            if (AUTHORIZATION_STATE_VERSION_V1.equals(parts[0]) && parts.length == 12) {
                return new AuthorizationScopeState(
                        decodeNullable(parts[1]),
                        decodeStringList(parts[2]),
                        decodeStringList(parts[3]),
                        decodeStringList(parts[4]),
                        decodeNullableBoolean(parts[5]),
                        decodeNullable(parts[6]),
                        decodeNullable(parts[7]),
                        decodeNullable(parts[8]),
                        decodeNullable(parts[9]),
                        decodeNullable(parts[10]),
                        decodeNullable(parts[11]));
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

    private String encodeStringList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return NULL_TOKEN;
        }
        return encodeNullable(String.join("\u001F", values));
    }

    private List<String> decodeStringList(String raw) {
        String decoded = decodeNullable(raw);
        if (!StringUtils.hasText(decoded)) {
            return List.of();
        }
        return List.of(decoded.split("\u001F", -1)).stream()
                .filter(StringUtils::hasText)
                .toList();
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

    private ResolvedSignal resolveSignal(Map<String, Object> metadata, boolean normalizeValueAsToken, Object... candidates) {
        if (metadata == null || candidates == null || candidates.length == 0) {
            return new ResolvedSignal(null, null, false);
        }
        for (int index = 0; index < candidates.length; index++) {
            Object candidate = candidates[index];
            if (!(candidate instanceof String key)) {
                continue;
            }
            boolean fallback = index > 0 && candidates[index - 1] instanceof Boolean previousFlag && previousFlag;
            String text = firstText(metadata.get(key));
            if (!StringUtils.hasText(text)) {
                continue;
            }
            return new ResolvedSignal(normalizeValueAsToken ? normalizeToken(text) : text.trim(), key, fallback);
        }
        return new ResolvedSignal(null, null, false);
    }

    private ResolvedCollection resolveCollectionSignal(Map<String, Object> metadata, boolean normalizeValueAsToken, Object... candidates) {
        if (metadata == null || candidates == null || candidates.length == 0) {
            return new ResolvedCollection(List.of(), null, false);
        }
        for (int index = 0; index < candidates.length; index++) {
            Object candidate = candidates[index];
            if (!(candidate instanceof String key)) {
                continue;
            }
            boolean fallback = index > 0 && candidates[index - 1] instanceof Boolean previousFlag && previousFlag;
            List<String> values = normalizeValueAsToken ? normalizeStrings(metadata.get(key)) : rawStrings(metadata.get(key));
            if (!values.isEmpty()) {
                return new ResolvedCollection(values, key, fallback);
            }
        }
        return new ResolvedCollection(List.of(), null, false);
    }

    private ResolvedBoolean resolveBooleanSignal(Map<String, Object> metadata, String... keys) {
        if (metadata == null || keys == null) {
            return new ResolvedBoolean(null, null, false);
        }
        for (int index = 0; index < keys.length; index++) {
            String key = keys[index];
            Boolean value = resolveBoolean(metadata.get(key));
            if (value != null) {
                return new ResolvedBoolean(value, key, index > 0);
            }
        }
        return new ResolvedBoolean(null, null, false);
    }

    private List<String> normalizeStrings(Object... values) {
        List<String> normalized = new ArrayList<>();
        if (values == null) {
            return List.of();
        }
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            if (value instanceof Collection<?> collection) {
                for (Object item : collection) {
                    addNormalized(normalized, item);
                }
                continue;
            }
            if (value instanceof String stringValue && stringValue.contains(",")) {
                for (String token : stringValue.split(",")) {
                    addNormalized(normalized, token);
                }
                continue;
            }
            addNormalized(normalized, value);
        }
        return normalized.stream().distinct().toList();
    }

    private List<String> rawStrings(Object... values) {
        List<String> normalized = new ArrayList<>();
        if (values == null) {
            return List.of();
        }
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            if (value instanceof Collection<?> collection) {
                for (Object item : collection) {
                    addRaw(normalized, item);
                }
                continue;
            }
            if (value instanceof String stringValue && stringValue.contains(",")) {
                for (String token : stringValue.split(",")) {
                    addRaw(normalized, token);
                }
                continue;
            }
            addRaw(normalized, value);
        }
        return normalized.stream().distinct().toList();
    }

    private void addNormalized(List<String> values, Object rawValue) {
        if (rawValue == null) {
            return;
        }
        String normalized = normalizeToken(rawValue.toString());
        if (StringUtils.hasText(normalized)) {
            values.add(normalized);
        }
    }

    private void addRaw(List<String> values, Object rawValue) {
        if (rawValue == null) {
            return;
        }
        String text = rawValue.toString().trim();
        if (StringUtils.hasText(text)) {
            values.add(text);
        }
    }

    private String stableObservationId(String fingerprint) {
        return UUID.nameUUIDFromBytes(fingerprint.getBytes(StandardCharsets.UTF_8)).toString();
    }

    private String stablePermissionChangeId(String fingerprint) {
        return UUID.nameUUIDFromBytes(fingerprint.getBytes(StandardCharsets.UTF_8)).toString();
    }

    private String stableScopeId(String fingerprint) {
        return UUID.nameUUIDFromBytes(fingerprint.getBytes(StandardCharsets.UTF_8)).toString();
    }

    private long toEpochMillis(LocalDateTime timestamp) {
        LocalDateTime safeTimestamp = timestamp != null ? timestamp : LocalDateTime.now();
        return safeTimestamp.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }

    private LocalDate toLocalDate(long timestampMs) {
        return Instant.ofEpochMilli(timestampMs)
                .atZone(ZoneId.systemDefault())
                .toLocalDate();
    }

    private Long parseTimestamp(String rawValue) {
        try {
            return Instant.parse(rawValue).toEpochMilli();
        } catch (DateTimeParseException ignored) {
        }
        try {
            return LocalDateTime.parse(rawValue)
                    .atZone(ZoneId.systemDefault())
                    .toInstant()
                    .toEpochMilli();
        } catch (DateTimeParseException ignored) {
            return null;
        }
    }

    private Boolean resolveBoolean(Object... candidates) {
        if (candidates == null) {
            return null;
        }
        for (Object candidate : candidates) {
            if (candidate == null) {
                continue;
            }
            if (candidate instanceof Boolean booleanValue) {
                return booleanValue;
            }
            String text = candidate.toString().trim();
            if ("true".equalsIgnoreCase(text) || "false".equalsIgnoreCase(text)) {
                return Boolean.parseBoolean(text);
            }
        }
        return null;
    }

    private Integer resolvePositiveInteger(Object... candidates) {
        if (candidates == null) {
            return null;
        }
        for (Object candidate : candidates) {
            if (candidate == null) {
                continue;
            }
            if (candidate instanceof Number number) {
                return number.intValue() >= 0 ? number.intValue() : null;
            }
            try {
                int value = Integer.parseInt(candidate.toString().trim());
                return value >= 0 ? value : null;
            } catch (RuntimeException ignored) {
                return null;
            }
        }
        return null;
    }

    private String normalizeActionFamily(String actionFamily) {
        if (!StringUtils.hasText(actionFamily)) {
            return null;
        }
        String normalized = normalizeToken(actionFamily);
        return switch (normalized) {
            case "GET", "HEAD", "READ", "VIEW", "LIST" -> "READ";
            case "POST", "CREATE" -> "CREATE";
            case "PUT", "PATCH", "UPDATE", "WRITE", "MODIFY" -> "UPDATE";
            case "DELETE", "REMOVE" -> "DELETE";
            case "EXPORT", "DOWNLOAD" -> "EXPORT";
            case "APPROVE" -> "APPROVE";
            default -> normalized;
        };
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

    @SafeVarargs
    private final <T> T firstNonNull(T... values) {
        if (values == null) {
            return null;
        }
        for (T value : values) {
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private boolean equalsBoolean(Boolean left, Boolean right) {
        return left == right || (left != null && left.equals(right));
    }

    private void addIfText(Set<String> values, String rawValue) {
        if (StringUtils.hasText(rawValue)) {
            values.add(rawValue.trim());
        }
    }

    private void addCsvValues(Set<String> values, String rawValue) {
        if (!StringUtils.hasText(rawValue)) {
            return;
        }
        for (String token : rawValue.split(",")) {
            addIfText(values, token);
        }
    }

    private void putIfText(Map<String, String> values, String key, String value) {
        if (StringUtils.hasText(key) && StringUtils.hasText(value)) {
            values.put(key, value);
        }
    }

    private void appendFlag(List<String> flags, String flag, boolean enabled) {
        if (enabled && StringUtils.hasText(flag)) {
            flags.add(flag);
        }
    }

    private String joinStrings(Collection<String> values) {
        if (values == null || values.isEmpty()) {
            return "none";
        }
        return String.join(", ", values);
    }

    private String joinCsv(Collection<String> values) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        return values.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .reduce((left, right) -> left + "," + right)
                .orElse(null);
    }

    private String safeText(String value) {
        return StringUtils.hasText(value) ? value : "";
    }

    private Double round(double value, int scale) {
        double factor = Math.pow(10, scale);
        return Math.round(value * factor) / factor;
    }

    private record ResolvedSignal(String value, String sourceKey, boolean fallback) {
    }

    private record ResolvedCollection(List<String> values, String sourceKey, boolean fallback) {
        private ResolvedCollection {
            values = values == null ? List.of() : List.copyOf(values);
        }
    }

    private record ResolvedBoolean(Boolean value, String sourceKey, boolean fallback) {
    }

    private record RoleScopeObservation(
            String observationId,
            long timestampMs,
            String scopeKey,
            String scopeSummary,
            String resourceFamily,
            String resourceFamilySourceKey,
            boolean resourceFamilyFallback,
            String actionFamily,
            String actionFamilySourceKey,
            boolean actionFamilyFallback,
            String decisionState,
            String approvalPattern,
            String escalationPattern) {
    }

    private record PermissionChangeObservation(
            String changeId,
            long timestampMs,
            String changeType,
            String summary,
            String reason,
            int windowMinutes,
            String sourceKeySummary,
            boolean fallback,
            boolean approvalLinked) {
    }

    private record AuthorizationScopeState(
            String fingerprint,
            List<String> effectiveRoles,
            List<String> scopeTags,
            List<String> effectivePermissions,
            Boolean privileged,
            String policyId,
            String policyVersion,
            String roleSourceKeySummary,
            String scopeTagSourceKeySummary,
            String permissionSourceKeySummary,
            String privilegedSourceKey) {

        private AuthorizationScopeState {
            effectiveRoles = effectiveRoles == null ? List.of() : List.copyOf(effectiveRoles);
            scopeTags = scopeTags == null ? List.of() : List.copyOf(scopeTags);
            effectivePermissions = effectivePermissions == null ? List.of() : List.copyOf(effectivePermissions);
        }

        String scopeKey() {
            String descriptor = (!effectiveRoles.isEmpty() || !scopeTags.isEmpty())
                    ? "roles=" + String.join(",", effectiveRoles) + "|scopes=" + String.join(",", scopeTags) + "|privileged=" + privileged
                    : "permissions=" + String.join(",", effectivePermissions) + "|privileged=" + privileged;
            return UUID.nameUUIDFromBytes(descriptor.getBytes(StandardCharsets.UTF_8)).toString();
        }

        String scopeSummary() {
            StringJoiner joiner = new StringJoiner(" | ");
            if (!effectiveRoles.isEmpty()) {
                joiner.add("Effective roles " + String.join(", ", effectiveRoles));
            }
            if (!scopeTags.isEmpty()) {
                joiner.add("Scope tags " + String.join(", ", scopeTags));
            }
            if (Boolean.TRUE.equals(privileged)) {
                joiner.add("Privileged flow active");
            }
            if (joiner.length() == 0 && !effectivePermissions.isEmpty()) {
                joiner.add("Effective permissions " + String.join(", ", effectivePermissions));
            }
            return joiner.toString();
        }

        boolean hasMaterialIdentity() {
            return !effectiveRoles.isEmpty()
                    || !scopeTags.isEmpty()
                    || !effectivePermissions.isEmpty()
                    || privileged != null
                    || StringUtils.hasText(policyId)
                    || StringUtils.hasText(policyVersion);
        }
    }

    private record CurrentRoleScopeHints(
            List<String> expectedResourceFamilies,
            String expectedResourceFamiliesSourceKey,
            boolean expectedResourceFamiliesFallback,
            List<String> expectedActionFamilies,
            String expectedActionFamiliesSourceKey,
            boolean expectedActionFamiliesFallback,
            List<String> forbiddenResourceFamilies,
            String forbiddenResourceFamiliesSourceKey,
            boolean forbiddenResourceFamiliesFallback,
            List<String> forbiddenActionFamilies,
            String forbiddenActionFamiliesSourceKey,
            boolean forbiddenActionFamiliesFallback,
            List<String> normalApprovalPatterns,
            List<String> normalEscalationPatterns,
            Boolean temporaryElevation,
            String temporaryElevationSourceKey,
            boolean temporaryElevationFallback,
            String temporaryElevationReason,
            String temporaryElevationReasonSourceKey,
            boolean temporaryElevationReasonFallback,
            Integer elevationWindowMinutes,
            String elevationWindowSourceKey,
            boolean elevationWindowFallback,
            boolean approvalLinked) {

        private CurrentRoleScopeHints {
            expectedResourceFamilies = expectedResourceFamilies == null ? List.of() : List.copyOf(expectedResourceFamilies);
            expectedActionFamilies = expectedActionFamilies == null ? List.of() : List.copyOf(expectedActionFamilies);
            forbiddenResourceFamilies = forbiddenResourceFamilies == null ? List.of() : List.copyOf(forbiddenResourceFamilies);
            forbiddenActionFamilies = forbiddenActionFamilies == null ? List.of() : List.copyOf(forbiddenActionFamilies);
            normalApprovalPatterns = normalApprovalPatterns == null ? List.of() : List.copyOf(normalApprovalPatterns);
            normalEscalationPatterns = normalEscalationPatterns == null ? List.of() : List.copyOf(normalEscalationPatterns);
        }
    }
}
