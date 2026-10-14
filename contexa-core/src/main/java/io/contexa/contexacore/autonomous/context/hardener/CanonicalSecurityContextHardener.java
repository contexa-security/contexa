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
package io.contexa.contexacore.autonomous.context.hardener;

import io.contexa.contexacore.autonomous.context.model.ContextEvidenceRecord;
import io.contexa.contexacore.autonomous.context.model.ContextFieldTrustRecord;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.context.support.NetworkZone;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

public class CanonicalSecurityContextHardener {

    public CanonicalSecurityContext harden(CanonicalSecurityContext context) {
        if (context == null) {
            return null;
        }

        if (context.getActor() == null) {
            context.setActor(new CanonicalSecurityContext.Actor());
        }
        if (context.getSession() == null) {
            context.setSession(new CanonicalSecurityContext.Session());
        }
        if (context.getResource() == null) {
            context.setResource(new CanonicalSecurityContext.Resource());
        }
        if (context.getAuthorization() == null) {
            context.setAuthorization(new CanonicalSecurityContext.Authorization());
        }
        if (context.getDelegation() == null) {
            context.setDelegation(new CanonicalSecurityContext.Delegation());
        }

        hardenActor(context.getActor());
        hardenSession(context.getSession());
        if (context.getDevice() != null) {
            hardenDevice(context.getDevice());
        }
        if (context.getIntent() != null) {
            hardenIntent(context.getIntent());
        }
        if (context.getLocation() != null) {
            hardenLocation(context.getLocation());
        }
        hardenResource(context.getResource());
        hardenAuthorization(context.getAuthorization());
        hardenDelegation(context.getDelegation());
        if (context.getObservedScope() != null) {
            hardenObservedScope(context.getObservedScope());
        }
        if (context.getSessionNarrativeProfile() != null) {
            hardenSessionNarrativeProfile(context.getSessionNarrativeProfile());
        }
        if (context.getWorkProfile() != null) {
            hardenWorkProfile(context.getWorkProfile());
        }
        if (context.getRoleScopeProfile() != null) {
            hardenRoleScopeProfile(context.getRoleScopeProfile());
        }
        if (context.getPeerCohortProfile() != null) {
            hardenPeerCohortProfile(context.getPeerCohortProfile());
        }
        if (context.getFrictionProfile() != null) {
            hardenFrictionProfile(context.getFrictionProfile());
        }
        if (context.getReasoningMemoryProfile() != null) {
            hardenReasoningMemoryProfile(context.getReasoningMemoryProfile());
        }
        if (context.getAttributes() == null) {
            context.setAttributes(Map.of());
        }
        context.setContextTrustProfiles(hardenTrustProfiles(context.getContextTrustProfiles()));
        return context;
    }

    private void hardenActor(CanonicalSecurityContext.Actor actor) {
        actor.setUserId(normalizeText(actor.getUserId()));
        actor.setExternalSubjectId(normalizeText(actor.getExternalSubjectId()));
        actor.setOrganizationId(normalizeText(actor.getOrganizationId()));
        actor.setTenantId(normalizeText(actor.getTenantId()));
        actor.setDepartment(normalizeText(actor.getDepartment()));
        actor.setPosition(normalizeText(actor.getPosition()));
        actor.setPrincipalType(normalizeUpperText(actor.getPrincipalType()));
        actor.setBridgeSubjectKey(normalizeText(actor.getBridgeSubjectKey()));
        actor.setRoleSet(normalizeList(actor.getRoleSet()));
        actor.setAuthoritySet(normalizeList(actor.getAuthoritySet()));
    }

    private void hardenSession(CanonicalSecurityContext.Session session) {
        session.setSessionId(normalizeText(session.getSessionId()));
        session.setClientIp(normalizeText(session.getClientIp()));
        session.setUserAgent(normalizeText(session.getUserAgent()));
        session.setAuthenticationType(SecuritySemanticNormalizer.normalizeAuthenticationType(session.getAuthenticationType()));
        session.setAuthenticationAssurance(normalizeUpperText(session.getAuthenticationAssurance()));
        session.setRecentMfaFailureCount(normalizeInteger(session.getRecentMfaFailureCount()));
        session.setLastMfaUsedAt(normalizeText(session.getLastMfaUsedAt()));
        session.setFailedLoginAttempts(normalizeInteger(session.getFailedLoginAttempts()));
        session.setRecentRequestCount(normalizeInteger(session.getRecentRequestCount()));
        session.setRecentChallengeCount(normalizeInteger(session.getRecentChallengeCount()));
        session.setRecentBlockCount(normalizeInteger(session.getRecentBlockCount()));
        session.setRecentEscalationCount(normalizeInteger(session.getRecentEscalationCount()));
        session.setCurrentAccessHour(normalizeHour(session.getCurrentAccessHour()));
        session.setConcurrentSessions(normalizeInteger(session.getConcurrentSessions()));
        session.setPasswordAgeDays(normalizeInteger(session.getPasswordAgeDays()));
    }

    private void hardenDevice(CanonicalSecurityContext.Device device) {
        device.setOs(SecuritySemanticNormalizer.normalizeOperatingSystem(device.getOs()));
        device.setOsVersion(normalizeText(device.getOsVersion()));
        device.setBrowser(normalizeText(device.getBrowser()));
        device.setBrowserVersion(normalizeText(device.getBrowserVersion()));
        device.setScreenResolution(normalizeText(device.getScreenResolution()));
        device.setLanguage(normalizeText(device.getLanguage()));
    }

    private void hardenIntent(CanonicalSecurityContext.Intent intent) {
    }

    private void hardenLocation(CanonicalSecurityContext.Location location) {
        location.setCountry(normalizeUpperText(location.getCountry()));
        location.setCity(normalizeText(location.getCity()));
        location.setIpBand(SecuritySemanticNormalizer.normalizeNetwork(null, normalizeText(location.getIpBand())));
        location.setAsn(normalizeUpperText(location.getAsn()));
        location.setNetworkZone(NetworkZone.nameOf(location.getNetworkZone()));
        CanonicalSecurityContext.Movement movement = location.getMovement();
        if (movement != null) {
            // A value outside what it can measure states nothing (W2-13).
            movement.setLatitude(within(movement.getLatitude(), -90, 90));
            movement.setLongitude(within(movement.getLongitude(), -180, 180));
            movement.setDistanceKm(movement.getDistanceKm() != null && movement.getDistanceKm() < 0
                    ? null : movement.getDistanceKm());
            movement.setElapsedMinutes(movement.getElapsedMinutes() != null && movement.getElapsedMinutes() < 0
                    ? null : movement.getElapsedMinutes());
            movement.setPreviousLocation(normalizeText(movement.getPreviousLocation()));
            movement.setBaselineConfidence(within(movement.getBaselineConfidence(), 0, 1));
        }
    }

    private static Double within(Double value, double low, double high) {
        return value == null || value.isNaN() || value < low || value > high ? null : value;
    }

    private void hardenResource(CanonicalSecurityContext.Resource resource) {
        resource.setResourceId(normalizeText(resource.getResourceId()));
        resource.setResourceType(normalizeUpperText(resource.getResourceType()));
        resource.setBusinessLabel(normalizeText(resource.getBusinessLabel()));
        resource.setAuthorText(normalizeText(resource.getAuthorText()));
        resource.setRequestedItems(normalizeInteger(resource.getRequestedItems()));
        resource.setSensitivity(SecuritySemanticNormalizer.normalizeSensitivity(resource.getSensitivity()));
        resource.setResourceClass(SecuritySemanticNormalizer.normalizeResourceClass(resource.getResourceClass()));
        resource.setResourceCategory(SecuritySemanticNormalizer.normalizeResourceCategory(resource.getResourceCategory()));
        resource.setRequestPath(normalizeText(resource.getRequestPath()));
        resource.setHttpMethod(normalizeUpperText(resource.getHttpMethod()));
        resource.setActionFamily(SecuritySemanticNormalizer.normalizeActionFamily(resource.getActionFamily(), resource.getHttpMethod()));
    }

    private void hardenAuthorization(CanonicalSecurityContext.Authorization authorization) {
        authorization.setEffectiveRoles(normalizeList(authorization.getEffectiveRoles()));
        authorization.setEffectivePermissions(normalizeList(authorization.getEffectivePermissions()));
        authorization.setScopeTags(normalizeList(authorization.getScopeTags()));
        authorization.setAuthorizationEffect(normalizeUpperText(authorization.getAuthorizationEffect()));
        authorization.setPolicyId(normalizeText(authorization.getPolicyId()));
        authorization.setPolicyVersion(normalizeText(authorization.getPolicyVersion()));
    }

    private void hardenDelegation(CanonicalSecurityContext.Delegation delegation) {
        delegation.setAgentId(normalizeText(delegation.getAgentId()));
        delegation.setObjectiveId(normalizeText(delegation.getObjectiveId()));
        delegation.setObjectiveFamily(normalizeUpperText(delegation.getObjectiveFamily()));
        delegation.setObjectiveSummary(normalizeText(delegation.getObjectiveSummary()));
        delegation.setAllowedOperations(normalizeList(delegation.getAllowedOperations()));
        delegation.setAllowedResources(normalizeList(delegation.getAllowedResources()));
        delegation.setObjectiveDriftSummary(normalizeText(delegation.getObjectiveDriftSummary()));
    }

    private void hardenObservedScope(CanonicalSecurityContext.ObservedScope observedScope) {
        observedScope.setProfileSource(normalizeUpperText(observedScope.getProfileSource()));
        observedScope.setSummary(normalizeText(observedScope.getSummary()));
        observedScope.setRecentProtectableAccessCount(normalizeInteger(observedScope.getRecentProtectableAccessCount()));
        observedScope.setRecentDeniedAccessCount(normalizeInteger(observedScope.getRecentDeniedAccessCount()));
        observedScope.setRecentSensitiveAccessCount(normalizeInteger(observedScope.getRecentSensitiveAccessCount()));
        observedScope.setFrequentResources(normalizeList(observedScope.getFrequentResources()));
        observedScope.setFrequentActionFamilies(normalizeActionFamilies(observedScope.getFrequentActionFamilies()));
    }

    private void hardenSessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile sessionNarrativeProfile) {
        sessionNarrativeProfile.setSummary(normalizeText(sessionNarrativeProfile.getSummary()));
        sessionNarrativeProfile.setSessionAgeMinutes(normalizeInteger(sessionNarrativeProfile.getSessionAgeMinutes()));
        reconcileSessionAgeSummary(sessionNarrativeProfile);
        sessionNarrativeProfile.setPreviousPath(normalizeText(sessionNarrativeProfile.getPreviousPath()));
        sessionNarrativeProfile.setPreviousActionFamily(ActionFamily.nameOrRaw(sessionNarrativeProfile.getPreviousActionFamily()));
        sessionNarrativeProfile.setLastRequestIntervalMs(normalizeLong(sessionNarrativeProfile.getLastRequestIntervalMs()));
        // Sequences keep their order and repeats: the same request made five times is five entries (A-2).
        sessionNarrativeProfile.setSessionActionSequence(normalizeSequence(sessionNarrativeProfile.getSessionActionSequence()));
        sessionNarrativeProfile.setSessionProtectableSequence(
                normalizeSequence(sessionNarrativeProfile.getSessionProtectableSequence()));
        sessionNarrativeProfile.setSessionDecisionHistory(normalizeSequence(sessionNarrativeProfile.getSessionDecisionHistory()));
    }

    private void hardenWorkProfile(CanonicalSecurityContext.WorkProfile workProfile) {
        workProfile.setSummary(normalizeText(workProfile.getSummary()));
        workProfile.setFrequentProtectableResources(normalizeList(workProfile.getFrequentProtectableResources()));
        workProfile.setFrequentActionFamilies(normalizeActionFamilies(workProfile.getFrequentActionFamilies()));
        workProfile.setFrequentSensitiveResourceCategories(normalizeList(workProfile.getFrequentSensitiveResourceCategories()));
        workProfile.setProtectableResourceHeatmap(normalizeList(workProfile.getProtectableResourceHeatmap()));
        workProfile.setNormalAccessHours(normalizeIntegerList(workProfile.getNormalAccessHours()));
        workProfile.setNormalAccessDays(normalizeIntegerList(workProfile.getNormalAccessDays()));
        workProfile.setNormalSessionLengthMinutes(normalizeInteger(workProfile.getNormalSessionLengthMinutes()));
        workProfile.setNormalReadWriteExportRatio(normalizeText(workProfile.getNormalReadWriteExportRatio()));
        workProfile.setNormalRequestRate(normalizeDouble(workProfile.getNormalRequestRate()));
        workProfile.setNormalPrivilegedActionFrequency(normalizeDouble(workProfile.getNormalPrivilegedActionFrequency()));
        workProfile.setProtectableInvocationDensity(normalizeDouble(workProfile.getProtectableInvocationDensity()));
        workProfile.setSeasonalBusinessProfile(normalizeText(workProfile.getSeasonalBusinessProfile()));
        workProfile.setLongTailLegitimateTasks(normalizeList(workProfile.getLongTailLegitimateTasks()));
    }

    private void hardenRoleScopeProfile(CanonicalSecurityContext.RoleScopeProfile roleScopeProfile) {
        roleScopeProfile.setSummary(normalizeText(roleScopeProfile.getSummary()));
        roleScopeProfile.setCurrentResourceFamily(normalizeUpperText(roleScopeProfile.getCurrentResourceFamily()));
        roleScopeProfile.setCurrentActionFamily(ActionFamily.nameOrRaw(roleScopeProfile.getCurrentActionFamily()));
        roleScopeProfile.setExpectedResourceFamilies(normalizeList(roleScopeProfile.getExpectedResourceFamilies()));
        roleScopeProfile.setExpectedActionFamilies(normalizeActionFamilies(roleScopeProfile.getExpectedActionFamilies()));
        roleScopeProfile.setForbiddenResourceFamilies(normalizeList(roleScopeProfile.getForbiddenResourceFamilies()));
        roleScopeProfile.setForbiddenActionFamilies(normalizeActionFamilies(roleScopeProfile.getForbiddenActionFamilies()));
        roleScopeProfile.setNormalApprovalPatterns(normalizeList(roleScopeProfile.getNormalApprovalPatterns()));
        roleScopeProfile.setNormalEscalationPatterns(normalizeList(roleScopeProfile.getNormalEscalationPatterns()));
        roleScopeProfile.setRecentPermissionChanges(normalizeList(roleScopeProfile.getRecentPermissionChanges()));
        roleScopeProfile.setTemporaryElevationReason(normalizeText(roleScopeProfile.getTemporaryElevationReason()));
        roleScopeProfile.setElevationWindowSummary(normalizeText(roleScopeProfile.getElevationWindowSummary()));
    }

    private void reconcileSessionAgeSummary(CanonicalSecurityContext.SessionNarrativeProfile sessionNarrativeProfile) {
        if (sessionNarrativeProfile == null || sessionNarrativeProfile.getSessionAgeMinutes() == null) {
            return;
        }
        String summary = sessionNarrativeProfile.getSummary();
        String canonicalAge = String.valueOf(sessionNarrativeProfile.getSessionAgeMinutes());
        if (!StringUtils.hasText(summary)) {
            sessionNarrativeProfile.setSummary("Session age " + canonicalAge + "m");
            return;
        }
        String reconciled = summary
                .replaceAll("(?i)Session age \\d+m", "Session age " + canonicalAge + "m")
                .replaceAll("(?i)Session age minutes: \\d+", "Session age minutes: " + canonicalAge);
        sessionNarrativeProfile.setSummary(reconciled);
    }

    private void hardenPeerCohortProfile(CanonicalSecurityContext.PeerCohortProfile peerCohortProfile) {
        peerCohortProfile.setCohortId(normalizeText(peerCohortProfile.getCohortId()));
        peerCohortProfile.setSummary(normalizeText(peerCohortProfile.getSummary()));
        peerCohortProfile.setPreferredResources(normalizeList(peerCohortProfile.getPreferredResources()));
        peerCohortProfile.setPreferredActionFamilies(normalizeActionFamilies(peerCohortProfile.getPreferredActionFamilies()));
        peerCohortProfile.setNormalProtectableFrequencyBand(normalizeText(peerCohortProfile.getNormalProtectableFrequencyBand()));
        peerCohortProfile.setNormalSensitivityBand(normalizeUpperText(peerCohortProfile.getNormalSensitivityBand()));
    }

    private void hardenFrictionProfile(CanonicalSecurityContext.FrictionProfile frictionProfile) {
        frictionProfile.setSummary(normalizeText(frictionProfile.getSummary()));
        frictionProfile.setRecentChallengeCount(normalizeInteger(frictionProfile.getRecentChallengeCount()));
        frictionProfile.setRecentBlockCount(normalizeInteger(frictionProfile.getRecentBlockCount()));
        frictionProfile.setRecentEscalationCount(normalizeInteger(frictionProfile.getRecentEscalationCount()));
        frictionProfile.setApprovalStatus(normalizeUpperText(frictionProfile.getApprovalStatus()));
        frictionProfile.setApprovalLineage(normalizeList(frictionProfile.getApprovalLineage()));
        frictionProfile.setPendingApproverRoles(normalizeList(frictionProfile.getPendingApproverRoles()));
        frictionProfile.setApprovalTicketId(normalizeText(frictionProfile.getApprovalTicketId()));
        frictionProfile.setApprovalDecisionAgeMinutes(normalizeInteger(frictionProfile.getApprovalDecisionAgeMinutes()));
        frictionProfile.setRecentDeniedAccessCount(normalizeInteger(frictionProfile.getRecentDeniedAccessCount()));
        frictionProfile.setCheckedRecordKinds(new ArrayList<>(normalizeList(frictionProfile.getCheckedRecordKinds())
                .stream().map(kind -> kind.toUpperCase(Locale.ROOT)).distinct().toList()));
        // The words of the company records in one case, so the engine compares them as words (W2-6).
        if (frictionProfile.getApprovalRecords() != null) {
            for (CanonicalSecurityContext.ApprovalRecord record : frictionProfile.getApprovalRecords()) {
                if (record != null) {
                    record.setApprovalId(normalizeText(record.getApprovalId()));
                    record.setStatus(normalizeUpperText(record.getStatus()));
                    record.setTarget(normalizeText(record.getTarget()));
                    record.setMaxItems(normalizeInteger(record.getMaxItems()));
                    record.setUsedItems(normalizeInteger(record.getUsedItems()));
                }
            }
        }
        if (frictionProfile.getTicketRecords() != null) {
            for (CanonicalSecurityContext.TicketRecord record : frictionProfile.getTicketRecords()) {
                if (record != null) {
                    record.setTicketId(normalizeText(record.getTicketId()));
                    record.setKind(normalizeUpperText(record.getKind()));
                    record.setStatus(normalizeUpperText(record.getStatus()));
                    record.setTarget(normalizeText(record.getTarget()));
                }
            }
        }
        if (frictionProfile.getPolicies() != null) {
            for (CanonicalSecurityContext.CompanyPolicy policy : frictionProfile.getPolicies()) {
                if (policy == null) {
                    continue;
                }
                policy.setPolicyId(normalizeText(policy.getPolicyId()));
                policy.setRequirement(normalizeUpperText(policy.getRequirement()));
                policy.setRequiredTicketKind(normalizeUpperText(policy.getRequiredTicketKind()));
                if (policy.getExceptions() != null) {
                    for (CanonicalSecurityContext.PolicyException exception : policy.getExceptions()) {
                        if (exception != null) {
                            exception.setKind(normalizeUpperText(exception.getKind()));
                            exception.setLimit(normalizeInteger(exception.getLimit()));
                        }
                    }
                }
            }
        }
    }

    private void hardenReasoningMemoryProfile(CanonicalSecurityContext.ReasoningMemoryProfile reasoningMemoryProfile) {
        reasoningMemoryProfile.setSummary(normalizeText(reasoningMemoryProfile.getSummary()));
        reasoningMemoryProfile.setReinforcedCaseCount(normalizeLong(reasoningMemoryProfile.getReinforcedCaseCount()));
        reasoningMemoryProfile.setHardNegativeCaseCount(normalizeLong(reasoningMemoryProfile.getHardNegativeCaseCount()));
        reasoningMemoryProfile.setFalseNegativeCaseCount(normalizeLong(reasoningMemoryProfile.getFalseNegativeCaseCount()));
        reasoningMemoryProfile.setKnowledgeAssistedCaseCount(normalizeLong(reasoningMemoryProfile.getKnowledgeAssistedCaseCount()));
        reasoningMemoryProfile.setObjectiveAwareReasoningMemory(normalizeText(reasoningMemoryProfile.getObjectiveAwareReasoningMemory()));
        reasoningMemoryProfile.setRetentionTier(normalizeUpperText(reasoningMemoryProfile.getRetentionTier()));
        reasoningMemoryProfile.setRecallPriority(normalizeUpperText(reasoningMemoryProfile.getRecallPriority()));
        reasoningMemoryProfile.setFreshnessState(normalizeUpperText(reasoningMemoryProfile.getFreshnessState()));
        reasoningMemoryProfile.setReasoningState(normalizeUpperText(reasoningMemoryProfile.getReasoningState()));
        reasoningMemoryProfile.setCohortPreference(normalizeUpperText(reasoningMemoryProfile.getCohortPreference()));
        reasoningMemoryProfile.setMemoryRiskProfile(normalizeUpperText(reasoningMemoryProfile.getMemoryRiskProfile()));
        reasoningMemoryProfile.setRetrievalWeight(normalizeInteger(reasoningMemoryProfile.getRetrievalWeight()));
        reasoningMemoryProfile.setMatchedSignalKeys(normalizeList(reasoningMemoryProfile.getMatchedSignalKeys()));
        reasoningMemoryProfile.setObjectiveFamilies(normalizeList(reasoningMemoryProfile.getObjectiveFamilies()));
        reasoningMemoryProfile.setMemoryGuardrails(normalizeList(reasoningMemoryProfile.getMemoryGuardrails()));
        reasoningMemoryProfile.setXaiLinkedFacts(normalizeList(reasoningMemoryProfile.getXaiLinkedFacts()));
        reasoningMemoryProfile.setReasoningFacts(normalizeList(reasoningMemoryProfile.getReasoningFacts()));
        reasoningMemoryProfile.setCrossTenantObjectiveMisusePackSummary(normalizeText(reasoningMemoryProfile.getCrossTenantObjectiveMisusePackSummary()));
        reasoningMemoryProfile.setCrossTenantObjectiveMisuseFacts(normalizeList(reasoningMemoryProfile.getCrossTenantObjectiveMisuseFacts()));
    }

    private Integer normalizeInteger(Integer value) {
        if (value == null) {
            return null;
        }
        return Math.max(value, 0);
    }

    private Integer normalizeHour(Integer value) {
        if (value == null) {
            return null;
        }
        if (value < 0) {
            return 0;
        }
        if (value > 23) {
            return 23;
        }
        return value;
    }

    private Double normalizeDouble(Double value) {
        if (value == null) {
            return null;
        }
        return value < 0 ? 0.0 : value;
    }

    private Long normalizeLong(Long value) {
        if (value == null) {
            return null;
        }
        return Math.max(value, 0L);
    }

    private String normalizeText(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        return value.trim();
    }

    private String normalizeUpperText(String value) {
        String normalized = normalizeText(value);
        if (normalized == null) {
            return null;
        }
        return normalized.toUpperCase(Locale.ROOT);
    }

    /** Action family values in the one vocabulary ({@link ActionFamily}); a value that names none stays as stated. */
    private List<String> normalizeActionFamilies(List<String> values) {
        return normalizeList(values).stream()
                .map(ActionFamily::nameOrRaw)
                .filter(Objects::nonNull)
                .distinct()
                .collect(Collectors.toCollection(ArrayList::new));
    }

    private List<String> normalizeList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        for (String value : values) {
            String normalizedValue = normalizeText(value);
            if (normalizedValue != null) {
                normalized.add(normalizedValue);
            }
        }
        return new ArrayList<>(normalized);
    }

    /** A sequence: entries trimmed and blanks dropped, order and repeats kept. */
    private List<String> normalizeSequence(List<String> values) {
        if (values == null || values.isEmpty()) {
            return new ArrayList<>();
        }
        List<String> normalized = new ArrayList<>(values.size());
        for (String value : values) {
            String normalizedValue = normalizeText(value);
            if (normalizedValue != null) {
                normalized.add(normalizedValue);
            }
        }
        return normalized;
    }

    private List<Integer> normalizeIntegerList(List<Integer> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<Integer> normalized = new LinkedHashSet<>();
        for (Integer value : values) {
            Integer normalizedValue = normalizeInteger(value);
            if (normalizedValue != null) {
                normalized.add(normalizedValue);
            }
        }
        return new ArrayList<>(normalized);
    }

    private List<ContextTrustProfile> hardenTrustProfiles(List<ContextTrustProfile> trustProfiles) {
        if (trustProfiles == null || trustProfiles.isEmpty()) {
            return List.of();
        }
        List<ContextTrustProfile> normalizedProfiles = new ArrayList<>();
        for (ContextTrustProfile trustProfile : trustProfiles) {
            if (trustProfile == null) {
                continue;
            }
            trustProfile.setProfileKey(normalizeUpperText(trustProfile.getProfileKey()));
            trustProfile.setCollectorId(normalizeUpperText(trustProfile.getCollectorId()));
            trustProfile.setSummary(normalizeText(trustProfile.getSummary()));
            trustProfile.setProvenanceSummary(normalizeText(trustProfile.getProvenanceSummary()));
            trustProfile.setOverallQualityScore(normalizeInteger(trustProfile.getOverallQualityScore()));
            trustProfile.setScopeLimitations(normalizeList(trustProfile.getScopeLimitations()));
            trustProfile.setQualityWarnings(normalizeList(trustProfile.getQualityWarnings()));
            trustProfile.setFieldRecords(hardenFieldRecords(trustProfile.getFieldRecords()));
            trustProfile.setEvidenceRecords(hardenEvidenceRecords(trustProfile.getEvidenceRecords()));
            normalizedProfiles.add(trustProfile);
        }
        return normalizedProfiles;
    }

    private List<ContextFieldTrustRecord> hardenFieldRecords(List<ContextFieldTrustRecord> fieldRecords) {
        if (fieldRecords == null || fieldRecords.isEmpty()) {
            return List.of();
        }
        List<ContextFieldTrustRecord> normalizedRecords = new ArrayList<>();
        for (ContextFieldTrustRecord fieldRecord : fieldRecords) {
            if (fieldRecord == null) {
                continue;
            }
            fieldRecord.setFieldPath(normalizeText(fieldRecord.getFieldPath()));
            fieldRecord.setSemanticMeaning(normalizeText(fieldRecord.getSemanticMeaning()));
            fieldRecord.setIntendedUse(normalizeText(fieldRecord.getIntendedUse()));
            fieldRecord.setProvenanceSummary(normalizeText(fieldRecord.getProvenanceSummary()));
            fieldRecord.setObservationCount(normalizeInteger(fieldRecord.getObservationCount()));
            fieldRecord.setDaysCovered(normalizeInteger(fieldRecord.getDaysCovered()));
            fieldRecord.setFallbackRate(normalizeDouble(fieldRecord.getFallbackRate()));
            fieldRecord.setUnknownRate(normalizeDouble(fieldRecord.getUnknownRate()));
            fieldRecord.setQualityScore(normalizeInteger(fieldRecord.getQualityScore()));
            fieldRecord.setQualitySummary(normalizeText(fieldRecord.getQualitySummary()));
            fieldRecord.setSourceKeys(normalizeList(fieldRecord.getSourceKeys()));
            fieldRecord.setFallbackSourceKeys(normalizeList(fieldRecord.getFallbackSourceKeys()));
            fieldRecord.setEvidenceIds(normalizeList(fieldRecord.getEvidenceIds()));
            normalizedRecords.add(fieldRecord);
        }
        return normalizedRecords;
    }

    private List<ContextEvidenceRecord> hardenEvidenceRecords(List<ContextEvidenceRecord> evidenceRecords) {
        if (evidenceRecords == null || evidenceRecords.isEmpty()) {
            return List.of();
        }
        List<ContextEvidenceRecord> normalizedRecords = new ArrayList<>();
        for (ContextEvidenceRecord evidenceRecord : evidenceRecords) {
            if (evidenceRecord == null) {
                continue;
            }
            evidenceRecord.setEvidenceId(normalizeText(evidenceRecord.getEvidenceId()));
            evidenceRecord.setObservedAt(normalizeText(evidenceRecord.getObservedAt()));
            evidenceRecord.setSummary(normalizeText(evidenceRecord.getSummary()));
            evidenceRecord.setDecisionState(normalizeUpperText(evidenceRecord.getDecisionState()));
            evidenceRecord.setSourceKeys(normalizeMap(evidenceRecord.getSourceKeys()));
            evidenceRecord.setFlags(normalizeList(evidenceRecord.getFlags()));
            normalizedRecords.add(evidenceRecord);
        }
        return normalizedRecords;
    }

    private Map<String, String> normalizeMap(Map<String, String> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        Map<String, String> normalized = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : values.entrySet()) {
            String key = normalizeText(entry.getKey());
            String value = normalizeText(entry.getValue());
            if (key != null && value != null) {
                normalized.put(key, value);
            }
        }
        return normalized;
    }
}
