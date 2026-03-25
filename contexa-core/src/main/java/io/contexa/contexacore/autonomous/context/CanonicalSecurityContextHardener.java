package io.contexa.contexacore.autonomous.context;

import org.springframework.util.StringUtils;

import java.util.*;

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
        session.setAuthenticationType(normalizeUpperText(session.getAuthenticationType()));
        session.setAuthenticationAssurance(normalizeUpperText(session.getAuthenticationAssurance()));
        session.setRecentMfaFailureCount(normalizeInteger(session.getRecentMfaFailureCount()));
        session.setLastMfaUsedAt(normalizeText(session.getLastMfaUsedAt()));
        session.setFailedLoginAttempts(normalizeInteger(session.getFailedLoginAttempts()));
        session.setRecentRequestCount(normalizeInteger(session.getRecentRequestCount()));
        session.setRecentChallengeCount(normalizeInteger(session.getRecentChallengeCount()));
        session.setRecentBlockCount(normalizeInteger(session.getRecentBlockCount()));
        session.setRecentEscalationCount(normalizeInteger(session.getRecentEscalationCount()));
    }

    private void hardenResource(CanonicalSecurityContext.Resource resource) {
        resource.setResourceId(normalizeText(resource.getResourceId()));
        resource.setResourceType(normalizeUpperText(resource.getResourceType()));
        resource.setBusinessLabel(normalizeText(resource.getBusinessLabel()));
        resource.setSensitivity(normalizeUpperText(resource.getSensitivity()));
        resource.setRequestPath(normalizeText(resource.getRequestPath()));
        resource.setHttpMethod(normalizeUpperText(resource.getHttpMethod()));
        resource.setActionFamily(normalizeUpperText(resource.getActionFamily()));
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
        observedScope.setFrequentActionFamilies(normalizeList(observedScope.getFrequentActionFamilies()));
    }

    private void hardenSessionNarrativeProfile(CanonicalSecurityContext.SessionNarrativeProfile sessionNarrativeProfile) {
        sessionNarrativeProfile.setSummary(normalizeText(sessionNarrativeProfile.getSummary()));
        sessionNarrativeProfile.setSessionAgeMinutes(normalizeInteger(sessionNarrativeProfile.getSessionAgeMinutes()));
        sessionNarrativeProfile.setPreviousPath(normalizeText(sessionNarrativeProfile.getPreviousPath()));
        sessionNarrativeProfile.setPreviousActionFamily(normalizeUpperText(sessionNarrativeProfile.getPreviousActionFamily()));
        sessionNarrativeProfile.setLastRequestIntervalMs(normalizeLong(sessionNarrativeProfile.getLastRequestIntervalMs()));
        sessionNarrativeProfile.setSessionActionSequence(normalizeList(sessionNarrativeProfile.getSessionActionSequence()));
        sessionNarrativeProfile.setSessionProtectableSequence(normalizeList(sessionNarrativeProfile.getSessionProtectableSequence()));
    }

    private void hardenWorkProfile(CanonicalSecurityContext.WorkProfile workProfile) {
        workProfile.setSummary(normalizeText(workProfile.getSummary()));
        workProfile.setFrequentProtectableResources(normalizeList(workProfile.getFrequentProtectableResources()));
        workProfile.setFrequentActionFamilies(normalizeList(workProfile.getFrequentActionFamilies()));
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
        roleScopeProfile.setCurrentActionFamily(normalizeUpperText(roleScopeProfile.getCurrentActionFamily()));
        roleScopeProfile.setExpectedResourceFamilies(normalizeList(roleScopeProfile.getExpectedResourceFamilies()));
        roleScopeProfile.setExpectedActionFamilies(normalizeList(roleScopeProfile.getExpectedActionFamilies()));
        roleScopeProfile.setForbiddenResourceFamilies(normalizeList(roleScopeProfile.getForbiddenResourceFamilies()));
        roleScopeProfile.setForbiddenActionFamilies(normalizeList(roleScopeProfile.getForbiddenActionFamilies()));
        roleScopeProfile.setNormalApprovalPatterns(normalizeList(roleScopeProfile.getNormalApprovalPatterns()));
        roleScopeProfile.setNormalEscalationPatterns(normalizeList(roleScopeProfile.getNormalEscalationPatterns()));
        roleScopeProfile.setRecentPermissionChanges(normalizeList(roleScopeProfile.getRecentPermissionChanges()));
        roleScopeProfile.setTemporaryElevationReason(normalizeText(roleScopeProfile.getTemporaryElevationReason()));
        roleScopeProfile.setElevationWindowSummary(normalizeText(roleScopeProfile.getElevationWindowSummary()));
    }

    private void hardenPeerCohortProfile(CanonicalSecurityContext.PeerCohortProfile peerCohortProfile) {
        peerCohortProfile.setCohortId(normalizeText(peerCohortProfile.getCohortId()));
        peerCohortProfile.setSummary(normalizeText(peerCohortProfile.getSummary()));
        peerCohortProfile.setPreferredResources(normalizeList(peerCohortProfile.getPreferredResources()));
        peerCohortProfile.setPreferredActionFamilies(normalizeList(peerCohortProfile.getPreferredActionFamilies()));
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
