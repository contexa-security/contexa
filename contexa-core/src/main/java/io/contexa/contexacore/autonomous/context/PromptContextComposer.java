package io.contexa.contexacore.autonomous.context;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

public class PromptContextComposer {

    public String compose(CanonicalSecurityContext context) {
        if (context == null) {
            return null;
        }

        StringBuilder section = new StringBuilder();
        appendSection(section, composeBridgeSection(context));
        appendSection(section, composeCoverageSection(context));
        appendSection(section, composeIdentitySection(context));
        appendSection(section, composeAuthenticationAndAssuranceSection(context));
        appendSection(section, composeResourceSection(context));
        appendSection(section, composeSessionNarrativeSection(context));
        appendSection(section, composeObservedScopeSection(context));
        appendSection(section, composeWorkProfileSection(context));
        appendSection(section, composeRoleScopeSection(context));
        appendSection(section, composePeerCohortSection(context));
        appendSection(section, composeFrictionSection(context));
        appendSection(section, composeDelegationSection(context));
        appendSection(section, composeReasoningMemorySection(context));
        appendSection(section, composeMissingKnowledgeSection(context));

        return section.isEmpty() ? null : section.toString();
    }

    public String composeBridgeSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendBridgeSection(section, context.getBridge()));
    }

    public String composeCoverageSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendCoverageSection(section, context.getCoverage()));
    }

    public String composeIdentitySection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendIdentitySection(section, context));
    }

    public String composeAuthenticationAndAssuranceSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendAuthenticationAndAssuranceSection(section, context.getSession()));
    }

    public String composeResourceSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendResourceSection(section, context.getResource()));
    }

    public String composeSessionNarrativeSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendSessionNarrativeSection(section, context.getSessionNarrativeProfile()));
    }

    public String composeObservedScopeSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendObservedScopeSection(section, context));
    }

    public String composeWorkProfileSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendWorkProfileSection(section, context.getWorkProfile()));
    }

    public String composeContextQualityAndProvenanceSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendContextQualityAndProvenanceSection(section, context.getContextTrustProfiles()));
    }

    public String composeRoleScopeSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendRoleScopeSection(section, context.getRoleScopeProfile()));
    }

    public String composePeerCohortSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendPeerCohortSection(section, context));
    }

    public String composeFrictionSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendFrictionSection(section, context.getFrictionProfile()));
    }

    public String composeDelegationSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendDelegationSection(section, context.getDelegation()));
    }

    public String composeReasoningMemorySection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendReasoningMemorySection(section, context.getReasoningMemoryProfile()));
    }

    public String composeMissingKnowledgeSection(CanonicalSecurityContext context) {
        return composeSection(context, section -> appendMissingKnowledgeSection(section, context));
    }

    private String composeSection(CanonicalSecurityContext context, java.util.function.Consumer<StringBuilder> composer) {
        if (context == null) {
            return null;
        }
        StringBuilder section = new StringBuilder();
        composer.accept(section);
        return section.isEmpty() ? null : section.toString();
    }

    private void appendSection(StringBuilder target, String section) {
        if (StringUtils.hasText(section)) {
            target.append(section);
        }
    }

    private void appendBridgeSection(StringBuilder section, CanonicalSecurityContext.Bridge bridge) {
        if (bridge == null) {
            return;
        }
        section.append("\n=== BRIDGE RESOLUTION CONTEXT ===\n");
        appendLine(section, "BridgeCompletenessLevel", bridge.getCoverageLevel());
        appendLine(section, "BridgeCompletenessSummary", bridge.getSummary());
        appendLine(section, "BridgeAuthenticationSource", bridge.getAuthenticationSource());
        appendLine(section, "BridgeAuthorizationSource", bridge.getAuthorizationSource());
        appendLine(section, "BridgeDelegationSource", bridge.getDelegationSource());
        appendList(section, "BridgeMissingContexts", bridge.getMissingContexts());
        appendList(section, "BridgeRemediationHints", bridge.getRemediationHints());
    }

    private void appendCoverageSection(StringBuilder section, ContextCoverageReport coverage) {
        if (coverage == null) {
            return;
        }
        section.append("\n=== CONTEXT COVERAGE ===\n");
        section.append("CoverageLevel: ").append(coverage.level()).append("\n");
        section.append("CoverageSummary: ").append(coverage.summary()).append("\n");
        if (!coverage.availableFacts().isEmpty()) {
            section.append("AvailableFacts:\n");
            for (String fact : coverage.availableFacts()) {
                section.append("- ").append(fact).append("\n");
            }
        }
        if (!coverage.missingCriticalFacts().isEmpty()) {
            section.append("MissingCriticalFacts:\n");
            for (String fact : coverage.missingCriticalFacts()) {
                section.append("- ").append(fact).append("\n");
            }
        }
        if (!coverage.remediationHints().isEmpty()) {
            section.append("RemediationHints:\n");
            for (String hint : coverage.remediationHints()) {
                section.append("- ").append(hint).append("\n");
            }
        }
        if (!coverage.confidenceWarnings().isEmpty()) {
            section.append("ConfidenceWarnings:\n");
            for (String warning : coverage.confidenceWarnings()) {
                section.append("- ").append(warning).append("\n");
            }
        }
    }

    private void appendIdentitySection(StringBuilder section, CanonicalSecurityContext context) {
        CanonicalSecurityContext.Actor actor = context.getActor();
        CanonicalSecurityContext.Authorization authorization = context.getAuthorization();
        if (actor == null && authorization == null) {
            return;
        }

        section.append("\n=== IDENTITY AND ROLE CONTEXT ===\n");
        if (actor != null) {
            appendLine(section, "UserId", actor.getUserId());
            appendLine(section, "ExternalSubjectId", actor.getExternalSubjectId());
            appendLine(section, "OrganizationId", actor.getOrganizationId());
            appendLine(section, "TenantId", actor.getTenantId());
            appendLine(section, "Department", actor.getDepartment());
            appendLine(section, "Position", actor.getPosition());
            appendLine(section, "PrincipalType", actor.getPrincipalType());
            appendLine(section, "BridgeSubjectKey", actor.getBridgeSubjectKey());
            appendList(section, "RoleSet", actor.getRoleSet());
            appendList(section, "AuthoritySet", actor.getAuthoritySet());
        }
        if (authorization != null) {
            appendList(section, "EffectiveRoles", authorization.getEffectiveRoles());
            appendList(section, "EffectivePermissions", authorization.getEffectivePermissions());
            appendList(section, "ScopeTags", authorization.getScopeTags());
            appendLine(section, "AuthorizationEffect", authorization.getAuthorizationEffect());
            appendLine(section, "PolicyId", authorization.getPolicyId());
            appendLine(section, "PolicyVersion", authorization.getPolicyVersion());
            appendLine(section, "PrivilegedFlow", authorization.getPrivileged());
        }
    }

    private void appendAuthenticationAndAssuranceSection(StringBuilder section, CanonicalSecurityContext.Session session) {
        if (session == null) {
            return;
        }

        section.append("\n=== AUTHENTICATION AND ASSURANCE CONTEXT ===\n");
        appendLine(section, "SessionId", session.getSessionId());
        appendLine(section, "ClientIp", session.getClientIp());
        appendLine(section, "UserAgent", session.getUserAgent());
        appendLine(section, "AuthenticationType", session.getAuthenticationType());
        appendLine(section, "AuthenticationAssurance", session.getAuthenticationAssurance());
        appendLine(section, "MfaVerified", session.getMfaVerified());
        appendLine(section, "RecentMfaFailureCount", session.getRecentMfaFailureCount());
        appendLine(section, "LastMfaUsedAt", session.getLastMfaUsedAt());
        appendLine(section, "FailedLoginAttempts", session.getFailedLoginAttempts());
        appendLine(section, "RecentRequestCount", session.getRecentRequestCount());
        appendLine(section, "RecentChallengeCount", session.getRecentChallengeCount());
        appendLine(section, "RecentBlockCount", session.getRecentBlockCount());
        appendLine(section, "RecentEscalationCount", session.getRecentEscalationCount());
        appendLine(section, "BlockedUser", session.getBlockedUser());
        appendLine(section, "NewSession", session.getNewSession());
        appendLine(section, "NewUser", session.getNewUser());
        appendLine(section, "NewDevice", session.getNewDevice());
    }

    private void appendResourceSection(StringBuilder section, CanonicalSecurityContext.Resource resource) {
        if (resource == null) {
            return;
        }

        section.append("\n=== RESOURCE AND ACTION CONTEXT ===\n");
        appendLine(section, "ResourceId", resource.getResourceId());
        appendLine(section, "RequestPath", resource.getRequestPath());
        appendLine(section, "HttpMethod", resource.getHttpMethod());
        appendLine(section, "ActionFamily", resource.getActionFamily());
        appendLine(section, "ResourceType", resource.getResourceType());
        appendLine(section, "BusinessLabel", resource.getBusinessLabel());
        appendLine(section, "Sensitivity", resource.getSensitivity());
        appendLine(section, "SensitiveResource", resource.getSensitiveResource());
        appendLine(section, "PrivilegedResource", resource.getPrivileged());
        appendLine(section, "ExportSensitive", resource.getExportSensitive());
    }

    private void appendSessionNarrativeSection(StringBuilder section, CanonicalSecurityContext.SessionNarrativeProfile sessionNarrativeProfile) {
        if (sessionNarrativeProfile == null) {
            return;
        }

        section.append("\n=== SESSION NARRATIVE CONTEXT ===\n");
        appendLine(section, "SessionNarrativeSummary", sessionNarrativeProfile.getSummary());
        appendLine(section, "SessionAgeMinutes", sessionNarrativeProfile.getSessionAgeMinutes());
        appendLine(section, "PreviousPath", sessionNarrativeProfile.getPreviousPath());
        appendLine(section, "PreviousActionFamily", sessionNarrativeProfile.getPreviousActionFamily());
        appendLine(section, "LastRequestIntervalMs", sessionNarrativeProfile.getLastRequestIntervalMs());
        appendList(section, "SessionActionSequence", sessionNarrativeProfile.getSessionActionSequence());
        appendList(section, "SessionProtectableSequence", sessionNarrativeProfile.getSessionProtectableSequence());
        appendLine(section, "BurstPattern", sessionNarrativeProfile.getBurstPattern());
    }

    private void appendObservedScopeSection(StringBuilder section, CanonicalSecurityContext context) {
        CanonicalSecurityContext.ObservedScope observedScope = context != null ? context.getObservedScope() : null;
        if (observedScope == null) {
            return;
        }

        section.append("\n=== OBSERVED WORK PATTERN CONTEXT ===\n");
        appendLine(section, "ProfileSource", observedScope.getProfileSource());
        appendLine(section, "ObservedScopeSummary", observedScope.getSummary());
        appendLine(section, "RecentProtectableAccessCount", observedScope.getRecentProtectableAccessCount());
        appendLine(section, "RecentDeniedAccessCount", observedScope.getRecentDeniedAccessCount());
        appendLine(section, "RecentSensitiveAccessCount", observedScope.getRecentSensitiveAccessCount());
        appendList(section, "FrequentResources", observedScope.getFrequentResources());
        appendList(section, "FrequentActionFamilies", observedScope.getFrequentActionFamilies());
        appendComparisonEvidence(
                section,
                "CurrentResourcePresentInObservedHistory",
                resolveCurrentResourceValue(context),
                observedScope.getFrequentResources(),
                observedScope.getRareCurrentResource());
        appendComparisonEvidence(
                section,
                "CurrentActionFamilyPresentInObservedHistory",
                resolveCurrentActionFamily(context),
                observedScope.getFrequentActionFamilies(),
                observedScope.getRareCurrentActionFamily());
    }

    private void appendWorkProfileSection(StringBuilder section, CanonicalSecurityContext.WorkProfile workProfile) {
        if (workProfile == null) {
            return;
        }

        section.append("\n=== PERSONAL WORK PROFILE ===\n");
        appendLine(section, "WorkProfileSummary", workProfile.getSummary());
        appendList(section, "FrequentProtectableResources", workProfile.getFrequentProtectableResources());
        appendList(section, "FrequentActionFamilies", workProfile.getFrequentActionFamilies());
        appendList(section, "FrequentSensitiveResourceCategories", workProfile.getFrequentSensitiveResourceCategories());
        appendList(section, "ProtectableResourceHeatmap", workProfile.getProtectableResourceHeatmap());
        appendIntegerList(section, "NormalAccessHours", workProfile.getNormalAccessHours());
        appendIntegerList(section, "NormalAccessDays", workProfile.getNormalAccessDays());
        appendLine(section, "NormalRequestRate", workProfile.getNormalRequestRate());
        appendLine(section, "NormalSessionLengthMinutes", workProfile.getNormalSessionLengthMinutes());
        appendLine(section, "NormalReadWriteExportRatio", workProfile.getNormalReadWriteExportRatio());
        appendLine(section, "NormalPrivilegedActionFrequency", workProfile.getNormalPrivilegedActionFrequency());
        appendLine(section, "ProtectableInvocationDensity", workProfile.getProtectableInvocationDensity());
        appendLine(section, "SeasonalBusinessProfile", workProfile.getSeasonalBusinessProfile());
        appendList(section, "LongTailLegitimateTasks", workProfile.getLongTailLegitimateTasks());
    }

    private void appendContextQualityAndProvenanceSection(StringBuilder section, List<ContextTrustProfile> trustProfiles) {
        if (trustProfiles == null || trustProfiles.isEmpty()) {
            return;
        }

        section.append("\n=== CONTEXT QUALITY AND PROVENANCE ===\n");
        for (ContextTrustProfile trustProfile : trustProfiles) {
            if (trustProfile == null) {
                continue;
            }
            appendLine(section, "TrustProfileKey", trustProfile.getProfileKey());
            appendLine(section, "TrustCollectorId", trustProfile.getCollectorId());
            appendLine(section, "TrustProfileSummary", trustProfile.getSummary());
            appendLine(section, "TrustProvenanceSummary", trustProfile.getProvenanceSummary());
            appendList(section, "TrustScopeLimitations", trustProfile.getScopeLimitations());
            appendList(section, "TrustQualityWarnings", trustProfile.getQualityWarnings());
            if (!trustProfile.getFieldRecords().isEmpty()) {
                section.append("TrustFieldAudits:\n");
                for (ContextFieldTrustRecord fieldRecord : trustProfile.getFieldRecords()) {
                    if (fieldRecord == null) {
                        continue;
                    }
                    section.append("- ")
                            .append(fieldRecord.getFieldPath())
                            .append(" | observations=")
                            .append(fieldRecord.getObservationCount())
                            .append(" | days=")
                            .append(fieldRecord.getDaysCovered())
                            .append(" | fallback=")
                            .append(formatPercent(fieldRecord.getFallbackRate()))
                            .append(" | unknown=")
                            .append(formatPercent(fieldRecord.getUnknownRate()))
                            .append(" | provenance=")
                            .append(fieldRecord.getProvenanceSummary())
                            .append(" | evidenceState=")
                            .append(describeFieldEvidenceState(fieldRecord))
                            .append("\n");
                }
            }
            if (!trustProfile.getEvidenceRecords().isEmpty()) {
                section.append("TrustEvidence:\n");
                for (ContextEvidenceRecord evidenceRecord : trustProfile.getEvidenceRecords()) {
                    if (evidenceRecord == null) {
                        continue;
                    }
                    section.append("- ")
                            .append(evidenceRecord.getEvidenceId())
                            .append(" | ")
                            .append(evidenceRecord.getSummary())
                            .append("\n");
                }
            }
        }
    }

    private void appendRoleScopeSection(StringBuilder section, CanonicalSecurityContext.RoleScopeProfile roleScopeProfile) {
        if (roleScopeProfile == null) {
            return;
        }

        section.append("\n=== ROLE AND WORK SCOPE CONTEXT ===\n");
        appendLine(section, "RoleScopeSummary", roleScopeProfile.getSummary());
        appendLine(section, "CurrentResourceFamily", roleScopeProfile.getCurrentResourceFamily());
        appendLine(section, "CurrentActionFamily", roleScopeProfile.getCurrentActionFamily());
        appendList(section, "ExpectedResourceFamilies", roleScopeProfile.getExpectedResourceFamilies());
        appendList(section, "ExpectedActionFamilies", roleScopeProfile.getExpectedActionFamilies());
        appendList(section, "ForbiddenResourceFamilies", roleScopeProfile.getForbiddenResourceFamilies());
        appendList(section, "ForbiddenActionFamilies", roleScopeProfile.getForbiddenActionFamilies());
        appendList(section, "NormalApprovalPatterns", roleScopeProfile.getNormalApprovalPatterns());
        appendList(section, "NormalEscalationPatterns", roleScopeProfile.getNormalEscalationPatterns());
        appendList(section, "RecentPermissionChanges", roleScopeProfile.getRecentPermissionChanges());
        appendComparisonEvidence(
                section,
                "CurrentResourceFamilyPresentInExpectedRoleScope",
                roleScopeProfile.getCurrentResourceFamily(),
                roleScopeProfile.getExpectedResourceFamilies(),
                !roleScopeProfile.getExpectedResourceFamilies().isEmpty()
                        ? ContextSemanticBoundaryPolicy.comparisonIncludesCurrent(
                        roleScopeProfile.getCurrentResourceFamily(),
                        roleScopeProfile.getExpectedResourceFamilies())
                        : null);
        appendComparisonEvidence(
                section,
                "CurrentResourceFamilyPresentInDeniedRoleScope",
                roleScopeProfile.getCurrentResourceFamily(),
                roleScopeProfile.getForbiddenResourceFamilies(),
                !roleScopeProfile.getForbiddenResourceFamilies().isEmpty()
                        ? ContextSemanticBoundaryPolicy.comparisonIncludesCurrent(
                        roleScopeProfile.getCurrentResourceFamily(),
                        roleScopeProfile.getForbiddenResourceFamilies())
                        : null);
        appendComparisonEvidence(
                section,
                "CurrentActionFamilyPresentInExpectedRoleScope",
                roleScopeProfile.getCurrentActionFamily(),
                roleScopeProfile.getExpectedActionFamilies(),
                !roleScopeProfile.getExpectedActionFamilies().isEmpty()
                        ? ContextSemanticBoundaryPolicy.comparisonIncludesCurrent(
                        roleScopeProfile.getCurrentActionFamily(),
                        roleScopeProfile.getExpectedActionFamilies())
                        : null);
        appendComparisonEvidence(
                section,
                "CurrentActionFamilyPresentInDeniedRoleScope",
                roleScopeProfile.getCurrentActionFamily(),
                roleScopeProfile.getForbiddenActionFamilies(),
                !roleScopeProfile.getForbiddenActionFamilies().isEmpty()
                        ? ContextSemanticBoundaryPolicy.comparisonIncludesCurrent(
                        roleScopeProfile.getCurrentActionFamily(),
                        roleScopeProfile.getForbiddenActionFamilies())
                        : null);
        appendLine(section, "TemporaryElevation", roleScopeProfile.getTemporaryElevation());
        appendLine(section, "TemporaryElevationReason", roleScopeProfile.getTemporaryElevationReason());
        appendLine(section, "ElevatedPrivilegeWindowActive", roleScopeProfile.getElevatedPrivilegeWindowActive());
        appendLine(section, "ElevationWindowSummary", roleScopeProfile.getElevationWindowSummary());
    }

    private void appendPeerCohortSection(StringBuilder section, CanonicalSecurityContext context) {
        CanonicalSecurityContext.PeerCohortProfile peerCohortProfile = context != null ? context.getPeerCohortProfile() : null;
        if (peerCohortProfile == null) {
            return;
        }

        section.append("\n=== PEER COHORT DELTA ===\n");
        appendLine(section, "PeerCohortId", peerCohortProfile.getCohortId());
        appendLine(section, "PeerCohortSummary", peerCohortProfile.getSummary());
        appendList(section, "CohortPreferredResources", peerCohortProfile.getPreferredResources());
        appendList(section, "CohortPreferredActionFamilies", peerCohortProfile.getPreferredActionFamilies());
        appendLine(section, "CohortNormalProtectableFrequencyBand", peerCohortProfile.getNormalProtectableFrequencyBand());
        appendLine(section, "CohortNormalSensitivityBand", peerCohortProfile.getNormalSensitivityBand());
        appendComparisonEvidence(
                section,
                "CurrentResourcePresentInPeerPreferredResources",
                resolveCurrentResourceValue(context),
                peerCohortProfile.getPreferredResources(),
                !peerCohortProfile.getPreferredResources().isEmpty()
                        ? containsIgnoreCase(peerCohortProfile.getPreferredResources(), resolveCurrentResourceValue(context))
                        : null);
        appendComparisonEvidence(
                section,
                "CurrentActionFamilyPresentInPeerPreferredActions",
                resolveCurrentActionFamily(context),
                peerCohortProfile.getPreferredActionFamilies(),
                !peerCohortProfile.getPreferredActionFamilies().isEmpty()
                        ? containsIgnoreCase(peerCohortProfile.getPreferredActionFamilies(), resolveCurrentActionFamily(context))
                        : null);
    }

    private void appendFrictionSection(StringBuilder section, CanonicalSecurityContext.FrictionProfile frictionProfile) {
        if (frictionProfile == null) {
            return;
        }

        section.append("\n=== FRICTION AND APPROVAL HISTORY ===\n");
        appendLine(section, "FrictionSummary", frictionProfile.getSummary());
        appendLine(section, "RecentChallengeCount", frictionProfile.getRecentChallengeCount());
        appendLine(section, "RecentBlockCount", frictionProfile.getRecentBlockCount());
        appendLine(section, "RecentEscalationCount", frictionProfile.getRecentEscalationCount());
        appendLine(section, "ApprovalRequired", frictionProfile.getApprovalRequired());
        appendLine(section, "ApprovalGranted", frictionProfile.getApprovalGranted());
        appendLine(section, "ApprovalMissing", frictionProfile.getApprovalMissing());
        appendLine(section, "ApprovalStatus", frictionProfile.getApprovalStatus());
        appendList(section, "ApprovalLineage", frictionProfile.getApprovalLineage());
        appendList(section, "PendingApproverRoles", frictionProfile.getPendingApproverRoles());
        appendLine(section, "ApprovalTicketId", frictionProfile.getApprovalTicketId());
        appendLine(section, "ApprovalDecisionAgeMinutes", frictionProfile.getApprovalDecisionAgeMinutes());
        appendLine(section, "BreakGlass", frictionProfile.getBreakGlass());
        appendLine(section, "RecentDeniedAccessCount", frictionProfile.getRecentDeniedAccessCount());
        appendLine(section, "BlockedUser", frictionProfile.getBlockedUser());
    }

    private void appendDelegationSection(StringBuilder section, CanonicalSecurityContext.Delegation delegation) {
        if (delegation == null || !hasDelegationData(delegation)) {
            return;
        }

        section.append("\n=== DELEGATED OBJECTIVE CONTEXT ===\n");
        appendLine(section, "Delegated", delegation.getDelegated());
        appendLine(section, "AgentId", delegation.getAgentId());
        appendLine(section, "ObjectiveId", delegation.getObjectiveId());
        appendLine(section, "ObjectiveFamily", delegation.getObjectiveFamily());
        appendLine(section, "ObjectiveSummary", delegation.getObjectiveSummary());
        appendList(section, "AllowedOperations", delegation.getAllowedOperations());
        appendList(section, "AllowedResources", delegation.getAllowedResources());
        appendLine(section, "ApprovalRequired", delegation.getApprovalRequired());
        appendLine(section, "PrivilegedExportAllowed", delegation.getPrivilegedExportAllowed());
        appendLine(section, "ContainmentOnly", delegation.getContainmentOnly());
        appendLine(section, "ObjectiveAlignmentEvidence", delegation.getObjectiveDriftSummary());
    }

    private void appendReasoningMemorySection(StringBuilder section, CanonicalSecurityContext.ReasoningMemoryProfile reasoningMemoryProfile) {
        if (reasoningMemoryProfile == null) {
            return;
        }

        section.append("\n=== OUTCOME AND REASONING MEMORY ===\n");
        appendLine(section, "ReasoningMemorySummary", reasoningMemoryProfile.getSummary());
        appendLine(section, "ReinforcedCaseCount", reasoningMemoryProfile.getReinforcedCaseCount());
        appendLine(section, "HardNegativeCaseCount", reasoningMemoryProfile.getHardNegativeCaseCount());
        appendLine(section, "FalseNegativeCaseCount", reasoningMemoryProfile.getFalseNegativeCaseCount());
        appendLine(section, "KnowledgeAssistedCaseCount", reasoningMemoryProfile.getKnowledgeAssistedCaseCount());
        appendLine(section, "ObjectiveAwareReasoningMemory", reasoningMemoryProfile.getObjectiveAwareReasoningMemory());
        appendLine(section, "RetentionTier", reasoningMemoryProfile.getRetentionTier());
        appendLine(section, "RecallPriority", reasoningMemoryProfile.getRecallPriority());
        appendLine(section, "FreshnessState", reasoningMemoryProfile.getFreshnessState());
        appendLine(section, "ReasoningState", reasoningMemoryProfile.getReasoningState());
        appendLine(section, "CohortPreference", reasoningMemoryProfile.getCohortPreference());
        appendLine(section, "MemoryRiskProfile", reasoningMemoryProfile.getMemoryRiskProfile());
        appendLine(section, "RetrievalWeight", reasoningMemoryProfile.getRetrievalWeight());
        appendList(section, "MatchedSignalKeys", reasoningMemoryProfile.getMatchedSignalKeys());
        appendList(section, "ObjectiveFamilies", reasoningMemoryProfile.getObjectiveFamilies());
        appendList(section, "MemoryGuardrails", reasoningMemoryProfile.getMemoryGuardrails());
        appendList(section, "XaiLinkedFacts", reasoningMemoryProfile.getXaiLinkedFacts());
        appendList(section, "ReasoningFacts", reasoningMemoryProfile.getReasoningFacts());
        appendLine(section, "CrossTenantObjectiveMisusePackSummary", reasoningMemoryProfile.getCrossTenantObjectiveMisusePackSummary());
        appendList(section, "CrossTenantObjectiveMisuseFacts", reasoningMemoryProfile.getCrossTenantObjectiveMisuseFacts());
    }

    private void appendMissingKnowledgeSection(StringBuilder section, CanonicalSecurityContext context) {
        ContextCoverageReport coverage = context.getCoverage();
        List<ContextTrustProfile> trustProfiles = context.getContextTrustProfiles();
        if (!hasMissingKnowledge(coverage, trustProfiles)) {
            return;
        }

        section.append("\n=== EXPLICIT MISSING KNOWLEDGE ===\n");
        if (coverage != null) {
            for (String fact : coverage.missingCriticalFacts()) {
                section.append("- ").append(fact).append("\n");
            }
            for (String hint : coverage.remediationHints()) {
                section.append("- Remediation: ").append(hint).append("\n");
            }
            for (String warning : coverage.confidenceWarnings()) {
                section.append("- ConfidenceWarning: ").append(warning).append("\n");
            }
        }
        if (trustProfiles == null || trustProfiles.isEmpty()) {
            return;
        }
        for (ContextTrustProfile trustProfile : trustProfiles) {
            if (trustProfile == null || !hasTrustGating(trustProfile)) {
                continue;
            }
            section.append("- ContextEvidenceLimitation: ")
                    .append(trustProfile.getProfileKey())
                    .append(" | collector=")
                    .append(trustProfile.getCollectorId())
                    .append(" | provenance=")
                    .append(trustProfile.getProvenanceSummary())
                    .append(" | evidenceState=")
                    .append(describeProfileEvidenceState(trustProfile))
                    .append("\n");
            for (String limitation : trustProfile.getScopeLimitations()) {
                section.append("- ContextTrustLimitation: ")
                        .append(trustProfile.getProfileKey())
                        .append(" | ")
                        .append(limitation)
                        .append("\n");
            }
            for (String warning : trustProfile.getQualityWarnings()) {
                section.append("- ContextTrustWarning: ")
                        .append(trustProfile.getProfileKey())
                        .append(" | ")
                        .append(warning)
                        .append("\n");
            }
            for (ContextFieldTrustRecord fieldRecord : trustProfile.getFieldRecords()) {
                if (fieldRecord == null || !ContextSemanticBoundaryPolicy.requiresEvidenceCaution(fieldRecord)) {
                    continue;
                }
                section.append("- ContextFieldCoverage: ")
                        .append(fieldRecord.getFieldPath())
                        .append(" | observations=")
                        .append(fieldRecord.getObservationCount())
                        .append(" | days=")
                        .append(fieldRecord.getDaysCovered())
                        .append(" | fallback=")
                        .append(formatPercent(fieldRecord.getFallbackRate()))
                        .append(" | unknown=")
                        .append(formatPercent(fieldRecord.getUnknownRate()))
                        .append(" | provenance=")
                        .append(fieldRecord.getProvenanceSummary())
                        .append("\n");
                section.append("- ContextFieldLimitation: ")
                        .append(fieldRecord.getFieldPath())
                        .append(" | ")
                        .append(describeFieldEvidenceLimitation(fieldRecord))
                        .append("\n");
            }
        }
    }

    private boolean hasMissingKnowledge(ContextCoverageReport coverage, List<ContextTrustProfile> trustProfiles) {
        boolean hasCoverageGap = coverage != null
                && (!coverage.missingCriticalFacts().isEmpty()
                || !coverage.remediationHints().isEmpty()
                || !coverage.confidenceWarnings().isEmpty());
        if (hasCoverageGap) {
            return true;
        }
        if (trustProfiles == null || trustProfiles.isEmpty()) {
            return false;
        }
        for (ContextTrustProfile trustProfile : trustProfiles) {
            if (trustProfile != null && hasTrustGating(trustProfile)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasTrustGating(ContextTrustProfile trustProfile) {
        return ContextSemanticBoundaryPolicy.requiresEvidenceCaution(trustProfile)
                || !trustProfile.getScopeLimitations().isEmpty()
                || !trustProfile.getQualityWarnings().isEmpty()
                || trustProfile.getFieldRecords().stream()
                .anyMatch(fieldRecord -> fieldRecord != null && ContextSemanticBoundaryPolicy.requiresEvidenceCaution(fieldRecord));
    }

    private boolean hasDelegationData(CanonicalSecurityContext.Delegation delegation) {
        return delegation.getDelegated() != null
                || StringUtils.hasText(delegation.getAgentId())
                || StringUtils.hasText(delegation.getObjectiveId())
                || StringUtils.hasText(delegation.getObjectiveFamily())
                || StringUtils.hasText(delegation.getObjectiveSummary())
                || !delegation.getAllowedOperations().isEmpty()
                || !delegation.getAllowedResources().isEmpty()
                || delegation.getApprovalRequired() != null
                || delegation.getPrivilegedExportAllowed() != null
                || delegation.getContainmentOnly() != null
                || delegation.getObjectiveDrift() != null
                || StringUtils.hasText(delegation.getObjectiveDriftSummary());
    }

    private void appendList(StringBuilder section, String label, List<String> values) {
        if (values == null || values.isEmpty()) {
            return;
        }
        section.append(label)
                .append(": ")
                .append(String.join(", ", values))
                .append("\n");
    }

    private void appendIntegerList(StringBuilder section, String label, List<Integer> values) {
        if (values == null || values.isEmpty()) {
            return;
        }
        section.append(label)
                .append(": ")
                .append(values.stream().map(String::valueOf).toList())
                .append("\n");
    }

    private void appendLine(StringBuilder section, String label, Object value) {
        if (value == null) {
            return;
        }
        String text = value.toString();
        if (!StringUtils.hasText(text)) {
            return;
        }
        section.append(label)
                .append(": ")
                .append(text)
                .append("\n");
    }

    private String formatPercent(Double value) {
        if (value == null) {
            return "0%";
        }
        return String.format(java.util.Locale.ROOT, "%.0f%%", value * 100.0d);
    }

    private void appendComparisonEvidence(
            StringBuilder section,
            String label,
            String currentValue,
            List<String> comparedValues,
            Boolean present) {
        if (!StringUtils.hasText(currentValue) || comparedValues == null || comparedValues.isEmpty() || present == null) {
            return;
        }
        appendLine(section, label, present);
    }

    private String resolveCurrentResourceValue(CanonicalSecurityContext context) {
        if (context == null || context.getResource() == null) {
            return null;
        }
        return firstText(context.getResource().getResourceId(), context.getResource().getRequestPath(), context.getResource().getResourceType());
    }

    private String resolveCurrentActionFamily(CanonicalSecurityContext context) {
        if (context == null || context.getResource() == null) {
            return null;
        }
        return firstText(context.getResource().getActionFamily(), context.getResource().getHttpMethod());
    }

    private String describeProfileEvidenceState(ContextTrustProfile trustProfile) {
        return ContextSemanticBoundaryPolicy.describeProfileEvidenceState(trustProfile);
    }

    private String describeFieldEvidenceState(ContextFieldTrustRecord fieldRecord) {
        return ContextSemanticBoundaryPolicy.describeFieldEvidenceState(fieldRecord);
    }

    private String describeFieldEvidenceLimitation(ContextFieldTrustRecord fieldRecord) {
        List<String> factors = new ArrayList<>();
        if (ContextSemanticBoundaryPolicy.hasThinCoverage(fieldRecord)) {
            factors.add("evidence count or time coverage is thin");
        }
        if (ContextSemanticBoundaryPolicy.hasFallbackHeavyCoverage(fieldRecord)) {
            factors.add("value derivation depends on fallback signals");
        }
        if (ContextSemanticBoundaryPolicy.hasUnknownHeavyCoverage(fieldRecord)) {
            factors.add("unknown values remain high");
        }
        if (factors.isEmpty()) {
            factors.add("evidence coverage is still partial");
        }
        return String.join("; ", factors);
    }

    private boolean containsIgnoreCase(List<String> values, String target) {
        if (!StringUtils.hasText(target) || values == null || values.isEmpty()) {
            return false;
        }
        for (String value : values) {
            if (StringUtils.hasText(value) && target.equalsIgnoreCase(value.trim())) {
                return true;
            }
        }
        return false;
    }

    private String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }
}
