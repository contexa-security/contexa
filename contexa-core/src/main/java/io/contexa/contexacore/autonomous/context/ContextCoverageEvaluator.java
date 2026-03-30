package io.contexa.contexacore.autonomous.context;

import java.util.ArrayList;
import java.util.List;

public class ContextCoverageEvaluator {

    public ContextCoverageReport evaluate(CanonicalSecurityContext context) {
        if (context == null) {
            return new ContextCoverageReport(
                    ContextCoverageLevel.ENVIRONMENT_ONLY,
                    List.of(),
                    List.of("Canonical security context is unavailable."),
                    List.of("Provide bridge-derived identity and request context before LLM evaluation."),
                    List.of("Canonical context is missing; post-auth reasoning will be highly unreliable."),
                    "No canonical context is available.");
        }

        List<String> availableFacts = new ArrayList<>();
        List<String> missingCriticalFacts = new ArrayList<>();
        List<String> remediationHints = new ArrayList<>();
        List<String> confidenceWarnings = new ArrayList<>();

        if (CanonicalContextFieldPolicy.hasActorIdentity(context)) {
            availableFacts.add("Actor identity is available.");
        }
        else {
            missingCriticalFacts.add("Actor identity is unavailable.");
            remediationHints.add("Propagate an internal or external subject identifier through the bridge or event metadata.");
            confidenceWarnings.add("Actor identity is missing; continuity and user-specific reasoning should remain conservative.");
        }

        if (CanonicalContextFieldPolicy.hasSessionIdentity(context)) {
            availableFacts.add("Session identity is available.");
        }
        else {
            missingCriticalFacts.add("Session identity is unavailable.");
            remediationHints.add("Provide a stable session identifier or equivalent request continuity key.");
        }

        if (CanonicalContextFieldPolicy.hasEffectiveRoles(context)) {
            availableFacts.add("Effective roles are available.");
        }
        else {
            missingCriticalFacts.add("Effective roles are unavailable.");
            remediationHints.add("Propagate effective roles for the current request when they exist.");
        }

        if (CanonicalContextFieldPolicy.hasAuthorizationScope(context)) {
            availableFacts.add("Authorization scope is available.");
        }
        else {
            missingCriticalFacts.add("Authorization scope is unavailable.");
            remediationHints.add("Propagate effective permissions or scope tags for the current request.");
            confidenceWarnings.add("Authorization scope is partial; privilege and scope conclusions should remain conservative.");
        }

        if (CanonicalContextFieldPolicy.hasResourceIdentity(context)) {
            availableFacts.add("Resource identity is available.");
        }
        else {
            missingCriticalFacts.add("Resource identity is unavailable.");
            remediationHints.add("Provide a stable resource identifier or request path mapping.");
        }

        if (CanonicalContextFieldPolicy.hasResourceBusinessLabel(context)) {
            availableFacts.add("Resource business label is available.");
        }
        else {
            remediationHints.add("Register resource business labels through the resource registry or event metadata.");
            confidenceWarnings.add("Resource business label is missing; business-purpose naming is partial, so rely more heavily on resource identity and sensitivity.");
        }

        if (CanonicalContextFieldPolicy.hasResourceSensitivity(context)) {
            availableFacts.add("Resource sensitivity is available.");
        }
        else {
            missingCriticalFacts.add("Resource sensitivity is unavailable.");
            remediationHints.add("Register or propagate resource sensitivity for the current protectable target.");
        }

        if (CanonicalContextFieldPolicy.hasMfaState(context)) {
            availableFacts.add("Session MFA state is available.");
        }
        else {
            missingCriticalFacts.add("Session MFA state is unavailable.");
            remediationHints.add("Propagate MFA verification state and recent assurance outcomes.");
        }

        if (CanonicalContextFieldPolicy.hasObservedScope(context)) {
            availableFacts.add("Observed work pattern is available.");
        }
        else {
            remediationHints.add("Collect protectable access history so observed work patterns can be inferred.");
            confidenceWarnings.add("Observed work pattern is missing; comparisons against previously seen resources or action families remain limited.");
        }

        if (CanonicalContextFieldPolicy.hasSessionNarrativeProfile(context)) {
            availableFacts.add("Session narrative is available.");
        }
        else {
            remediationHints.add("Provide previous path, previous action, request interval, or session action sequence.");
            confidenceWarnings.add("Session narrative is incomplete; sequence-based reasoning is partial.");
        }

        if (CanonicalContextFieldPolicy.hasWorkProfile(context)) {
            availableFacts.add("Personal work profile is available.");
        }
        else if (CanonicalContextFieldPolicy.hasProvisionalWorkProfile(context)) {
            availableFacts.add("Personal work profile evidence is available but provisional.");
            remediationHints.add("Increase allowed observations and reduce fallback-derived work profile fields before treating personal work profile as a strong reasoning anchor.");
            confidenceWarnings.add("Personal work profile exists but remains thin, fallback-heavy, or comparison-incomplete; do not treat it as a standalone proof of normal behavior.");
        }
        else if (CanonicalContextFieldPolicy.hasWorkProfileEvidence(context)) {
            availableFacts.add("Personal work profile evidence is available but not yet trust-qualified.");
            remediationHints.add("Attach personal work profile trust assessment before using work-pattern claims as a strong reasoning anchor.");
            confidenceWarnings.add("Personal work profile evidence is present without an explicit trust assessment; keep work-pattern conclusions conservative.");
        }
        else {
            remediationHints.add("Build personal work profile signals such as frequent resources, action families, and request rates.");
            confidenceWarnings.add("Personal work profile is missing; do not claim the current request matches long-term normal work patterns.");
        }

        if (CanonicalContextFieldPolicy.hasRoleScopeProfile(context)) {
            availableFacts.add("Role scope profile is available.");
        }
        else if (CanonicalContextFieldPolicy.hasProvisionalRoleScopeProfile(context)) {
            availableFacts.add("Role scope profile evidence is available but provisional.");
            remediationHints.add("Increase explicit role-scope evidence and reduce fallback-derived comparisons before treating role scope as a strong reasoning anchor.");
            confidenceWarnings.add("Role scope profile exists but remains thin, fallback-heavy, or comparison-incomplete; do not treat it as a standalone proof of authorized business scope.");
        }
        else if (CanonicalContextFieldPolicy.hasRoleScopeProfileEvidence(context)) {
            availableFacts.add("Role scope profile evidence is available but not yet trust-qualified.");
            remediationHints.add("Attach role scope trust assessment before using role-scope comparisons as a strong reasoning anchor.");
            confidenceWarnings.add("Role scope profile evidence is present without an explicit trust assessment; keep role-scope conclusions conservative.");
        }
        else {
            remediationHints.add("Attach role-scoped resource families, action families, and permission change facts.");
            confidenceWarnings.add("Role scope profile is missing; scope-fit conclusions should rely on direct authorization facts rather than inferred role norms.");
        }

        if (CanonicalContextFieldPolicy.hasPeerCohortProfile(context)) {
            availableFacts.add("Peer cohort delta is available.");
        }
        else {
            remediationHints.add("Attach peer cohort deltas through enterprise cohort enrichment when available.");
            confidenceWarnings.add("Peer cohort delta is missing; cohort-based deviation claims should remain conservative.");
        }

        if (CanonicalContextFieldPolicy.hasFrictionProfile(context)) {
            availableFacts.add("Friction and approval history is available.");
        }
        else {
            remediationHints.add("Propagate challenge, block, escalation, approval, and denied-access history.");
            confidenceWarnings.add("Friction and approval history is missing; do not assume prior approval, challenge, or denial precedent exists.");
        }

        appendDelegationFacts(context, availableFacts, missingCriticalFacts, remediationHints, confidenceWarnings);

        if (CanonicalContextFieldPolicy.hasReasoningMemoryProfile(context)) {
            availableFacts.add("Outcome and reasoning memory is available.");
        }
        else {
            remediationHints.add("Attach reinforced cases, hard negatives, and reasoning memory facts from enterprise memory services when available.");
            confidenceWarnings.add("Reasoning memory is missing; avoid assuming prior validated cases or XAI-backed precedents exist.");
        }

        appendBridgeFacts(context, availableFacts, missingCriticalFacts, remediationHints);
        appendTrustProfileFacts(context, availableFacts, remediationHints, confidenceWarnings);

        ContextCoverageLevel level = CanonicalContextFieldPolicy.determineCoverageLevel(context);
        String summary = switch (level) {
            case BUSINESS_AWARE -> "Business-aware context is available for role, resource, and session reasoning.";
            case SCOPE_AWARE -> "Scope-aware context is available, but business semantics remain partial.";
            case IDENTITY_AWARE -> "Identity-aware context is available, but authorization scope is partial.";
            case ENVIRONMENT_ONLY -> "Only environment or minimal request context is available.";
        };

        if (context.getBridge() != null && context.getBridge().getCoverageLevel() != null) {
            summary = summary + " Bridge coverage: " + context.getBridge().getCoverageLevel() + ".";
        }

        return new ContextCoverageReport(
                level,
                List.copyOf(availableFacts),
                List.copyOf(missingCriticalFacts),
                deduplicate(remediationHints),
                deduplicate(confidenceWarnings),
                summary);
    }

    private void appendBridgeFacts(
            CanonicalSecurityContext context,
            List<String> availableFacts,
            List<String> missingCriticalFacts,
            List<String> remediationHints) {
        CanonicalSecurityContext.Bridge bridge = context.getBridge();
        if (bridge == null) {
            return;
        }
        if (bridge.getCoverageLevel() != null) {
            availableFacts.add("Bridge coverage metadata is available.");
        }
        if (bridge.getAuthenticationSource() != null) {
            availableFacts.add("Bridge authentication source is available.");
        }
        if (bridge.getAuthorizationSource() != null) {
            availableFacts.add("Bridge authorization source is available.");
        }
        if (bridge.getDelegationSource() != null) {
            availableFacts.add("Bridge delegation source is available.");
        }
        if (bridge.getSummary() != null && !bridge.getSummary().isBlank()) {
            availableFacts.add("Bridge summary: " + bridge.getSummary());
        }
        for (String missingContext : bridge.getMissingContexts()) {
            missingCriticalFacts.add("Bridge missing context: " + missingContext + ".");
        }
        for (String remediationHint : bridge.getRemediationHints()) {
            availableFacts.add("Bridge remediation hint: " + remediationHint);
            remediationHints.add(remediationHint);
        }
    }

    private void appendDelegationFacts(
            CanonicalSecurityContext context,
            List<String> availableFacts,
            List<String> missingCriticalFacts,
            List<String> remediationHints,
            List<String> confidenceWarnings) {
        if (!CanonicalContextFieldPolicy.hasDelegationContext(context) || context.getDelegation() == null) {
            return;
        }
        CanonicalSecurityContext.Delegation delegation = context.getDelegation();
        availableFacts.add("Delegated objective context is available.");
        if (delegation.getObjectiveFamily() != null && !delegation.getObjectiveFamily().isBlank()) {
            availableFacts.add("Delegated objective family is available.");
        }
        else {
            missingCriticalFacts.add("Delegated objective family is unavailable.");
            remediationHints.add("Propagate a canonical objective family so delegated-agent intent can be evaluated without free-text guessing.");
            confidenceWarnings.add("Delegated objective family is missing; delegated-agent intent should remain conservative.");
        }

        if (CanonicalContextFieldPolicy.hasObjectiveDriftAssessment(context)) {
            availableFacts.add("Delegated objective comparison evidence is available.");
            if (Boolean.TRUE.equals(delegation.getObjectiveDrift())) {
                confidenceWarnings.add("Delegated objective comparison shows a mismatch between current request facts and declared delegated scope; any ALLOW conclusion must explain why the request is still acceptable.");
            }
        }
        else {
            missingCriticalFacts.add("Delegated objective comparison is incomplete.");
            remediationHints.add("Provide comparable current action/resource family inputs so delegated objective comparison can be evaluated before an ALLOW decision.");
            confidenceWarnings.add("Delegated objective comparison is incomplete; delegated-agent ALLOW conclusions should remain conservative.");
        }
    }

    private void appendTrustProfileFacts(
            CanonicalSecurityContext context,
            List<String> availableFacts,
            List<String> remediationHints,
            List<String> confidenceWarnings) {
        if (context.getContextTrustProfiles() == null || context.getContextTrustProfiles().isEmpty()) {
            return;
        }
        for (ContextTrustProfile trustProfile : context.getContextTrustProfiles()) {
            if (trustProfile == null) {
                continue;
            }
            if (trustProfile.getProfileKey() != null) {
                availableFacts.add("Context trust profile is available for " + trustProfile.getProfileKey() + ".");
            }
            if (trustProfile.getProvenanceSummary() != null && !trustProfile.getProvenanceSummary().isBlank()) {
                availableFacts.add("Context provenance summary: " + trustProfile.getProvenanceSummary());
            }
            if (ContextSemanticBoundaryPolicy.requiresEvidenceCaution(trustProfile)) {
                confidenceWarnings.add("Context evidence for " + trustProfile.getProfileKey()
                        + " is thin, fallback-heavy, or comparison-incomplete; do not use it as a standalone reasoning anchor.");
                remediationHints.add("Increase explicit collector signals and evidence coverage before using "
                        + trustProfile.getProfileKey() + " as a strong reasoning anchor.");
            }
            for (String warning : trustProfile.getQualityWarnings()) {
                confidenceWarnings.add(warning);
            }
            for (String limitation : trustProfile.getScopeLimitations()) {
                confidenceWarnings.add("Scope limitation: " + limitation);
            }
        }
    }

    private List<String> deduplicate(List<String> values) {
        if (values.isEmpty()) {
            return List.of();
        }
        List<String> deduplicated = new ArrayList<>();
        for (String value : values) {
            if (value == null || value.isBlank() || deduplicated.contains(value)) {
                continue;
            }
            deduplicated.add(value);
        }
        return List.copyOf(deduplicated);
    }
}

