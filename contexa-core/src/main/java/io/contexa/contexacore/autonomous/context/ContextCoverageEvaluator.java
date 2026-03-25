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
            missingCriticalFacts.add("Resource business label is unavailable.");
            remediationHints.add("Register resource business labels through the resource registry or event metadata.");
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
            missingCriticalFacts.add("Observed work pattern is unavailable.");
            remediationHints.add("Collect protectable access history so observed work patterns can be inferred.");
            confidenceWarnings.add("Observed work pattern is missing; rare-resource and rare-action conclusions are limited.");
        }

        if (CanonicalContextFieldPolicy.hasSessionNarrativeProfile(context)) {
            availableFacts.add("Session narrative is available.");
        }
        else {
            missingCriticalFacts.add("Session narrative is unavailable.");
            remediationHints.add("Provide previous path, previous action, request interval, or session action sequence.");
            confidenceWarnings.add("Session narrative is incomplete; sequence-based reasoning is partial.");
        }

        if (CanonicalContextFieldPolicy.hasWorkProfile(context)) {
            availableFacts.add("Personal work profile is available.");
        }
        else {
            missingCriticalFacts.add("Personal work profile is unavailable.");
            remediationHints.add("Build personal work profile signals such as frequent resources, action families, and request rates.");
        }

        if (CanonicalContextFieldPolicy.hasRoleScopeProfile(context)) {
            availableFacts.add("Role scope profile is available.");
        }
        else {
            missingCriticalFacts.add("Role scope profile is unavailable.");
            remediationHints.add("Attach role-scoped resource families, action families, and permission change facts.");
        }

        if (CanonicalContextFieldPolicy.hasPeerCohortProfile(context)) {
            availableFacts.add("Peer cohort delta is available.");
        }
        else {
            missingCriticalFacts.add("Peer cohort delta is unavailable.");
            remediationHints.add("Attach peer cohort deltas through enterprise cohort enrichment when available.");
            confidenceWarnings.add("Peer cohort delta is missing; cohort-based deviation claims should remain conservative.");
        }

        if (CanonicalContextFieldPolicy.hasFrictionProfile(context)) {
            availableFacts.add("Friction and approval history is available.");
        }
        else {
            missingCriticalFacts.add("Friction and approval history is unavailable.");
            remediationHints.add("Propagate challenge, block, escalation, approval, and denied-access history.");
        }

        if (CanonicalContextFieldPolicy.hasReasoningMemoryProfile(context)) {
            availableFacts.add("Outcome and reasoning memory is available.");
        }
        else {
            missingCriticalFacts.add("Outcome and reasoning memory is unavailable.");
            remediationHints.add("Attach reinforced cases, hard negatives, and reasoning memory facts from enterprise memory services when available.");
            confidenceWarnings.add("Reasoning memory is missing; avoid assuming prior validated cases or XAI-backed precedents exist.");
        }

        appendBridgeFacts(context, availableFacts, missingCriticalFacts, remediationHints);

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

