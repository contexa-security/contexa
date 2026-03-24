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
                    "No canonical context is available.");
        }

        List<String> availableFacts = new ArrayList<>();
        List<String> missingCriticalFacts = new ArrayList<>();

        if (CanonicalContextFieldPolicy.hasActorIdentity(context)) {
            availableFacts.add("Actor identity is available.");
        }
        else {
            missingCriticalFacts.add("Actor identity is unavailable.");
        }

        if (CanonicalContextFieldPolicy.hasSessionIdentity(context)) {
            availableFacts.add("Session identity is available.");
        }
        else {
            missingCriticalFacts.add("Session identity is unavailable.");
        }

        if (CanonicalContextFieldPolicy.hasEffectiveRoles(context)) {
            availableFacts.add("Effective roles are available.");
        }
        else {
            missingCriticalFacts.add("Effective roles are unavailable.");
        }

        if (CanonicalContextFieldPolicy.hasAuthorizationScope(context)) {
            availableFacts.add("Authorization scope is available.");
        }
        else {
            missingCriticalFacts.add("Authorization scope is unavailable.");
        }

        if (CanonicalContextFieldPolicy.hasResourceIdentity(context)) {
            availableFacts.add("Resource identity is available.");
        }
        else {
            missingCriticalFacts.add("Resource identity is unavailable.");
        }

        if (CanonicalContextFieldPolicy.hasResourceBusinessLabel(context)) {
            availableFacts.add("Resource business label is available.");
        }
        else {
            missingCriticalFacts.add("Resource business label is unavailable.");
        }

        if (CanonicalContextFieldPolicy.hasResourceSensitivity(context)) {
            availableFacts.add("Resource sensitivity is available.");
        }
        else {
            missingCriticalFacts.add("Resource sensitivity is unavailable.");
        }

        if (CanonicalContextFieldPolicy.hasMfaState(context)) {
            availableFacts.add("Session MFA state is available.");
        }
        else {
            missingCriticalFacts.add("Session MFA state is unavailable.");
        }

        if (CanonicalContextFieldPolicy.hasObservedScope(context)) {
            availableFacts.add("Observed work pattern is available.");
        }

        appendBridgeFacts(context, availableFacts, missingCriticalFacts);

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

        return new ContextCoverageReport(level, List.copyOf(availableFacts), List.copyOf(missingCriticalFacts), summary);
    }

    private void appendBridgeFacts(CanonicalSecurityContext context, List<String> availableFacts, List<String> missingCriticalFacts) {
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
        }
    }
}

