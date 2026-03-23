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

        ContextCoverageLevel level = CanonicalContextFieldPolicy.determineCoverageLevel(context);
        String summary = switch (level) {
            case BUSINESS_AWARE -> "Business-aware context is available for role, resource, and session reasoning.";
            case SCOPE_AWARE -> "Scope-aware context is available, but business semantics remain partial.";
            case IDENTITY_AWARE -> "Identity-aware context is available, but authorization scope is partial.";
            case ENVIRONMENT_ONLY -> "Only environment or minimal request context is available.";
        };

        return new ContextCoverageReport(level, List.copyOf(availableFacts), List.copyOf(missingCriticalFacts), summary);
    }
}
