package io.contexa.contexacore.autonomous.context;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ObjectiveDriftEvaluatorTest {

    private final ObjectiveDriftEvaluator evaluator = new ObjectiveDriftEvaluator();

    @Test
    void evaluateShouldUseExplicitDelegationScopeWhenPresent() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .resourceType("REPORT")
                        .actionFamily("EXPORT")
                        .requestPath("/api/customer/export")
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .currentActionFamily("EXPORT")
                        .currentResourceFamily("REPORT")
                        .build())
                .build();
        CanonicalSecurityContext.Delegation delegation = CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .objectiveFamily("EXPORT_GUARD")
                .allowedOperations(List.of("READ"))
                .allowedResources(List.of("/api/customer/list"))
                .build();

        ObjectiveDriftEvaluation evaluation = evaluator.evaluate(delegation, context);

        assertThat(evaluation.objectiveDrift()).isTrue();
        assertThat(evaluation.comparisonSource()).isEqualTo("EXPLICIT_DELEGATION_SCOPE");
        assertThat(evaluation.currentActionFamily()).isEqualTo("EXPORT");
        assertThat(evaluation.currentResourceFamily()).isEqualTo("REPORT");
        assertThat(evaluation.facts()).anyMatch(fact -> fact.contains("Current action family is not listed"));
        assertThat(evaluation.facts()).anyMatch(fact -> fact.contains("Current resource does not match delegated raw resource constraints"));
    }

    @Test
    void evaluateShouldFallbackToObjectiveContractWhenExplicitScopeIsMissing() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/runtime/prompt/context")
                        .resourceType("prompt_context")
                        .actionFamily("AUDIT")
                        .requestPath("/runtime/prompt/context")
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .currentActionFamily("AUDIT")
                        .currentResourceFamily("PROMPT_CONTEXT")
                        .build())
                .build();
        CanonicalSecurityContext.Delegation delegation = CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .objectiveFamily("PROMPT_CONTEXT_GOVERNANCE")
                .build();

        ObjectiveDriftEvaluation evaluation = evaluator.evaluate(delegation, context);

        assertThat(evaluation.objectiveDrift()).isFalse();
        assertThat(evaluation.comparisonSource()).isEqualTo("OBJECTIVE_CONTRACT");
        assertThat(evaluation.allowedActionFamilies()).contains("INGEST", "AUDIT");
        assertThat(evaluation.allowedResourceFamilies()).contains("PROMPT_CONTEXT", "MEMORY_CONTEXT");
        assertThat(evaluation.facts()).anyMatch(fact -> fact.contains("Current action family is listed in delegated action scope evidence."));
        assertThat(evaluation.facts()).anyMatch(fact -> fact.contains("Current resource family is listed in delegated resource scope evidence."));
    }

    @Test
    void evaluateShouldRemainUnknownWhenComparableInputsAreMissing() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/opaque/resource")
                        .build())
                .build();
        CanonicalSecurityContext.Delegation delegation = CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .objectiveFamily("EXPORT_GUARD")
                .build();

        ObjectiveDriftEvaluation evaluation = evaluator.evaluate(delegation, context);

        assertThat(evaluation.objectiveDrift()).isNull();
        assertThat(evaluation.facts()).anyMatch(fact -> fact.contains("Delegated objective comparison is incomplete because comparable action/resource family inputs are missing."));
    }
}
