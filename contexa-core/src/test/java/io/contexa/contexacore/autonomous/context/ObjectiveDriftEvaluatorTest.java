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
package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.context.inference.ObjectiveDriftEvaluator;
import io.contexa.contexacore.autonomous.execution.ObjectiveResourceCompatibilityCatalog;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import io.contexa.contexacore.autonomous.context.model.ObjectiveDriftEvaluation;

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

    @Test
    void aWriteUnderAReadOnlyDelegationIsADriftNotARead() {
        CanonicalSecurityContext context = context("CREATE");
        CanonicalSecurityContext.Delegation delegation = CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .objectiveFamily("REPORT_READ")
                .allowedOperations(List.of("READ"))
                .build();

        ObjectiveDriftEvaluation evaluation = evaluator.evaluate(delegation, context);

        // S-16: a create used to read as READ and stay inside a READ-only scope (W2-1).
        assertThat(evaluation.objectiveDrift()).isTrue();
        assertThat(evaluation.facts()).anyMatch(fact -> fact.contains("Current action family is not listed"));
    }

    @Test
    void anActionNoSourceNamesIsNotComparedWithTheDelegatedScope() {
        CanonicalSecurityContext context = context("UNKNOWN");
        CanonicalSecurityContext.Delegation delegation = CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .objectiveFamily("REPORT_READ")
                .allowedOperations(List.of("READ"))
                .build();

        ObjectiveDriftEvaluation evaluation = evaluator.evaluate(delegation, context);

        assertThat(evaluation.facts()).anyMatch(fact -> fact.contains("Current action family is unknown"));
        assertThat(evaluation.facts()).noneMatch(fact -> fact.contains("Current action family is listed")
                || fact.contains("Current action family is not listed"));
    }

    @Test
    void theFactsNameTheRequestByItsActionFamilyAndTheOperationItWasComparedAs() {
        CanonicalSecurityContext context = context("WRITE");
        CanonicalSecurityContext.Delegation delegation = CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .objectiveFamily("READ_ONLY_INCIDENT_SUMMARY")
                .allowedOperations(List.of("READ"))
                .build();

        ObjectiveDriftEvaluation evaluation = evaluator.evaluate(delegation, context);

        // The prompt says ActionFamily: WRITE; the delegation line names the same request WRITE, not MODIFY.
        assertThat(evaluation.objectiveDrift()).isTrue();
        assertThat(evaluation.currentActionFamily()).isEqualTo("WRITE");
        assertThat(evaluation.facts())
                .contains("Current action family: WRITE", "Current action family compared as delegated operation: MODIFY")
                .doesNotContain("Current action family: MODIFY");
    }

    @Test
    void anActionTheDelegationVocabularyHasNoOperationForIsNotComparedAndNotCalledUnknown() {
        CanonicalSecurityContext context = context("EXECUTE");
        CanonicalSecurityContext.Delegation delegation = CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .objectiveFamily("REPORT_READ")
                .allowedOperations(List.of("READ"))
                .build();

        ObjectiveDriftEvaluation evaluation = evaluator.evaluate(delegation, context);

        assertThat(evaluation.facts())
                .contains("Current action family: EXECUTE",
                        "Current action family has no delegated operation; it is not compared with delegated action scope evidence.")
                .noneMatch(fact -> fact.contains("Current action family is unknown")
                        || fact.contains("Current action family is listed")
                        || fact.contains("Current action family is not listed"));
    }

    @Test
    void theDelegatedScopeIsComparedWithTheResourcesCategory() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/reports/7")
                        .resourceType("CRITICAL")
                        .resourceClass("CRITICAL")
                        .resourceCategory("TENANT_DATA")
                        .actionFamily("READ")
                        .requestPath("/api/reports/7")
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .currentActionFamily("READ")
                        .build())
                .build();
        CanonicalSecurityContext.Delegation delegation = CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .objectiveFamily("READ_ONLY_INCIDENT_SUMMARY")
                .allowedOperations(List.of("READ"))
                .allowedResources(List.of("TENANT_DATA"))
                .build();

        ObjectiveDriftEvaluation evaluation = evaluator.evaluate(delegation, context);

        // W2-10: the type said CRITICAL, a class; the delegated scope names categories.
        assertThat(evaluation.currentResourceFamily()).isEqualTo("TENANT_DATA");
        assertThat(evaluation.objectiveDrift()).isFalse();
    }

    @Test
    void aClassWordTypeLeavesTheCategoryToThePathAndNotToTheClass() {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/projects/W04/exports")
                        .resourceType("CRITICAL")
                        .resourceClass("CRITICAL")
                        .actionFamily("READ")
                        .requestPath("/api/projects/W04/exports")
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .currentActionFamily("READ")
                        .build())
                .build();
        CanonicalSecurityContext.Delegation delegation = CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .objectiveFamily("READ_ONLY_INCIDENT_SUMMARY")
                .allowedOperations(List.of("READ"))
                .allowedResources(List.of("TENANT_DATA"))
                .build();

        ObjectiveDriftEvaluation evaluation = evaluator.evaluate(delegation, context);

        assertThat(evaluation.currentResourceFamily()).isEqualTo("TENANT_DATA");
        assertThat(evaluation.objectiveDrift()).isFalse();
        assertThat(evaluation.facts()).doesNotContain("Current resource family: CRITICAL");
    }

    private static CanonicalSecurityContext context(String actionFamily) {
        return CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/reports/7")
                        .actionFamily(actionFamily)
                        .requestPath("/api/reports/7")
                        .build())
                .roleScopeProfile(CanonicalSecurityContext.RoleScopeProfile.builder()
                        .currentActionFamily(actionFamily)
                        .build())
                .build();
    }

    @Test
    void aRequestedResourceBroaderThanTheConstraintIsOutsideIt() {
        CanonicalSecurityContext.Delegation delegation = CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .objectiveFamily("READ_ONLY_INCIDENT_SUMMARY")
                .allowedOperations(List.of("READ"))
                .allowedResources(List.of("/api/tenants/t1/reports"))
                .build();

        ObjectiveDriftEvaluation broader = evaluator.evaluate(delegation, read("/api/tenants/t1"));
        ObjectiveDriftEvaluation within = evaluator.evaluate(delegation, read("/api/tenants/t1/reports/7"));

        // N-ID-1 (D5): the request lies within a raw constraint when its resource starts with it; a constraint that
        // starts with the request's resource names something narrower than what is asked for.
        assertThat(broader.facts()).anyMatch(fact -> fact.contains("Current resource does not match delegated raw resource constraints"));
        assertThat(within.facts()).anyMatch(fact -> fact.contains("Current resource matches delegated raw resource constraints"));
    }

    /**
     * A2-4 (AG2 on control D): a delegation scoped to a business record ({@code HX-310}) is compared with the request's
     * business target, its host-recorded scope and the identifiers in its path, not with the protected method's id.
     * The drawing HX-310-DWG-00002 of project HX-310 was reported as outside the delegation.
     */
    @Test
    void aBusinessScopedDelegationIsComparedWithTheRequestsBusinessTarget() {
        CanonicalSecurityContext drawing = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("io.example.Documents#readDocument")
                        .resourceCategory("PROJECT_DOCUMENTS")
                        .actionFamily("READ")
                        .scope("projectKey=HX-310")
                        .requestPath("/api/documents/HX-310-DWG-00002")
                        .build())
                .build();

        ObjectiveDriftEvaluation inScope = evaluator.evaluate(delegationTo("HX-310"), drawing);
        ObjectiveDriftEvaluation otherProject = evaluator.evaluate(delegationTo("GB-500"), drawing);

        assertThat(inScope.objectiveDrift()).isFalse();
        assertThat(inScope.facts()).anyMatch(fact -> fact.contains("Current resource matches delegated raw resource constraints"));
        assertThat(otherProject.objectiveDrift()).isTrue();
        assertThat(otherProject.facts()).anyMatch(fact -> fact.contains("Current resource does not match delegated raw resource constraints"));
    }

    /**
     * A2-1, A2-2: an objective the application declares (here a report: its project documents, read and export up to
     * 500 items) is the scope a delegation of that objective is compared with, in the words of the methods'
     * {@code @Protectable} category and actions.
     */
    @Test
    void anApplicationsObjectiveContractIsTheComparedScope() {
        ObjectiveDriftEvaluator withContracts = new ObjectiveDriftEvaluator(new ObjectiveResourceCompatibilityCatalog(
                List.of(new ObjectiveResourceCompatibilityCatalog.ObjectiveContractDefinition("REPORTING",
                        List.of("READ", "EXPORT"), List.of("PROJECT_DOCUMENTS"), false, true, 500))));
        CanonicalSecurityContext.Delegation reporting = CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .objectiveFamily("REPORTING")
                .build();

        ObjectiveDriftEvaluation read = withContracts.evaluate(reporting, documents("READ", null));
        ObjectiveDriftEvaluation smallExport = withContracts.evaluate(reporting, documents("EXPORT", 20));
        ObjectiveDriftEvaluation largeExport = withContracts.evaluate(reporting, documents("EXPORT", 600));
        ObjectiveDriftEvaluation customerRead = withContracts.evaluate(reporting, CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder().resourceCategory("CUSTOMERS").actionFamily("READ")
                        .requestPath("/api/customers/C-1").build())
                .build());
        ObjectiveDriftEvaluation undeclared = evaluator.evaluate(reporting, documents("READ", null));

        assertThat(read.objectiveDrift()).isFalse();
        assertThat(read.comparisonSource()).isEqualTo("OBJECTIVE_CONTRACT");
        assertThat(smallExport.objectiveDrift()).isFalse();
        assertThat(smallExport.facts()).anyMatch(fact -> fact.contains("20 requested items are within the objective's export limit of 500"));
        assertThat(largeExport.objectiveDrift()).isTrue();
        assertThat(largeExport.facts()).anyMatch(fact -> fact.contains("600 requested items exceed the objective's export limit of 500"));
        assertThat(customerRead.objectiveDrift()).isTrue();
        assertThat(undeclared.objectiveDrift()).isNull();
    }

    @Test
    void theApplicationsContractsJoinTheBuiltInOnes() {
        ObjectiveResourceCompatibilityCatalog catalog = new ObjectiveResourceCompatibilityCatalog(List.of(
                new ObjectiveResourceCompatibilityCatalog.ObjectiveContractDefinition(" reporting ", List.of("search"),
                        List.of("project_documents"), true, false, null)));

        assertThat(catalog.hasObjectiveContract("REPORTING")).isTrue();
        assertThat(catalog.resolve("REPORTING").allowedOperations()).containsExactly("QUERY");
        assertThat(catalog.resolve("REPORTING").allowedResourceFamilies()).containsExactly("PROJECT_DOCUMENTS");
        assertThat(catalog.resolve("REPORTING").readOnlyObjective()).isTrue();
        assertThat(catalog.resolve("REPORTING").maxExportItems()).isNull();
        assertThat(catalog.hasObjectiveContract("READ_ONLY_INCIDENT_SUMMARY")).isTrue();
        assertThat(new ObjectiveResourceCompatibilityCatalog().hasObjectiveContract("REPORTING")).isFalse();
    }

    private static CanonicalSecurityContext.Delegation delegationTo(String resource) {
        return CanonicalSecurityContext.Delegation.builder()
                .delegated(true)
                .objectiveFamily("REPORTING")
                .allowedOperations(List.of("DOCUMENT_READ"))
                .allowedResources(List.of(resource))
                .build();
    }

    private static CanonicalSecurityContext documents(String action, Integer items) {
        return CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("io.example.Documents#" + action.toLowerCase())
                        .resourceCategory("PROJECT_DOCUMENTS")
                        .actionFamily(action)
                        .requestedItems(items)
                        .requestPath("/api/projects/HX-310/documents")
                        .build())
                .build();
    }

    private static CanonicalSecurityContext read(String path) {
        return CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId(path)
                        .actionFamily("READ")
                        .requestPath(path)
                        .build())
                .build();
    }
}
