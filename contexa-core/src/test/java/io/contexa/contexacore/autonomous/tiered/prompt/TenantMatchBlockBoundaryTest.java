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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.PolicySatisfaction;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.DrawnPrompt;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.Outcome;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.ReasonFinding;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * N2: the required BLOCK boundary of the decision rules names a tenant conflict that TenantMatch states ("TenantMatch
 * says the tenants differ") beside the one DataConflicts names. The boundary check reads it, a tenant conflict may cite
 * the TenantMatch line, and a version that includes the decision rules tells the model so.
 *
 * <p>The tenant mismatch control case: an allowed read of a normal resource whose only adverse fact is that the actor's
 * tenant is not the tenant the request names. Before N2 the check let an ALLOW pass as the low-risk boundary
 * ({@code null}) and refused the BLOCK the rules ask for as BLOCK_WITHOUT_DECISIVE_EVIDENCE; TENANT_CONFLICT citing the
 * TenantMatch line was refused as a line the code does not cite.
 */
class TenantMatchBlockBoundaryTest {

    private static final String DIFFER = "actor tenant acme, request tenant beta: differ";

    @Test
    void tenantsThatDifferOnTheTenantMatchLineRequireBlock() {
        CanonicalSecurityContext context = context("acme", "beta");
        DrawnPrompt drawn = DrawnPrompt.of(prompt("[F2] TenantMatch: " + DIFFER + "\n"));

        assertThat(V1LineValues.tenantMatch(context)).isEqualTo(DIFFER);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, context.getDecisionFacts(), drawn, "ALLOW"))
                .isEqualTo(SecurityDecisionFactChecks.REQUIRED_BLOCK);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, context.getDecisionFacts(), drawn, "CHALLENGE"))
                .isEqualTo(SecurityDecisionFactChecks.REQUIRED_BLOCK);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(context, context.getDecisionFacts(), drawn, "BLOCK"))
                .isNull();
    }

    /** The same tenant, or a TenantMatch line the prompt does not draw, is no boundary: the request stays low risk. */
    @Test
    void theSameTenantOrAnUndrawnLineIsNoBlockBoundary() {
        CanonicalSecurityContext same = context("acme", "ACME");
        DrawnPrompt samePrompt = DrawnPrompt.of(prompt("[F2] TenantMatch: actor tenant acme, request tenant ACME: same\n"));
        CanonicalSecurityContext differ = context("acme", "beta");
        DrawnPrompt withoutTheLine = DrawnPrompt.of(prompt(""));

        assertThat(SecurityDecisionFactChecks.boundaryViolation(same, same.getDecisionFacts(), samePrompt, "ALLOW"))
                .isNull();
        assertThat(SecurityDecisionFactChecks.boundaryViolation(same, same.getDecisionFacts(), samePrompt, "BLOCK"))
                .isEqualTo(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
        assertThat(SecurityDecisionFactChecks.boundaryViolation(differ, differ.getDecisionFacts(), withoutTheLine,
                "ALLOW")).isNull();
        assertThat(SecurityDecisionFactChecks.boundaryViolation(differ, differ.getDecisionFacts(), withoutTheLine,
                "BLOCK")).isEqualTo(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
    }

    @Test
    void aTenantConflictMayCiteTheTenantMatchLineWhenItSaysTheTenantsDiffer() {
        CanonicalSecurityContext differ = context("acme", "beta");
        DrawnPrompt differPrompt = DrawnPrompt.of(prompt("[F2] TenantMatch: " + DIFFER + "\n"));
        CanonicalSecurityContext same = context("acme", "acme");
        DrawnPrompt samePrompt = DrawnPrompt.of(prompt("[F2] TenantMatch: actor tenant acme, request tenant acme: same\n"));

        List<ReasonFinding> held = SecurityDecisionAnswerChecks.reasonFindings(differ, differPrompt,
                List.of(new SecurityDecisionOutputContract.Citation("TENANT_CONFLICT", "F2")));
        List<ReasonFinding> refused = SecurityDecisionAnswerChecks.reasonFindings(same, samePrompt,
                List.of(new SecurityDecisionOutputContract.Citation("TENANT_CONFLICT", "F2")));
        List<ReasonFinding> otherCode = SecurityDecisionAnswerChecks.reasonFindings(differ, differPrompt,
                List.of(new SecurityDecisionOutputContract.Citation("DATA_CONFLICT", "F2")));

        assertThat(held).singleElement().satisfies(finding -> {
            assertThat(finding.outcome()).isEqualTo(Outcome.MATCH);
            assertThat(finding.reason()).isEqualTo("DECISION_FACTS.TenantMatch");
        });
        assertThat(refused).singleElement().satisfies(finding -> {
            assertThat(finding.outcome()).isEqualTo(Outcome.MISMATCH);
            assertThat(finding.reason()).isEqualTo("the line does not state what TENANT_CONFLICT says");
        });
        assertThat(otherCode).singleElement().satisfies(finding -> {
            assertThat(finding.outcome()).isEqualTo(Outcome.MISMATCH);
            assertThat(finding.reason()).isEqualTo("the code does not cite DECISION_FACTS.TenantMatch");
        });
    }

    /**
     * A version that includes the decision rules names TenantMatch among the lines of a tenant conflict; the product
     * version, which leaves the rules out, draws the lines it was measured with.
     */
    @Test
    void onlyAVersionWithTheDecisionRulesNamesTenantMatchForATenantConflict() {
        AssembledPrompt rules = MeasuredVariant.FALLBACK_SIMILAR.version();
        AssembledPrompt product = SecurityDecisionPromptDocument.product();

        assertThat(SecurityDecisionVersionFeatures.of(rules).decisionRules()).isTrue();
        assertThat(SecurityDecisionVersionFeatures.of(product).decisionRules()).isFalse();
        assertThat(SecurityDecisionPromptDocument.systemPreview(rules))
                .contains("- TENANT_CONFLICT: a tenant or organization conflict; DataConflicts, TenantMatch\n");
        assertThat(SecurityDecisionPromptDocument.systemPreview(product))
                .contains("- TENANT_CONFLICT: a tenant or organization conflict; DataConflicts\n")
                .doesNotContain("DataConflicts, TenantMatch");
        assertThat(SecurityDecisionOutputContractV4.citedLines(false))
                .isSameAs(SecurityDecisionOutputContractV4.citedLines());
        assertThat(SecurityDecisionOutputContractV4.citedLines(true).get("TENANT_CONFLICT"))
                .containsExactly("DataConflicts", "TenantMatch");
        assertThat(SecurityDecisionOutputContractV4.citedLines(true)).hasSameSizeAs(
                SecurityDecisionOutputContractV4.citedLines());
    }

    private static String prompt(String tenantLine) {
        return """
                === REQUEST (host) ===
                ResourceClass: NORMAL

                === DECISION FACTS (computed) ===
                [F1] AuthorizationEffect: ALLOW
                """ + tenantLine;
    }

    private static CanonicalSecurityContext context(String actorTenant, String requestTenant) {
        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .actor(CanonicalSecurityContext.Actor.builder().tenantId(actorTenant).build())
                .resource(CanonicalSecurityContext.Resource.builder().resourceClass("NORMAL").actionFamily("READ")
                        .build())
                .authorization(CanonicalSecurityContext.Authorization.builder().authorizationEffect("ALLOW").build())
                .decisionFacts(new DecisionFacts(List.of(), List.of(), PolicySatisfaction.UNKNOWN, List.of()))
                .build();
        context.getAttributes().put("tenantId", requestTenant);
        return context;
    }
}
