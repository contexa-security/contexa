package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageReport;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacore.autonomous.saas.dto.BaselineSeedSnapshot;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TO-1..TO-3 (plan 5.3.2, Q-84, Q-85): the v20 fact lines hold facts only. The trust profiles' usage notes and the
 * instruction clauses after their facts, the coverage clauses the system text's evidence rules already state, the
 * delegation unknowns' instructions and the cohort seed's instruction sentences are left out; the facts before them stay.
 */
class PromptFactLinesWithoutGuidanceTest {

    private static final SecurityDecisionGoldenRender GOLDEN = SecurityDecisionGoldenRender.load();

    /** The clauses and sentences the v20 fact lines leave out, as the context producers write them. */
    private static final List<String> LEFT_OUT = List.of(
            // Trust profiles (Q-84 request 1): the usage notes and the instructions after a fact.
            "Use this profile to understand", "require friction, delegation, or enterprise memory context",
            "This profile describes enacted", "treat pattern claims as provisional", "treat expected scope as provisional",
            "do not treat it as a standalone indicator of user intent",
            "confirm intent with approval lineage or delegated objective", "do not use it as a standalone reasoning anchor",
            // Coverage (Q-85): the clauses the system text's evidence rules state.
            "should remain conservative", "conclusions conservative", "do not infer permissions beyond",
            "do not treat it as a standalone proof", "do not claim the current request matches",
            "do not assume prior approval, challenge, or denial precedent", "avoid assuming prior validated cases",
            // Delegation and cohort seed (Q-84 request 2).
            "do not infer objective family", "do not infer objective summary", "do not infer business intent",
            "This cohort seed is shared industry or region context",
            "Do NOT override established personal or organization baseline",
            "Tenant organization baseline should be used before this seed", "Use the seed only for missing dimensions",
            "Use this seed as low-priority cold-start support only");

    @Test
    void noGoldenFactLineCarriesAGuidanceClause() {
        List<String> found = new ArrayList<>();
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            for (String line : factLines(render.userPrompt())) {
                LEFT_OUT.stream().filter(line::contains)
                        .forEach(clause -> found.add(render.caseKey() + " " + labelOf(line) + ": " + clause));
            }
        }
        assertThat(found.stream().distinct().toList()).isEmpty();
    }

    @Test
    void theEvidenceLineKeepsTheFactsBeforeTheInstructions() {
        InspectionGolden.Render render = InspectionGolden.render(prompt -> prompt.contains("collector ROLE_SCOPE_PROFILE")
                && prompt.contains("Action family baseline includes fallback-derived signals"));
        String evidence = value(render.userPrompt(), "Evidence");
        assertThat(evidence).contains("collector ROLE_SCOPE_PROFILE", "provenance ",
                "Action family baseline includes fallback-derived signals", "has thin or fallback-heavy evidence")
                .doesNotContain(", limits ");
    }

    @Test
    void theCoverageLineKeepsItsFactsAndTheInstructionsTheSystemTextDoesNotState() {
        InspectionGolden.Render base = InspectionGolden.renders().get(0);
        assertThat(value(base.userPrompt(), "Coverage")).contains(
                "Broader authorization scope metadata is unavailable.", "Reasoning memory is missing.");
        // The clauses the system text does not state stay with their facts.
        List<String> kept = List.of("Resource business label is missing; business-purpose naming is partial, so rely "
                        + "more heavily on resource identity and sensitivity.",
                "Role scope profile is missing; scope-fit conclusions should rely on direct authorization facts rather "
                        + "than inferred role norms.",
                "Delegated objective comparison shows a mismatch between current request facts and declared delegated "
                        + "scope; any ALLOW conclusion must explain why the request is still acceptable.");
        InspectionGolden.Render render = InspectionGolden.renderWith(base, context -> {
            ContextCoverageReport report = context.getCoverage();
            List<String> warnings = new ArrayList<>(report.confidenceWarnings());
            warnings.addAll(kept);
            context.setCoverage(new ContextCoverageReport(report.level(), report.availableFacts(),
                    report.missingCriticalFacts(), report.remediationHints(), warnings, report.summary()));
        });
        assertThat(value(render.userPrompt(), "Coverage")).contains(kept.toArray(String[]::new));
    }

    /** A coverage that repeats the trust profiles' texts (the profiles not in the context) draws neither the notes nor their label. */
    @Test
    void aCoverageThatRepeatsTheTrustProfilesNotesDrawsNeitherTheNotesNorTheirLabel() {
        InspectionGolden.Render base = InspectionGolden.renders().get(0);
        InspectionGolden.Render render = InspectionGolden.renderWith(base,
                context -> context.setContextTrustProfiles(new ArrayList<>()));
        String coverage = value(render.userPrompt(), "Coverage");
        assertThat(base.used().getCoverage().confidenceWarnings()).anyMatch(warning -> warning.startsWith("Scope limitation: "));
        assertThat(coverage).contains("Action family baseline includes fallback-derived signals.")
                .doesNotContain("Scope limitation:");
        LEFT_OUT.forEach(clause -> assertThat(coverage).doesNotContain(clause));
    }

    @Test
    void aDelegationWithoutItsObjectiveKeepsTheUnknownsWithoutTheInstructions() {
        InspectionGolden.Render base = InspectionGolden.renders().get(0);
        InspectionGolden.Render render = InspectionGolden.renderWith(base, context -> context.setDelegation(
                CanonicalSecurityContext.Delegation.builder().delegated(true).agentId("agent-7").build()));
        String delegation = value(render.userPrompt(), "Delegation");
        assertThat(delegation).contains("AgentId: agent-7",
                "ObjectiveFamily: UNKNOWN - delegation context supplied no objective family",
                "ObjectiveSummary: UNKNOWN - delegation context supplied no objective summary",
                "ObjectiveAlignmentEvidence: UNKNOWN - delegation context supplied no objective alignment evidence")
                .doesNotContain("do not infer");
    }

    @Test
    void anEstablishedOrganizationBaselineLeavesTheSeedWithItsFactsOnly() {
        String peer = value(seeded(true).userText(), "PeerReference");
        assertThat(peer).contains("organization baseline established", "Use only for dimensions: ACCESS_HOURS",
                "Runtime weight: 70% (LIMITED)", "Cohort: finance-kr");
        LEFT_OUT.forEach(clause -> assertThat(peer).doesNotContain(clause));
    }

    @Test
    void anImmatureOrganizationBaselineIsStillStatedWithoutTheSeedInstruction() {
        String peer = value(seeded(false).userText(), "PeerReference");
        assertThat(peer).contains("Tenant organization baseline is still immature.", "Cohort: finance-kr");
        LEFT_OUT.forEach(clause -> assertThat(peer).doesNotContain(clause));
    }

    /** A golden case with a cohort seed applied, its organization baseline established or not. */
    private static SecurityDecisionGoldenRender.RenderedCase seeded(boolean organizationEstablished) {
        ObjectNode goldenCase = GOLDEN.cases().get(0).deepCopy();
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        analysis.setOrganizationBaselineAvailable(true);
        analysis.setOrganizationBaselineEstablished(organizationEstablished);
        analysis.setSupportingBaselineEvidence(new BaselineEvidenceSnapshot(LearningEvidenceScope.SUPPORTING, true,
                organizationEstablished, 25L, null, List.of(), List.of("9", "10"), List.of("1", "2"), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of(), "organization baseline available"
                + (organizationEstablished ? " | organization baseline established" : ""),
                BaselineEvidenceStatus.AVAILABLE, null, List.of()));
        analysis.setCohortSeedApplied(true);
        analysis.setCohortBaselineSeed(new BaselineSeedSnapshot("tenant-1", true, true, true, "finance-kr", "finance",
                "kr", 4, 120L, List.of(9, 10), List.of(1, 2), List.of("WINDOWS"), Map.of(), Map.of(), Map.of(),
                LocalDate.of(2026, 10, 1), null));
        analysis.setCohortSeedSupportingDimensions(List.of("ACCESS_HOURS"));
        analysis.setCohortSeedWeight(0.7d);
        analysis.setCohortSeedWeightState("LIMITED");
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        return GOLDEN.render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties, analysis);
    }

    /** The drawn lines outside the UNTRUSTED TEXT block (whose texts are the requester's), fact ids set aside. */
    private static List<String> factLines(String userPrompt) {
        List<String> lines = new ArrayList<>();
        boolean untrusted = false;
        for (String raw : userPrompt.split("\n")) {
            if (raw.startsWith("=== ")) {
                untrusted = raw.contains("UNTRUSTED TEXT");
                continue;
            }
            if (!untrusted && raw.contains(": ")) {
                lines.add(InspectionGolden.bare(raw));
            }
        }
        return lines;
    }

    private static String labelOf(String line) {
        return line.substring(0, line.indexOf(": "));
    }

    /** The value of the first line with the label, its fact id set aside; null without one. */
    private static String value(String userPrompt, String label) {
        return Arrays.stream(userPrompt.split("\n")).map(InspectionGolden::bare)
                .filter(line -> line.startsWith(label + ": ")).findFirst()
                .map(line -> line.substring(label.length() + 2)).orElse(null);
    }
}
