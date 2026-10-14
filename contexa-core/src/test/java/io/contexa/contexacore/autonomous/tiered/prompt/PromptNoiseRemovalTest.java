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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W3-5 (principle 14; removals Q-61 and Q-73 decided 2026-10-13): the v20 prompt leaves out the items the user
 * removed and keeps their facts where the removal check list says they stay.
 */
class PromptNoiseRemovalTest {

    private static final SecurityDecisionGoldenRender GOLDEN = SecurityDecisionGoldenRender.load();

    /**
     * The labelled items of the removal check list the user removed: section 1.1 and 1.2, and of section 2 the trust
     * family, the dead sections, the rewritten summaries and the instructions the system text holds.
     */
    private static final List<String> REMOVED_LABELS = List.of(
            "BaselineContextSummary", "CurrentRequestCombinationSummary", "ObservedComparableCombination1",
            "RoleScopeSummary", "SessionNarrativeSummary", "StrongestCurrentVsObservedDelta", "OrganizationId",
            "TenantId", "CurrentAuthenticationType", "CurrentOperatingSystem", "CurrentNetwork", "CurrentBrowser",
            "SessionId", "HistoricalComparableCount",
            "AuthorizationEffectStageNote", "SupportingEvidenceConstraint", "MissingKnowledgeDecisionLimit",
            "RagEvidenceBoundary", "RagDecisionLimit", "SupportingEvidenceNeverReplacesPersonalBaseline",
            "SupportingEvidenceMode", "HistoricalBaselineSupport", "SessionTimelineSupport", "AuthorizationContext",
            "AvailableFacts", "HistoricalComparableEvents", "BaselineGapSupport", "Baseline gap impact",
            "Baseline evidence constraints",
            "TrustProfileKey", "TrustCollectorId", "TrustProfileSummary", "TrustProvenanceSummary",
            "TrustScopeLimitations", "TrustQualityWarnings", "TrustFieldAudits", "TrustEvidence", "CurrentOS",
            "CurrentUA", "PeerCohortSummary", "ReasoningMemorySummary", "CrossTenantObjectiveMisusePackSummary",
            "MemoryGuardrails", "Seed policy");

    /** The unlabelled items of section 1.1 and 1.2, by the text the check list names. */
    private static final List<String> REMOVED_TEXTS = List.of(
            "Actor identity is available.", "Session identity is available.", "Effective roles are available.",
            "User is requesting ", "FINAL RESPONSE COMPACTNESS",
            "Organization or cohort baseline is reference evi", "Sparse personal history limits user-specific com",
            "Sparse personal history is uncertainty, not proo", "Current-vs-observed facts and limitations are re");

    /** The v20 golden renders, written for the value-by-value comparison of the prompt before and after a removal. */
    @Test
    void theGoldenRendersAreReported() throws IOException {
        Path directory = Path.of("build/reports/prompt-bundle/rendered-v20");
        Files.createDirectories(directory);
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            Files.writeString(directory.resolve(render.caseKey() + "-" + render.profile().name() + "-user.txt"),
                    render.userPrompt());
        }
        assertThat(InspectionGolden.renders()).isNotEmpty();
    }

    /**
     * Q-61: no removed item is drawn, neither as a line nor inside the value of a line that carries a v19 section (the
     * golden renders, and a case whose context fills every section the removed items come from).
     */
    @Test
    void noRemovedItemIsDrawn() {
        List<String> prompts = new ArrayList<>();
        InspectionGolden.renders().forEach(render -> prompts.add(render.userPrompt()));
        prompts.add(filled().userText());
        for (String prompt : prompts) {
            for (String label : REMOVED_LABELS) {
                assertThat(prompt).as(label).doesNotContain(label + ": ").doesNotContain(label + ":\n");
            }
            for (String text : REMOVED_TEXTS) {
                assertThat(prompt).as(text).doesNotContain(text);
            }
        }
    }

    /**
     * Q-73 T2: the coverage line names the context coverage and bridge levels without the fixed sentences that only
     * restate them; the missing facts and warnings it states stay.
     */
    @Test
    void theCoverageLineNamesTheLevelsWithoutTheirSentences() {
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            ContextCoverageReport report = render.used().getCoverage();
            CanonicalSecurityContext.Bridge bridge = render.used().getBridge();
            List<String> parts = Arrays.asList(value(render.userPrompt(), "Coverage").split("; "));
            assertThat(parts).as(render.caseKey()).contains("context coverage " + report.level(),
                    "bridge " + bridge.getCoverageLevel());
            assertThat(value(render.userPrompt(), "Coverage")).as(render.caseKey())
                    .doesNotContain(report.summary()).doesNotContain(bridge.getSummary());
        }
        String filled = value(filled().userText(), "Coverage");
        assertThat(filled).contains("missing Bridge missing context: DELEGATION.").contains("coverage warnings ");
    }

    /** Q-73 T1 and T3: the resource class keeps its marks without the verification mark; the action keeps its method. */
    @Test
    void theResourceClassKeepsItsMarksWithoutTheVerificationMark() {
        String user = filled().userText();
        assertThat(value(user, "ResourceClass"))
                .isEqualTo("CRITICAL (sensitivity RESTRICTED, sensitive-resource flag, export-sensitive)");
        assertThat(value(user, "Action")).contains("method ");
    }

    /** Q-61 X15, X26, X27: the validated cases keep the memory facts without the summary, guardrails and pack summary. */
    @Test
    void theValidatedCasesKeepTheMemoryFactsWithoutTheRemovedLines() {
        String cases = value(filled().userText(), "ValidatedCases");
        assertThat(cases).contains("ReinforcedCaseCount: 3", "HardNegativeCaseCount: 1", "RetentionTier: HOT",
                "CrossTenantObjectiveMisuseFacts: objective drift across tenants");
        assertThat(cases).doesNotContain("memory summary").doesNotContain("never treat memory as proof")
                .doesNotContain("pack summary");
    }

    /** Q-61 X48 (X46, X47 kept): the cohort seed keeps its dimensions, weight and figures without its seed policy. */
    @Test
    void thePeerReferenceKeepsTheSeedFactsWithoutTheSeedPolicy() {
        String peer = value(filled().userText(), "PeerReference");
        assertThat(peer).contains("Use only for dimensions: ACCESS_HOURS", "Runtime weight: 70% (LIMITED)",
                "Cohort: finance-kr", "Cohort tenants: 4", "Sampled user baselines: 120");
        assertThat(peer).doesNotContain("Runtime weight 0.70 applies to cohort");
    }

    /**
     * A golden case whose context fills every section a removed item comes from: a resource with all its marks, a
     * reasoning memory, a bridge with a missing context, and a behaviour analysis with a cohort seed.
     */
    private static SecurityDecisionGoldenRender.RenderedCase filled() {
        ObjectNode goldenCase = GOLDEN.cases().get(0).deepCopy();
        ObjectNode canonical = (ObjectNode) goldenCase.path("canonicalContext");
        ObjectNode resource = objectAt(canonical, "resource");
        resource.put("resourceClass", "CRITICAL");
        resource.put("sensitivity", "RESTRICTED");
        resource.put("sensitiveResource", true);
        resource.put("exportSensitive", true);
        resource.put("verificationRequired", true);
        ObjectNode memory = objectAt(canonical, "reasoningMemoryProfile");
        memory.put("summary", "memory summary");
        memory.put("reinforcedCaseCount", 3);
        memory.put("hardNegativeCaseCount", 1);
        memory.put("retentionTier", "HOT");
        memory.putArray("memoryGuardrails").add("never treat memory as proof");
        memory.put("crossTenantObjectiveMisusePackSummary", "pack summary");
        memory.putArray("crossTenantObjectiveMisuseFacts").add("objective drift across tenants");
        ObjectNode coverage = objectAt(canonical, "coverage");
        coverage.putArray("missingCriticalFacts").add("Bridge missing context: DELEGATION.");
        objectAt(canonical, "bridge").putArray("missingContexts").add("DELEGATION");

        // As the strategy fills it (AbstractTieredStrategy.enrichBaselineSupportContext): the organization baseline's
        // evidence, then the cohort seed applied with its weight and policy facts.
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        analysis.setOrganizationBaselineAvailable(true);
        analysis.setOrganizationBaselineEstablished(true);
        analysis.setSupportingBaselineEvidence(new BaselineEvidenceSnapshot(LearningEvidenceScope.SUPPORTING, true, true,
                25L, null, List.of(), List.of("9", "10"), List.of("1", "2"), List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of(), "organization baseline available | organization baseline established",
                BaselineEvidenceStatus.AVAILABLE, null, List.of()));
        analysis.setCohortSeedApplied(true);
        analysis.setCohortBaselineSeed(new BaselineSeedSnapshot("tenant-1", true, true, true, "finance-kr", "finance",
                "kr", 4, 120L, List.of(9, 10), List.of(1, 2), List.of("WINDOWS"), Map.of(), Map.of(), Map.of(),
                LocalDate.of(2026, 10, 1), null));
        analysis.setCohortSeedSupportingDimensions(List.of("ACCESS_HOURS"));
        analysis.setCohortSeedWeight(0.7d);
        analysis.setCohortSeedWeightState("LIMITED");
        analysis.setCohortSeedPolicyFacts(List.of("Runtime weight 0.70 applies to cohort finance-kr with 4 cohort tenants"));
        return GOLDEN.render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, v20(), analysis);
    }

    /** The value of the first line with the label, its fact id set aside; null without one. */
    private static String value(String userPrompt, String label) {
        return Arrays.stream(userPrompt.split("\n")).map(InspectionGolden::bare)
                .filter(line -> line.startsWith(label + ": ")).findFirst()
                .map(line -> line.substring(label.length() + 2)).orElse(null);
    }

    private static ObjectNode objectAt(ObjectNode parent, String field) {
        if (!parent.path(field).isObject()) {
            parent.putObject(field);
        }
        return (ObjectNode) parent.path(field);
    }

    private static TieredStrategyProperties v20() {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        return properties;
    }
}
