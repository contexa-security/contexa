package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptMissingNotation;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.FactAccuracyCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The fact accuracy check on the USER BASELINE lines drawn from the sealed baseline view (the canonical context seals
 * the final view the decision used), on real packages the showcase engine sealed and on golden renders.
 */
class PromptInspectionBaselineFactsTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new FactAccuracyCheck()), InspectionGolden.JSON);
    private static final String EVIDENCE_LINE = "\nEvidence: ";
    private static final List<String> VIEW_LINES = List.of("UsualHours", "UsualDays", "UsualTargets", "UsualActions",
            "UsualResourceClass", "UsualExportSize", "UsualRequestRate", "UsualSessionLength", "UsualPrivilegedActions",
            "KnownRareTasks");

    @Test
    void realShowcasePackagesStateEveryFactAsTheirSealedSources() {
        int matched = 0;
        for (SealedEvidencePackage sealed : InspectionGolden.showcaseSealed()) {
            PromptInspectionCheckResult check = check(sealed);
            assertThat(check.findings().stream().filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH))
                    .as(sealed.getPackageId()).isEmpty();
            matched += check.matched();
        }
        assertThat(matched).isPositive();
    }

    @Test
    void realShowcasePackagesHaveTheirBaselineViewLinesCompared() {
        int compared = 0;
        for (SealedEvidencePackage sealed : InspectionGolden.showcaseSealed()) {
            List<PromptInspectionFinding> unverifiable = check(sealed).findings().stream()
                    .filter(finding -> VIEW_LINES.contains(finding.entry())).toList();
            assertThat(unverifiable).as(sealed.getPackageId()).isEmpty();
            compared += (int) VIEW_LINES.stream()
                    .filter(name -> sealed.getUserPromptText().contains("\n" + name + ": ")).count();
        }
        assertThat(compared).isPositive();
    }

    @Test
    void aBaselineLineSayingOtherThanTheSealedViewIsPointedAt() {
        SealedEvidencePackage sealed = withLine("UsualHours: ");
        String line = lineStarting(sealed.getUserPromptText(), "UsualHours: ");
        sealed.setUserPromptText(sealed.getUserPromptText().replace(line, "UsualHours: 00-23"));

        List<PromptInspectionFinding> found = mismatches(check(sealed), "UsualHours");
        assertThat(found).hasSize(1);
        assertThat(found.get(0).expected()).isEqualTo(line.substring("UsualHours: ".length()));
        assertThat(found.get(0).sourceRef()).isEqualTo("canonicalContext.workProfile.baselineView");
    }

    @Test
    void withoutASealedBaselineViewTheViewLinesCannotBeComparedAndSaySo() {
        SealedEvidencePackage sealed = withLine("UsualHours: ");
        CanonicalSecurityContext context = InspectionGolden.SERIALIZER.deserialize(sealed.getCanonicalContextJson());
        context.getWorkProfile().setBaselineView(null);
        sealed.setCanonicalContextJson(InspectionGolden.SERIALIZER.serialize(context));

        List<PromptInspectionFinding> hours = check(sealed).findings().stream()
                .filter(finding -> "UsualHours".equals(finding.entry())).toList();
        assertThat(hours).hasSize(1);
        assertThat(hours.get(0).outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(hours.get(0).reason()).contains("baseline view is not sealed");
    }

    /**
     * A user without any learning (P3-extra-41, as the showcase sealed it: package 5059): no baseline view is sealed and
     * the sealed baseline state is NONE, so the render can only say "not learned" on the view lines and the devices;
     * they are compared with that state instead of being left unchecked. A line the dictionary leaves out without a
     * value is not drawn for such a user; a package that still states one is pointed at.
     */
    @Test
    void withoutAnyLearningTheViewLinesAreComparedWithTheSealedNoneState() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "UsualHours: ")
                && InspectionGolden.hasLine(text, "UsualDevices: ") && InspectionGolden.hasLine(text, "BaselineStatus: ")
                && VIEW_LINES.stream().anyMatch(name -> leftOutWithoutValue(name)
                && InspectionGolden.hasLine(text, name + ": ")));
        String prompt = render.userPrompt();
        String status = lineStarting(prompt, "BaselineStatus: ");
        prompt = prompt.replace(status, status.substring(0, status.indexOf("BaselineStatus: "))
                + "BaselineStatus: NONE (no learned requests, no observations, personal baseline NO_DATA)");
        List<String> notLearned = new ArrayList<>(VIEW_LINES);
        notLearned.add("UsualDevices");
        List<String> leftOut = new ArrayList<>();
        for (String name : notLearned) {
            if (!InspectionGolden.hasLine(prompt, name + ": ")) {
                continue;
            }
            if (leftOutWithoutValue(name)) {
                leftOut.add(lineStarting(prompt, name + ": "));
            }
            else {
                prompt = prompt.replace(lineStarting(prompt, name + ": "), name + ": not learned");
            }
        }
        for (String line : leftOut.subList(1, leftOut.size())) {
            prompt = prompt.replace(line + "\n", "");
        }
        String stated = prompt;
        prompt = prompt.replace(leftOut.get(0) + "\n", "");
        Map<String, Object> metadata = new LinkedHashMap<>(render.executionMetadata());
        metadata.put("promptBaselineStatus", "NONE");
        InspectionGolden.Render none = new InspectionGolden.Render(render.caseKey(), render.profile(),
                render.systemPrompt(), prompt, render.used(), metadata, render.ragResultsJson(), render.requestFactsJson());
        CanonicalSecurityContext context = InspectionGolden.SERIALIZER.deserialize(none.sealed().getCanonicalContextJson());
        context.getWorkProfile().setBaselineView(null);

        assertThat(check(sealedWith(none, prompt, context)).findings())
                .noneMatch(finding -> notLearned.contains(finding.entry()));

        String broken = prompt.replace("UsualHours: not learned", "UsualHours: 09-17");
        List<PromptInspectionFinding> found = mismatches(check(sealedWith(none, broken, context)), "UsualHours");
        assertThat(found).hasSize(1);
        assertThat(found.get(0).expected()).isEqualTo("not learned");
        assertThat(found.get(0).sourceRef()).isEqualTo("executionMetadata.promptBaselineStatus");

        String statedName = InspectionGolden.bare(leftOut.get(0));
        statedName = statedName.substring(0, statedName.indexOf(": "));
        List<PromptInspectionFinding> statedFound = mismatches(check(sealedWith(none, stated, context)), statedName);
        assertThat(statedFound).hasSize(1);
        assertThat(statedFound.get(0).expected()).isEqualTo("no line (nothing is learned)");
        assertThat(statedFound.get(0).sourceRef()).isEqualTo("executionMetadata.promptBaselineStatus");
    }

    @Test
    void theSeasonalPatternIsComparedWithTheSealedWorkProfile() {
        InspectionGolden.Render render = InspectionGolden.render(text -> text.contains("=== USER BASELINE"));
        CanonicalSecurityContext context = InspectionGolden.SERIALIZER.deserialize(
                InspectionGolden.SERIALIZER.serialize(render.used()));
        if (context.getWorkProfile() == null) {
            context.setWorkProfile(new CanonicalSecurityContext.WorkProfile());
        }
        context.getWorkProfile().setSeasonalBusinessProfile("quarter-end exports");
        String header = lineStarting(render.userPrompt(), "=== USER BASELINE");
        String kept = withoutLine(render.userPrompt(), "SeasonalPattern: ")
                .replace(header + "\n", header + "\nSeasonalPattern: quarter-end exports\n");
        String broken = withoutLine(render.userPrompt(), "SeasonalPattern: ")
                .replace(header + "\n", header + "\nSeasonalPattern: year-end exports\n");

        assertThat(mismatches(check(sealedWith(render, kept, context)), "SeasonalPattern")).isEmpty();
        List<PromptInspectionFinding> found = mismatches(check(sealedWith(render, broken, context)), "SeasonalPattern");
        assertThat(found).hasSize(1);
        assertThat(found.get(0).sourceRef()).isEqualTo("canonicalContext.workProfile.seasonalBusinessProfile");
    }

    /**
     * Q-79 A1: without an observed view the evidence line states the sealed trust profiles; a collector the sealed
     * context does not hold is pointed at. The line holds no baseline state.
     */
    @Test
    void theEvidenceLineNamesTheSealedTrustProfiles() {
        // A render without an observed view: with one, the line's window and observations are what is compared.
        InspectionGolden.Render render = InspectionGolden.render(text -> text.contains(EVIDENCE_LINE)
                && !lineStarting(text, "Evidence: ").contains("window "));
        String evidence = lineStarting(render.userPrompt(), "Evidence: ");
        assertThat(evidence).startsWith("Evidence: collector ").doesNotContain("state ");
        assertThat(check(render.sealed()).findings()).noneMatch(finding -> "Evidence".equals(finding.entry()));

        String key = render.used().getContextTrustProfiles().get(0).getProfileKey();
        String broken = render.userPrompt().replace(evidence, evidence.replace("collector " + key, "collector OTHER"));
        List<PromptInspectionFinding> found = mismatches(check(render.sealed(broken)), "Evidence");
        assertThat(found).hasSize(1);
        assertThat(found.get(0).sourceRef()).isEqualTo("canonicalContext.contextTrustProfiles");
    }

    /**
     * W3-19, Q-79 A1: a package sealed in the form before Q-79 names the baseline state on its evidence line; that state
     * is the state the render sealed, and without a sealed state it cannot be compared.
     */
    @Test
    void theFormerEvidenceStateIsComparedWithTheSealedBaselineState() {
        InspectionGolden.Render render = InspectionGolden.render(text -> text.contains(EVIDENCE_LINE));
        Object sealedState = render.executionMetadata().get("promptBaselineStatus");
        assertThat(sealedState).isNotNull();
        String evidence = lineStarting(render.userPrompt(), "Evidence: ");
        String former = render.userPrompt().replace(evidence, evidence.replace("Evidence: ",
                "Evidence: state " + sealedState + "; "));
        assertThat(check(render.sealed(former)).findings()).noneMatch(finding -> "Evidence".equals(finding.entry()));

        String broken = render.userPrompt().replace(evidence, evidence.replace("Evidence: ", "Evidence: state NONE; "));
        List<PromptInspectionFinding> found = mismatches(check(render.sealed(broken)), "Evidence");
        assertThat(found).hasSize(1);
        assertThat(found.get(0).sourceRef()).isEqualTo("executionMetadata.promptBaselineStatus");

        Map<String, Object> metadata = new LinkedHashMap<>(render.executionMetadata());
        metadata.remove("promptBaselineStatus");
        InspectionGolden.Render before = new InspectionGolden.Render(render.caseKey(), render.profile(),
                render.systemPrompt(), former, render.used(), metadata, render.ragResultsJson(), render.requestFactsJson());
        List<PromptInspectionFinding> unverifiable = check(before.sealed()).findings().stream()
                .filter(finding -> "Evidence".equals(finding.entry())).toList();
        assertThat(unverifiable).hasSize(1);
        assertThat(unverifiable.get(0).outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(unverifiable.get(0).reason()).contains("baseline state");
    }

    /**
     * R1b-1: the BaselineStatus line names the baseline state the render sealed ({@code promptBaselineStatus}); another
     * state is pointed at, and a package sealed before the state was kept cannot be compared.
     */
    @Test
    void theBaselineStatusIsComparedWithTheSealedBaselineState() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "BaselineStatus: "));
        Object sealedState = render.executionMetadata().get("promptBaselineStatus");
        assertThat(sealedState).isNotNull();
        String status = lineStarting(render.userPrompt(), "BaselineStatus: ");
        assertThat(InspectionGolden.bare(status)).startsWith("BaselineStatus: " + sealedState);
        assertThat(check(render.sealed()).findings()).noneMatch(finding -> "BaselineStatus".equals(finding.entry()));

        String broken = render.userPrompt().replace(status, status.replace("BaselineStatus: " + sealedState,
                "BaselineStatus: ESTABLISHED"));
        List<PromptInspectionFinding> found = mismatches(check(render.sealed(broken)), "BaselineStatus");
        assertThat(found).hasSize(1);
        assertThat(found.get(0).expected()).isEqualTo(sealedState.toString());
        assertThat(found.get(0).sourceRef()).isEqualTo("executionMetadata.promptBaselineStatus");

        Map<String, Object> metadata = new LinkedHashMap<>(render.executionMetadata());
        metadata.remove("promptBaselineStatus");
        InspectionGolden.Render before = new InspectionGolden.Render(render.caseKey(), render.profile(),
                render.systemPrompt(), render.userPrompt(), render.used(), metadata, render.ragResultsJson(), render.requestFactsJson());
        List<PromptInspectionFinding> unverifiable = check(before.sealed()).findings().stream()
                .filter(finding -> "BaselineStatus".equals(finding.entry())).toList();
        assertThat(unverifiable).hasSize(1);
        assertThat(unverifiable.get(0).outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(unverifiable.get(0).reason()).contains("seals no baseline state");
    }

    /** A baseline line the dictionary leaves out when it has no value (it has no missing text). */
    private static boolean leftOutWithoutValue(String name) {
        return SecurityDecisionPromptDictionary.ENTRIES.stream()
                .filter(entry -> entry.block() == PromptBlock.USER_BASELINE && entry.name().equals(name))
                .anyMatch(entry -> entry.missing() == PromptMissingNotation.LINE_OMITTED);
    }

    private static SealedEvidencePackage withLine(String start) {
        return InspectionGolden.showcaseSealed().stream()
                .filter(sealed -> sealed.getUserPromptText().contains("\n" + start))
                .findFirst().orElseThrow();
    }

    private static SealedEvidencePackage sealedWith(InspectionGolden.Render render, String userPrompt,
                                                    CanonicalSecurityContext context) {
        SealedEvidencePackage sealed = render.sealed(userPrompt);
        sealed.setCanonicalContextJson(InspectionGolden.SERIALIZER.serialize(context));
        return sealed;
    }

    private static PromptInspectionCheckResult check(SealedEvidencePackage sealed) {
        PromptInspectionResult result = INSPECTOR.inspect(sealed);
        assertThat(result.checks()).hasSize(1);
        return result.checks().get(0);
    }

    private static List<PromptInspectionFinding> mismatches(PromptInspectionCheckResult check, String label) {
        return check.findings().stream().filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .filter(finding -> label.equals(finding.entry())).toList();
    }

    private static String withoutLine(String text, String start) {
        String existing = Arrays.stream(text.split("\n")).filter(line -> line.startsWith(start)).findFirst().orElse(null);
        return existing == null ? text : text.replace(existing + "\n", "");
    }

    private static String lineStarting(String text, String start) {
        return Arrays.stream(text.split("\n")).filter(line -> InspectionGolden.bare(line).startsWith(start)).findFirst()
                .orElseThrow();
    }
}
