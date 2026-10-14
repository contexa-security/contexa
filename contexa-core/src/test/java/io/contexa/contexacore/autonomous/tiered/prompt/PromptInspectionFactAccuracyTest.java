package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.verification.inspection.FactAccuracyCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The fact accuracy check of the prompt inspector on the REQUEST block: the subject, the time, the size, the resource
 * class and the network say what the sealed canonical context says, compared field by field with the sealed source
 * and not by rendering again.
 */
class PromptInspectionFactAccuracyTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new FactAccuracyCheck()), InspectionGolden.JSON);

    @Test
    void everyV20RenderOfTheGoldenCasesStatesTheSealedRequestFacts() {
        int matched = 0;
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            PromptInspectionCheckResult check = check(render.userPrompt(), render);
            assertThat(check.findings().stream().filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH))
                    .as(render.caseKey() + " " + render.profile()).isEmpty();
            matched += check.matched();
        }
        assertThat(matched).isPositive();
    }

    @Test
    void aSubjectOfAnotherUserIsPointedAtWithTheSealedUserId() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Subject: "));
        String subject = lineStarting(render.userPrompt(), "Subject: ");
        String userId = render.used().getActor().getUserId();
        String broken = render.userPrompt().replace(subject, subject.replace("Subject: " + userId, "Subject: mallory"));

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.entry()).isEqualTo("Subject");
        assertThat(finding.expected()).isEqualTo(userId);
        assertThat(finding.actual()).isEqualTo("mallory");
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.actor.userId");
    }

    @Test
    void theTimeIsComparedWithTheSealedRequestTimeOnTheSealedClock() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Time: "));
        CanonicalSecurityContext context = copy(render.used());
        // The golden inputs predate the sealed request time (W2-5); a Monday 07:15 UTC request is given here.
        context.setRequestObservedAt(Instant.parse("2026-10-12T07:15:00Z"));
        String time = lineStarting(render.userPrompt(), "Time: ");

        assertThat(mismatches(check(render.userPrompt().replace(time, InspectionGolden.factIdOf(time) + "Time: Mon 07:15"), render, context))).isEmpty();
        PromptInspectionFinding finding = single(check(render.userPrompt().replace(time, InspectionGolden.factIdOf(time) + "Time: Sun 23:59"), render, context));
        assertThat(finding.entry()).isEqualTo("Time");
        assertThat(finding.expected()).isEqualTo("Mon 07:15");
        assertThat(finding.actual()).isEqualTo("Sun 23:59");
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.requestObservedAt");
    }

    @Test
    void theSizeAndTheResourceClassAreComparedWithTheSealedResource() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Time: "));
        CanonicalSecurityContext context = copy(render.used());
        CanonicalSecurityContext.Resource resource = context.getResource() != null
                ? context.getResource() : new CanonicalSecurityContext.Resource();
        resource.setRequestedItems(4831);
        resource.setResourceClass("CRITICAL");
        // R1b-7: the line is compared whole, so the sealed resource holds what the kept line states beside its class.
        resource.setSensitivity("RESTRICTED");
        resource.setSensitiveResource(null);
        resource.setExportSensitive(null);
        resource.setPrivileged(null);
        context.setResource(resource);
        String time = lineStarting(render.userPrompt(), "Time: ");
        String kept = render.userPrompt().replace(time + "\n",
                time + "\nSize: 4,831 items\nResourceClass: CRITICAL (sensitivity RESTRICTED)\n");
        String broken = render.userPrompt().replace(time + "\n",
                time + "\nSize: 1 items\nResourceClass: PUBLIC\n");

        assertThat(mismatches(check(kept, render, context))).isEmpty();
        List<PromptInspectionFinding> findings = mismatches(check(broken, render, context));
        assertThat(findings).extracting(PromptInspectionFinding::entry).containsExactlyInAnyOrder("Size", "ResourceClass");
        assertThat(findings).extracting(PromptInspectionFinding::sourceRef)
                .containsExactlyInAnyOrder("canonicalContext.resource.requestedItems", "canonicalContext.resource.resourceClass");
        assertThat(findings).extracting(PromptInspectionFinding::expected).containsExactlyInAnyOrder("4,831 items", "CRITICAL");
    }

    @Test
    void aSizeTheSealedResourceDoesNotHoldIsPointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Time: "));
        CanonicalSecurityContext context = copy(render.used());
        if (context.getResource() != null) {
            context.getResource().setRequestedItems(null);
        }
        String time = lineStarting(render.userPrompt(), "Time: ");

        PromptInspectionFinding finding = single(check(
                render.userPrompt().replace(time + "\n", time + "\nSize: 12 items\n"), render, context));
        assertThat(finding.entry()).isEqualTo("Size");
        assertThat(finding.reason()).contains("does not hold");
    }

    @Test
    void aNetworkAddressOtherThanTheSealedClientIpIsPointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Network: "));
        String network = lineStarting(render.userPrompt(), "Network: ");
        String ip = render.used().getSession().getClientIp();
        String broken = render.userPrompt().replace(network, network.replace("Network: " + ip, "Network: 203.0.113.9"));

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.entry()).isEqualTo("Network");
        assertThat(finding.expected()).isEqualTo(ip);
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.session.clientIp");
    }

    /** W3-5: the coverage line states the sealed coverage level; another level is pointed at. */
    @Test
    void aCoverageLevelOtherThanTheSealedOneIsPointedAt() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Coverage: "));
        String level = "context coverage " + render.used().getCoverage().level();
        assertThat(level).isNotEqualTo("context coverage ENVIRONMENT_ONLY");
        String broken = render.userPrompt().replace(level, "context coverage ENVIRONMENT_ONLY");

        PromptInspectionFinding finding = single(check(broken, render));
        assertThat(finding.entry()).isEqualTo("Coverage");
        assertThat(finding.expected()).isEqualTo(level);
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.coverage");

        // The level is a part of the line, not any text: the sealed level written inside another part is no statement.
        String coverage = lineStarting(broken, "Coverage: ");
        String inside = broken.replace(coverage, coverage + "; hints read " + level + " first");
        assertThat(single(check(inside, render)).expected()).isEqualTo(level);
    }

    /**
     * W3-5, R1b-7: a coverage line in the form before W3-5 (each level followed by the sentence that restates it, Q-73
     * T2) states the same levels, but a package of this build's form draws the line without those sentences, so the
     * whole line is pointed at. Packages drawn in the former form are of earlier bundles, which are not read (R1b-7).
     */
    @Test
    void aCoverageLineOfTheFormerFormInAPackageOfThisFormIsPointedAtWhole() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Coverage: "));
        CanonicalSecurityContext context = render.used();
        String level = "context coverage " + context.getCoverage().level();
        String bridge = "bridge " + context.getBridge().getCoverageLevel();
        String former = render.userPrompt()
                .replace(level, level + ": " + context.getCoverage().summary())
                .replace("; " + bridge, "; " + bridge + ": " + context.getBridge().getSummary());
        assertThat(former).contains(level + ": ");

        String drawn = InspectionGolden.bare(lineStarting(render.userPrompt(), "Coverage: "));
        PromptInspectionFinding finding = single(check(former, render));
        assertThat(finding.entry()).isEqualTo("Coverage");
        assertThat(finding.expected()).isEqualTo(drawn.substring("Coverage: ".length()));
        assertThat(finding.sourceRef()).isEqualTo("canonicalContext.coverage");
    }

    @Test
    void aTimeWithoutASealedRequestTimeCannotBeComparedAndSaysSo() {
        InspectionGolden.Render render = InspectionGolden.render(text -> InspectionGolden.hasLine(text, "Time: "));
        CanonicalSecurityContext context = InspectionGolden.SERIALIZER.deserialize(
                InspectionGolden.SERIALIZER.serialize(render.used()));
        context.setRequestObservedAt(null);

        var sealed = render.sealed(render.userPrompt());
        sealed.setCanonicalContextJson(InspectionGolden.SERIALIZER.serialize(context));
        PromptInspectionResult result = INSPECTOR.inspect(sealed);
        assertThat(result.checks().get(0).findings())
                .filteredOn(finding -> "Time".equals(finding.entry()))
                .singleElement()
                .satisfies(finding -> {
                    assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
                    assertThat(finding.reason()).contains("request time is not sealed");
                });
    }

    private static PromptInspectionCheckResult check(String userPrompt, InspectionGolden.Render render) {
        PromptInspectionResult result = INSPECTOR.inspect(render.sealed(userPrompt));
        assertThat(result.checks()).hasSize(1);
        assertThat(result.checks().get(0).checkCode()).isEqualTo(FactAccuracyCheck.CODE);
        return result.checks().get(0);
    }

    private static PromptInspectionCheckResult check(String userPrompt, InspectionGolden.Render render,
                                                     CanonicalSecurityContext context) {
        var sealed = render.sealed(userPrompt);
        sealed.setCanonicalContextJson(InspectionGolden.SERIALIZER.serialize(context));
        PromptInspectionResult result = INSPECTOR.inspect(sealed);
        assertThat(result.checks()).hasSize(1);
        return result.checks().get(0);
    }

    private static CanonicalSecurityContext copy(CanonicalSecurityContext context) {
        return InspectionGolden.SERIALIZER.deserialize(InspectionGolden.SERIALIZER.serialize(context));
    }

    private static List<PromptInspectionFinding> mismatches(PromptInspectionCheckResult check) {
        return check.findings().stream().filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH).toList();
    }

    /** The single mismatch of a check (items it cannot compare are counted apart). */
    private static PromptInspectionFinding single(PromptInspectionCheckResult check) {
        List<PromptInspectionFinding> mismatches = check.findings().stream()
                .filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH).toList();
        assertThat(mismatches).hasSize(1);
        return mismatches.get(0);
    }

    private static String lineStarting(String text, String start) {
        return Arrays.stream(text.split("\n")).filter(line -> InspectionGolden.bare(line).startsWith(start)).findFirst().orElseThrow();
    }
}
