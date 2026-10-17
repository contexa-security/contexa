package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.FactAccuracyCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every dictionary entry is accounted for by the inspection: compared with its sealed source by the fact accuracy
 * check, inspected by another check, or named as not comparable with the reason. The untrusted texts whose sources are
 * sealed are compared too.
 */
class PromptInspectionCoverageTest {

    private static final PromptInspector INSPECTOR =
            new PromptInspector(List.of(new FactAccuracyCheck()), InspectionGolden.JSON);

    @Test
    void everyDictionaryEntryIsComparedInspectedElsewhereOrNamedNotComparable() {
        Set<String> entries = SecurityDecisionPromptDictionary.ENTRIES.stream()
                .map(entry -> entry.block().name() + "." + entry.name()).collect(Collectors.toSet());
        Set<String> compared = FactAccuracyCheck.COMPARED;
        Set<String> elsewhere = FactAccuracyCheck.INSPECTED_ELSEWHERE.keySet();
        Set<String> notComparable = FactAccuracyCheck.NOT_COMPARABLE.keySet();

        Set<String> accounted = new HashSet<>(compared);
        accounted.addAll(elsewhere);
        accounted.addAll(notComparable);
        assertThat(accounted).isEqualTo(entries);
        assertThat(compared).doesNotContainAnyElementsOf(elsewhere).doesNotContainAnyElementsOf(notComparable);
        assertThat(elsewhere).doesNotContainAnyElementsOf(notComparable);
        assertThat(FactAccuracyCheck.NOT_COMPARABLE.values()).allMatch(why -> why.source() != null
                && !why.source().isBlank() && why.reason() != null && !why.reason().isBlank());
    }

    @Test
    void aDrawnLineOfAnEntryWithoutASealedSourceIsCountedNotComparableWithItsReason() {
        SealedEvidencePackage sealed = InspectionGolden.showcaseSealed().stream()
                .filter(candidate -> candidate.getUserPromptText().contains("\nPeerReference: "))
                .findFirst().orElseThrow();

        PromptInspectionFinding finding = check(sealed).findings().stream()
                .filter(candidate -> "PeerReference".equals(candidate.entry())).findFirst().orElseThrow();
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        FactAccuracyCheck.NotComparable why = FactAccuracyCheck.NOT_COMPARABLE.get("USER_BASELINE.PeerReference");
        assertThat(finding.reason()).isEqualTo(why.reason());
        assertThat(finding.sourceRef()).isEqualTo(why.source());
    }

    @Test
    void theRequestPathTextIsComparedWithTheSealedRequestPath() {
        SealedEvidencePackage sealed = InspectionGolden.showcaseSealed().stream()
                .filter(candidate -> candidate.getUserPromptText().contains("source=request path (requester); \""))
                .findFirst().orElseThrow();
        String line = Arrays.stream(sealed.getUserPromptText().split("\n"))
                .filter(candidate -> candidate.contains("source=request path (requester); \"")).findFirst().orElseThrow();
        assertThat(mismatches(check(sealed), line.substring(0, line.indexOf(": ")))).isEmpty();

        String label = line.substring(0, line.indexOf(": "));
        sealed.setUserPromptText(sealed.getUserPromptText().replace(line,
                label + ": source=request path (requester); \"/api/admin/everything\""));
        List<PromptInspectionFinding> found = mismatches(check(sealed), label);
        assertThat(found).hasSize(1);
        assertThat(found.get(0).sourceRef()).isEqualTo("canonicalContext.resource.requestPath");
    }

    /** N-INJ-3: the business label's UNTRUSTED TEXT line is compared with the sealed label. */
    @Test
    void theBusinessLabelTextIsComparedWithTheSealedLabel() {
        InspectionGolden.Render render = InspectionGolden.render(text -> text.contains("=== REQUEST"));
        CanonicalSecurityContext context = InspectionGolden.SERIALIZER.deserialize(
                InspectionGolden.SERIALIZER.serialize(render.used()));
        if (context.getResource() == null) {
            context.setResource(new CanonicalSecurityContext.Resource());
        }
        context.getResource().setBusinessLabel("Export of 4831 documents from project GB-500");
        String source = "UntrustedText1: source=" + UntrustedTextSources.BUSINESS_LABEL + "; ";
        String kept = withUntrusted(render.userPrompt(), source + "\"Export of 4831 documents from project GB-500\"");
        String broken = withUntrusted(render.userPrompt(), source + "\"Export of 40 documents from project GB-500\"");

        assertThat(mismatches(check(sealedWith(render, kept, context)), "UntrustedText1")).isEmpty();
        List<PromptInspectionFinding> found = mismatches(check(sealedWith(render, broken, context)), "UntrustedText1");
        assertThat(found).hasSize(1);
        assertThat(found.get(0).sourceRef()).isEqualTo("canonicalContext.resource.businessLabel");
    }

    @Test
    void aCutTextKeepsTheFirstCodePointsOfItsSourceAndCountsTheRest() {
        InspectionGolden.Render render = InspectionGolden.render(text -> text.contains("=== REQUEST"));
        CanonicalSecurityContext context = InspectionGolden.SERIALIZER.deserialize(
                InspectionGolden.SERIALIZER.serialize(render.used()));
        if (context.getResource() == null) {
            context.setResource(new CanonicalSecurityContext.Resource());
        }
        context.getResource().setAuthorText("Quarterly export of the design archive, approved by the owner");
        String kept = withUntrusted(render.userPrompt(),
                "UntrustedText1: source=document description (external author); \"Quarterly… [+52 chars cut]\"");
        String broken = withUntrusted(render.userPrompt(),
                "UntrustedText1: source=document description (external author); \"Quarterly… [+9 chars cut]\"");

        assertThat(mismatches(check(sealedWith(render, kept, context)), "UntrustedText1")).isEmpty();
        List<PromptInspectionFinding> found = mismatches(check(sealedWith(render, broken, context)), "UntrustedText1");
        assertThat(found).hasSize(1);
        assertThat(found.get(0).sourceRef()).isEqualTo("canonicalContext.resource.authorText");
    }

    /**
     * R1b-2: the inspector expects the line form the render draws. A sealed author text with line breaks, a tab, a line
     * separator, a control character and quotes is drawn escaped, and the inspector finds the drawn line the sealed one.
     */
    @Test
    void theEscapedLineFormOfATextIsWhatTheInspectorExpects() {
        InspectionGolden.Render base = InspectionGolden.render(text -> text.contains("=== REQUEST"));
        InspectionGolden.Render render = InspectionGolden.renderWith(base, context -> {
            if (context.getResource() == null) {
                context.setResource(new CanonicalSecurityContext.Resource());
            }
            context.getResource().setAuthorText("Line one\nLine two\tend next \u0007bell \"quoted\"");
        });
        String line = Arrays.stream(render.userPrompt().split("\n"))
                .filter(candidate -> candidate.contains("source=document description (external author); \""))
                .findFirst().orElseThrow();
        String label = InspectionGolden.bare(line).substring(0, InspectionGolden.bare(line).indexOf(": "));

        assertThat(line).contains("Line one\\nLine two\\tend\\u2028next \\u0007bell \\\"quoted\\\"");
        assertThat(check(render.sealed()).findings().stream().filter(finding -> label.equals(finding.entry()))).isEmpty();
    }

    @Test
    void aRequestBodyTextCannotBeComparedAndSaysSo() {
        InspectionGolden.Render render = InspectionGolden.render(text -> text.contains("=== REQUEST"));
        String drawn = withUntrusted(render.userPrompt(),
                "UntrustedText1: source=request body (requester); \"{\\\"items\\\":4831}\"");

        PromptInspectionFinding finding = check(sealedWith(render, drawn, render.used())).findings().stream()
                .filter(candidate -> "UntrustedText1".equals(candidate.entry())).findFirst().orElseThrow();
        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
        assertThat(finding.reason()).contains("not sealed");
    }

    /** The prompt with one untrusted text in place of the block the render drew. */
    private static String withUntrusted(String userPrompt, String line) {
        int start = userPrompt.indexOf("=== UNTRUSTED TEXT");
        String head = start >= 0 ? userPrompt.substring(0, start) : userPrompt + "\n";
        return head + "=== UNTRUSTED TEXT (untrusted) ===\n" + line + "\n";
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
}
