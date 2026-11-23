package io.contexa.contexaiam.admin.promptquality.inspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.inspection.InspectedPrompt;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionRecord;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionResultStore;
import io.contexa.contexacore.verification.inspection.PromptInspectionTally;
import io.contexa.contexacore.verification.inspection.PromptInspectionTrigger;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.lang.reflect.RecordComponent;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The inspection detail: the package's user prompt line by line with the checks that matched each line and the
 * findings on it, inspected again with this inspector, beside the stored results, and what changed from the newest
 * stored result of another inspector version (the findings gone and the new ones).
 */
class PromptInspectionConsoleTest {

    private static final String PROMPT = "=== REQUEST ===\nSubject: user-1\nNotALine\n";
    private static final Instant CAPTURED = Instant.parse("2026-10-12T05:00:00Z");

    private final SealedEvidencePackageRepository packages = mock(SealedEvidencePackageRepository.class);
    private final PromptInspectionResultStore store = mock(PromptInspectionResultStore.class);
    /**
     * The core checks read no line of the prompt since the inspection is the evidence audit (plan 2.1 of the prompt
     * quality redesign), so a check of the test matches the lines that read as lines and points at the others.
     */
    private static final String LINES = "LINES";
    private final PromptInspector inspector = new PromptInspector(withLineCheck(), new ObjectMapper());
    private final PromptInspectionConsole console = new PromptInspectionConsole(packages, inspector, store,
            new ObjectMapper());

    @Test
    void eachLineCarriesTheChecksThatMatchedItAndTheFindingsOnIt() {
        when(packages.findByPackageId("p1")).thenReturn(Optional.of(sealed()));
        when(store.findAll("p1")).thenReturn(List.of());

        PromptInspectionConsole.Detail detail = console.detail("p1").orElseThrow();

        assertThat(detail.lines()).extracting(PromptInspectionConsole.LineView::text)
                .containsExactly("=== REQUEST ===", "Subject: user-1", "NotALine");
        assertThat(detail.lines().get(0).matchedBy()).contains(LINES);
        PromptInspectionConsole.LineView notALine = detail.lines().get(2);
        assertThat(notALine.findings()).extracting(PromptInspectionFinding::checkCode).contains(LINES);
        assertThat(notALine.findings()).allMatch(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH);
        assertThat(detail.unplacedFindings()).allMatch(finding -> finding.lineNumber() == null);
        assertThat(detail.verdict()).isEqualTo("FAIL");
        assertThat(detail.inspectorVersion()).isEqualTo(PromptInspector.INSPECTOR_VERSION);
        assertThat(detail.checks()).extracting(PromptInspectionConsole.CheckView::checkCode)
                .contains("SEAL_INTEGRITY", LINES);
        assertThat(detail.stored()).isNull();
        assertThat(detail.changes()).isNull();
        assertThat(detail.history()).isEmpty();
    }

    @Test
    void thePackageReadsWithItsRequestAndTheStoredResultsBesideTheInspectionAgain() {
        SealedEvidencePackage sealed = sealed();
        when(packages.findByPackageId("p1")).thenReturn(Optional.of(sealed));
        PromptInspectionRecord same = new PromptInspectionRecord(7L, inspector.inspect(sealed),
                PromptInspectionTrigger.AUTO, CAPTURED.plusSeconds(30));
        when(store.findAll("p1")).thenReturn(List.of(same));

        PromptInspectionConsole.Detail detail = console.detail("p1").orElseThrow();

        assertThat(detail.capturedAt()).isEqualTo(CAPTURED);
        assertThat(detail.userId()).isEqualTo("user-1");
        assertThat(detail.httpMethod()).isEqualTo("POST");
        assertThat(detail.requestPath()).isEqualTo("/api/projects/GB-500/exports");
        assertThat(detail.resourceId()).isEqualTo("exportDocuments");
        assertThat(detail.stored().inspectorVersion()).isEqualTo(PromptInspector.INSPECTOR_VERSION);
        assertThat(detail.stored().sameInspector()).isTrue();
        assertThat(detail.stored().sameFindings()).isTrue();
        assertThat(detail.history()).extracting(PromptInspectionConsole.HistoryView::inspectorVersion)
                .containsExactly(PromptInspector.INSPECTOR_VERSION);
        assertThat(detail.changes().comparedVersion()).isEqualTo(PromptInspector.INSPECTOR_VERSION);
        assertThat(detail.changes().disappeared()).isEmpty();
        assertThat(detail.changes().appeared()).isEmpty();
    }

    @Test
    void aStoredResultOfKindsIsTheInspectionAgainWhenItHasTheSameKindsOnAsManyLines() {
        // W3-20: the store keeps a result's findings as kinds with their lines, not the lines' numbers and values.
        SealedEvidencePackage sealed = sealed();
        when(packages.findByPackageId("p1")).thenReturn(Optional.of(sealed));
        PromptInspectionResult current = inspector.inspect(sealed);
        assertThat(current.findings()).anyMatch(finding -> finding.lineNumber() != null);
        when(store.findAll("p1")).thenReturn(List.of(new PromptInspectionRecord(7L,
                asKinds(current, current.findings()), PromptInspectionTrigger.AUTO, CAPTURED.plusSeconds(30))));

        assertThat(console.detail("p1").orElseThrow().stored().sameFindings()).isTrue();

        when(store.findAll("p1")).thenReturn(List.of(new PromptInspectionRecord(7L,
                asKinds(current, current.findings().subList(1, current.findings().size())),
                PromptInspectionTrigger.AUTO, CAPTURED.plusSeconds(30))));

        assertThat(console.detail("p1").orElseThrow().stored().sameFindings()).isFalse();
    }

    /** The result as the store reads it back: the kept findings without their line numbers and values. */
    private static PromptInspectionResult asKinds(PromptInspectionResult result, List<PromptInspectionFinding> kept) {
        List<PromptInspectionCheckResult> checks = result.checks().stream()
                .map(check -> new PromptInspectionCheckResult(check.checkCode(), check.matched(), check.mismatched(),
                        check.unverifiable(), kept.stream()
                        .filter(finding -> check.checkCode().equals(finding.checkCode()))
                        .map(finding -> PromptInspectionFinding.builder(finding.checkCode(), finding.outcome())
                                .block(finding.block()).entry(finding.entry()).sourceRef(finding.sourceRef())
                                .reason(finding.reason()).build())
                        .toList()))
                .toList();
        return new PromptInspectionResult(result.packageId(), result.inspectorVersion(), result.dictionaryVersion(),
                result.layoutVersion(), result.verdict(), checks, result.errorReason());
    }

    @Test
    void theFindingsGoneAndNewSinceAnotherInspectorsResultAreListed() {
        SealedEvidencePackage sealed = sealed();
        when(packages.findByPackageId("p1")).thenReturn(Optional.of(sealed));
        PromptInspectionResult current = inspector.inspect(sealed);
        PromptInspectionFinding gone = PromptInspectionFinding.builder("BUNDLE_TRACE", PromptInspectionOutcome.MISMATCH)
                .entry("promptVersion").reason("a finding the older inspector made").build();
        List<PromptInspectionCheckResult> olderChecks = new ArrayList<>(current.checks().subList(1,
                current.checks().size()));
        olderChecks.add(new PromptInspectionCheckResult("BUNDLE_TRACE", 0, 1, 0, List.of(gone)));
        PromptInspectionResult older = new PromptInspectionResult("p1", "prompt-inspector/0", current.dictionaryVersion(),
                current.layoutVersion(), PromptInspectionVerdict.FAIL, olderChecks, null);
        PromptInspectionRecord sameVersion = new PromptInspectionRecord(9L, current, PromptInspectionTrigger.AUTO,
                CAPTURED.plusSeconds(90));
        PromptInspectionRecord olderVersion = new PromptInspectionRecord(3L, older, PromptInspectionTrigger.AUTO,
                CAPTURED.plusSeconds(30));
        when(store.findAll("p1")).thenReturn(List.of(sameVersion, olderVersion));

        PromptInspectionConsole.Detail detail = console.detail("p1").orElseThrow();

        assertThat(detail.changes().comparedVersion()).isEqualTo("prompt-inspector/0");
        assertThat(detail.changes().comparedAt()).isEqualTo(CAPTURED.plusSeconds(30));
        assertThat(detail.changes().disappeared()).containsExactly(gone);
        assertThat(detail.changes().appeared()).containsExactlyElementsOf(current.checks().get(0).findings());
        assertThat(detail.history()).extracting(PromptInspectionConsole.HistoryView::inspectorVersion)
                .containsExactly(PromptInspector.INSPECTOR_VERSION, "prompt-inspector/0");
    }

    @Test
    void theAnswerKeepsNoFieldTheScreensDoNotUse() {
        assertThat(components(PromptInspectionConsole.Detail.class)).doesNotContain("correlationId")
                .contains("errorReason");
        assertThat(components(PromptInspectionConsole.LineView.class)).doesNotContain("kind");
        assertThat(components(PromptInspectionConsole.HistoryView.class)).doesNotContain("resultId");
    }

    private static List<String> components(Class<?> type) {
        return Arrays.stream(type.getRecordComponents()).map(RecordComponent::getName).toList();
    }

    @Test
    void anUnknownPackageHasNoDetail() {
        when(packages.findByPackageId("none")).thenReturn(Optional.empty());
        assertThat(console.detail("none")).isEmpty();
    }

    /** The core checks and a check that matches every header and entry line and points at any other line. */
    private static List<PromptInspectionCheck> withLineCheck() {
        List<PromptInspectionCheck> checks = new ArrayList<>(PromptInspector.coreChecks());
        checks.add(new PromptInspectionCheck() {
            @Override
            public String code() {
                return LINES;
            }

            @Override
            public boolean dictionaryPromptOnly() {
                return false;
            }

            @Override
            public void inspect(PromptInspectionTally tally) {
                for (InspectedPrompt.Line line : tally.subject().prompt().lines()) {
                    if (line.kind() == InspectedPrompt.Kind.HEADER || line.kind() == InspectedPrompt.Kind.ENTRY) {
                        tally.matched(line);
                    } else if (line.kind() == InspectedPrompt.Kind.OTHER) {
                        tally.mismatch(tally.mismatchFinding().lineNumber(line.number()).actual(line.text())
                                .reason("not a line of the dictionary").build());
                    }
                }
            }
        });
        return checks;
    }

    private static SealedEvidencePackage sealed() {
        return SealedEvidencePackage.builder()
                .packageId("p1")
                .correlationId("correlation-p1")
                .capturedAt(CAPTURED)
                .userId("user-1")
                .userPromptText(PROMPT)
                .rawUserPrompt(PROMPT)
                .requestFactsJson("{\"httpMethod\":\"POST\",\"requestPath\":\"/api/projects/GB-500/exports\","
                        + "\"resourceId\":\"exportDocuments\"}")
                .promptExecutionMetadataJson("{\"governanceDescriptor\":{\"userPromptLayoutVersion\":\""
                        + PromptInspector.V1_LAYOUT + "\",\"promptKey\":\"cortex.security-decision\","
                        + "\"promptBundleVersion\":\"" + SecurityDecisionPromptBundles.V1.descriptor().promptVersion()
                        + "\"}}")
                .build();
    }
}
