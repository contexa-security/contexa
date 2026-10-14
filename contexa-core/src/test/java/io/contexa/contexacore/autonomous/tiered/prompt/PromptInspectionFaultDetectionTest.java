package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The prompt inspector with the core checks against the v20 prompt quality faults (W3-14, the faults that reached a
 * model): on every golden render each line a fault writes or changes is pointed at on its line as a mismatch and each
 * line it takes away is pointed at by its entry; a render without faults, or with a harmless change, has no mismatch;
 * and what the golden renders leave uncheckable is a fixed list.
 */
class PromptInspectionFaultDetectionTest {

    private static final PromptInspector INSPECTOR = new PromptInspector(PromptInspector.coreChecks(),
            InspectionGolden.JSON);
    private static final Pattern ENTRY_LABEL = Pattern.compile("^(?:\\[[A-Z]+\\d+] )?([A-Za-z][A-Za-z0-9]*): ");

    @Test
    void everyLineTheResourceAndActionFaultWritesIsPointedAt() {
        int faulted = everyFaultLinePointedAt("resource-action-fault", render -> PromptQualityDictionaryFaults
                .resourceActionNotAvailable(
                render.userPrompt()));
        assertThat(faulted).isEqualTo(InspectionGolden.renders().size());
    }

    @Test
    void everyLineTheMultiMetricFaultsWriteIsPointedAt() {
        int faulted = everyFaultLinePointedAt("multi-metric-faults", render -> {
            CanonicalSecurityContext.Resource resource = render.used().getResource();
            String path = resource != null && resource.getRequestPath() != null ? resource.getRequestPath()
                    : "/requested/path";
            String id = resource != null && resource.getResourceId() != null ? resource.getResourceId() : "resource-001";
            return PromptQualityDictionaryFaults.allMetricRuntimeSlotFaults(render.userPrompt(), path, id);
        });
        assertThat(faulted).isEqualTo(InspectionGolden.renders().size());
    }

    @Test
    void aGoldenRenderWithoutFaultsHasNoMismatchAndAFixedListOfWhatCannotBeChecked() {
        Set<String> unverifiable = new TreeSet<>();
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            PromptInspectionResult result = INSPECTOR.inspect(render.sealed());
            assertThat(mismatches(result)).as(render.caseKey() + " " + render.profile()).isEmpty();
            result.findings().forEach(finding -> unverifiable.add(finding.checkCode() + " "
                    + finding.block() + (finding.entry() != null ? "." + finding.entry() : "") + " <- "
                    + finding.sourceRef()));
        }
        assertThat(unverifiable).containsExactlyElementsOf(UNCHECKABLE_ON_THE_GOLDEN_RENDERS);
    }

    @Test
    void aBlankLineMoreBetweenBlocksIsNoFinding() {
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            String spaced = render.userPrompt().replace("\n\n===", "\n\n\n===");
            assertThat(spaced).isNotEqualTo(render.userPrompt());

            PromptInspectionResult result = INSPECTOR.inspect(render.sealed(spaced));
            assertThat(mismatches(result)).as(render.caseKey() + " " + render.profile()).isEmpty();
            assertThat(result.unverifiableCount())
                    .isEqualTo(INSPECTOR.inspect(render.sealed()).unverifiableCount());
        }
    }

    /**
     * What the golden renders leave uncheckable, each for a source that is not sealed: the learning evidence, which no
     * package seals (the two baseline comparison facts; the baseline status is compared with the sealed state since
     * R1b-1), and what the golden case files predate
     * (the sealed authentication state and an observed baseline view in the sealed context).
     */
    private static final List<String> UNCHECKABLE_ON_THE_GOLDEN_RENDERS = List.of(
            "DECISION_FACT_MATCH DECISION FACTS.DeviationsFromBaseline <- learningContextEvidence",
            "DECISION_FACT_MATCH DECISION FACTS.SameAsBaseline <- learningContextEvidence",
            "FACT_ACCURACY SESSION.LoginMethod <- authStateJson.authMethod",
            "FACT_ACCURACY USER BASELINE.UsualActions <- canonicalContext.workProfile.baselineView",
            "FACT_ACCURACY USER BASELINE.UsualDays <- canonicalContext.workProfile.baselineView",
            "FACT_ACCURACY USER BASELINE.UsualDevices <- canonicalContext.workProfile.baselineView",
            "FACT_ACCURACY USER BASELINE.UsualExportSize <- canonicalContext.workProfile.baselineView",
            "FACT_ACCURACY USER BASELINE.UsualHours <- canonicalContext.workProfile.baselineView",
            "FACT_ACCURACY USER BASELINE.UsualRequestRate <- canonicalContext.workProfile.baselineView",
            "FACT_ACCURACY USER BASELINE.UsualResourceClass <- canonicalContext.workProfile.baselineView",
            "FACT_ACCURACY USER BASELINE.UsualTargets <- canonicalContext.workProfile.baselineView");

    /**
     * Applies the fault to every golden render, requires every fault line to be pointed at, writes which checks pointed
     * at each kind of fault line to the build reports and returns how many renders the fault changed.
     */
    private static int everyFaultLinePointedAt(String report, Function<InspectionGolden.Render, String> fault) {
        int faulted = 0;
        Map<String, Set<String>> checksByLine = new TreeMap<>();
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            String prompt = fault.apply(render);
            if (prompt.equals(render.userPrompt())) {
                continue;
            }
            faulted++;
            List<PromptInspectionFinding> mismatches = mismatches(INSPECTOR.inspect(render.sealed(prompt)));
            List<String> missed = new ArrayList<>();
            for (FaultLine line : faultLines(render.userPrompt(), prompt)) {
                Set<String> checks = mismatches.stream()
                        .filter(finding -> line.number() != null ? line.number().equals(finding.lineNumber())
                                : line.label() != null && line.label().equals(finding.entry()))
                        .map(PromptInspectionFinding::checkCode).collect(Collectors.toCollection(TreeSet::new));
                if (checks.isEmpty()) {
                    missed.add(line.toString());
                }
                checksByLine.computeIfAbsent(line.kind(), key -> new TreeSet<>()).addAll(checks);
            }
            assertThat(missed).as(render.caseKey() + " " + render.profile()).isEmpty();
        }
        write(report, checksByLine);
        return faulted;
    }

    /** A line the fault wrote or changed (with its number) or took away (without one). */
    private record FaultLine(Integer number, String text, String label) {

        /** The kind of the line across renders: its entry label, or the text of a line that is no entry. */
        String kind() {
            return (number == null ? "taken away " : "") + (label != null ? label : text);
        }

        @Override
        public String toString() {
            return (number != null ? number + ": " : "taken away: ") + text;
        }
    }

    private static List<FaultLine> faultLines(String original, String faulted) {
        Map<String, Integer> before = new HashMap<>();
        for (String line : original.split("\n", -1)) {
            before.merge(line, 1, Integer::sum);
        }
        List<FaultLine> lines = new ArrayList<>();
        String[] after = faulted.split("\n", -1);
        for (int index = 0; index < after.length; index++) {
            Integer left = before.get(after[index]);
            if (left != null && left > 0) {
                before.put(after[index], left - 1);
                continue;
            }
            lines.add(new FaultLine(index + 1, after[index], label(after[index])));
        }
        before.forEach((line, left) -> {
            if (left > 0 && !line.isBlank()) {
                lines.add(new FaultLine(null, line, label(line)));
            }
        });
        return lines;
    }

    private static String label(String line) {
        Matcher label = ENTRY_LABEL.matcher(line);
        return label.find() ? label.group(1) : null;
    }

    private static void write(String report, Map<String, Set<String>> checksByLine) {
        try {
            Path path = Path.of("build/reports/prompt-inspection/" + report + ".json");
            Files.createDirectories(path.getParent());
            Files.writeString(path, InspectionGolden.JSON.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(checksByLine));
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    private static List<PromptInspectionFinding> mismatches(PromptInspectionResult result) {
        return result.findings().stream().filter(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH)
                .toList();
    }
}
