package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.DictionaryContractCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The dictionary contract check of the prompt inspector on v20 renders of the golden cases: a render of the code keeps
 * the contract, and each way a prompt can break the renderer's rules is pointed at by line.
 */
class PromptInspectionDictionaryContractTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final PromptInspector INSPECTOR = new PromptInspector(List.of(new DictionaryContractCheck()), JSON);
    private static final List<String> RENDERS = new ArrayList<>();

    @BeforeAll
    static void render() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        for (JsonNode goldenCase : golden.cases()) {
            for (PromptBudgetProfile profile : SecurityDecisionGoldenRender.PROFILES) {
                RENDERS.add(golden.render(goldenCase, profile, properties).userText());
            }
        }
    }

    @Test
    void everyV20RenderOfTheGoldenCasesKeepsTheDictionaryContract() {
        int matched = 0;
        for (String render : RENDERS) {
            PromptInspectionCheckResult check = contract(render);
            assertThat(check.findings()).as(render).isEmpty();
            matched += check.matched();
        }
        assertThat(matched).isPositive();
    }

    @Test
    void aLineThatIsNoEntryOfItsBlockIsPointedAt() {
        String render = render(text -> text.contains("=== REQUEST") && text.contains("\nSubject: "));
        String broken = insertAfterLineStarting(render, "Subject: ", "Bogus: value");

        PromptInspectionFinding finding = single(contract(broken));
        assertThat(finding.block()).isEqualTo("REQUEST");
        assertThat(finding.entry()).isEqualTo("Bogus");
        assertThat(finding.lineNumber()).isEqualTo(lineNumberOf(broken, "Bogus: value"));
        assertThat(finding.reason()).contains("not an entry of the block");
    }

    @Test
    void anEntryDrawnTwiceIsPointedAtOnItsSecondLine() {
        String render = render(text -> text.contains("] Time: "));
        String line = lineContaining(render, "] Time: ");
        String broken = render.replace(line + "\n", line + "\n" + line + "\n");

        PromptInspectionFinding finding = single(contract(broken));
        assertThat(finding.entry()).isEqualTo("Time");
        assertThat(finding.lineNumber()).isEqualTo(lineNumberOf(broken, line) + 1);
        assertThat(finding.reason()).contains("drawn twice");
    }

    @Test
    void entriesOutOfDictionaryOrderArePointedAt() {
        String render = render(text -> text.contains("=== REQUEST"));
        String[] request = block(render, "=== REQUEST").split("\n");
        String first = request[1];
        String second = request[2];
        String broken = render.replace(first + "\n" + second + "\n", second + "\n" + first + "\n");
        assertThat(broken).isNotEqualTo(render);

        PromptInspectionFinding finding = single(contract(broken));
        assertThat(finding.entry()).isEqualTo(first.substring(0, first.indexOf(": ")));
        assertThat(finding.reason()).contains("dictionary order");
    }

    @Test
    void aValueOutOfTheEntryFormIsPointedAtWithTheFormItShouldHave() {
        String render = render(text -> text.contains("] Network: "));
        String network = lineContaining(render, "] Network: ");
        String broken = render.replace(network + "\n", network.substring(0, network.indexOf("] ") + 2) + "Network: somewhere\n");

        PromptInspectionFinding finding = single(contract(broken));
        assertThat(finding.entry()).isEqualTo("Network");
        assertThat(finding.actual()).isEqualTo("somewhere");
        assertThat(finding.expected()).isEqualTo(entry("REQUEST", "Network").formatPattern());
        assertThat(finding.reason()).contains("form");
    }

    @Test
    void blocksOutOfOrderArePointedAt() {
        String render = render(text -> text.contains("=== SESSION") && text.contains("=== REQUEST"));
        String session = block(render, "=== SESSION");
        String request = block(render, "=== REQUEST");
        String broken = render.replace(session + request, request + session);
        assertThat(broken).isNotEqualTo(render);

        assertThat(contract(broken).findings()).extracting(PromptInspectionFinding::reason)
                .anyMatch(reason -> reason.contains("block order"));
    }

    @Test
    void aBlockDrawnTwiceIsPointedAt() {
        String render = render(text -> text.contains("=== SESSION"));
        String session = block(render, "=== SESSION");
        String broken = render.replace(session, session + session);

        assertThat(contract(broken).findings()).extracting(PromptInspectionFinding::reason)
                .anyMatch(reason -> reason.contains("drawn twice"));
    }

    @Test
    void aHeaderOfNoBlockIsPointedAt() {
        String render = render(text -> text.contains("=== SESSION"));
        String broken = render.replace("=== SESSION", "=== CURRENT REQUEST ===\n\n=== SESSION");

        PromptInspectionFinding finding = single(contract(broken));
        assertThat(finding.lineNumber()).isEqualTo(lineNumberOf(broken, "=== CURRENT REQUEST ==="));
        assertThat(finding.reason()).contains("no block");
    }

    @Test
    void aDecisionFactWithoutItsIdIsPointedAt() {
        String render = render(text -> text.contains("[F1] "));
        String broken = render.replace("[F1] ", "");

        assertThat(contract(broken).findings()).extracting(PromptInspectionFinding::reason)
                .anyMatch(reason -> reason.contains("fact id"));
    }

    @Test
    void aFactIdOutOfDrawnOrderIsPointedAt() {
        String render = render(text -> text.contains("[F2] "));
        String broken = render.replace("[F2] ", "[F5] ");

        PromptInspectionFinding finding = single(contract(broken));
        assertThat(finding.factId()).isEqualTo("F5");
        assertThat(finding.expected()).isEqualTo("F2");
    }

    @Test
    void aFactIdOfAnotherBlockPrefixIsPointedAt() {
        String render = render(text -> text.contains("] Time: "));
        String time = lineContaining(render, "] Time: ");
        String broken = render.replace(time + "\n", "[F9] " + time.substring(time.indexOf("] ") + 2) + "\n");

        PromptInspectionFinding finding = single(contract(broken));
        assertThat(finding.entry()).isEqualTo("Time");
        assertThat(finding.factId()).isEqualTo("F9");
    }

    /** P3 extra 12: a line a reason code cites carries its block's ID in every block that has one, not only F. */
    @Test
    void aCitedRequestLineWithoutItsIdIsPointedAt() {
        String render = render(text -> text.contains("] Time: "));
        String time = lineContaining(render, "] Time: ");
        String id = time.substring(1, time.indexOf(']'));
        assertThat(id).startsWith("R");
        String broken = render.replace(time + "\n", time.substring(time.indexOf("] ") + 2) + "\n");

        PromptInspectionFinding finding = single(contract(broken));
        assertThat(finding.entry()).isEqualTo("Time");
        assertThat(finding.expected()).isEqualTo(id);
        assertThat(finding.reason()).contains("fact id");
    }

    @Test
    void aLineOfNoEntryFormIsPointedAt() {
        String render = render(text -> text.contains("\nSubject: "));
        String broken = insertAfterLineStarting(render, "Subject: ", "a sentence without a label");

        PromptInspectionFinding finding = single(contract(broken));
        assertThat(finding.lineNumber()).isEqualTo(lineNumberOf(broken, "a sentence without a label"));
        assertThat(finding.reason()).contains("not a dictionary line");
    }

    @Test
    void carriageReturnsAndAMissingFinalLineFeedArePointedAt() {
        String render = render(text -> true);

        assertThat(contract(render.replace("\n", "\r\n")).findings()).extracting(PromptInspectionFinding::reason)
                .anyMatch(reason -> reason.contains("line feeds only"));
        assertThat(contract(render.stripTrailing()).findings()).extracting(PromptInspectionFinding::reason)
                .anyMatch(reason -> reason.contains("final line feed"));
    }

    @Test
    void numberedLinesOutOfSequenceArePointedAt() {
        // A numbered line may carry its block's ID (P3 extra 12), which stays where it is.
        Pattern second = Pattern.compile("\n((?:\\[[A-Z]\\d+\\] )?)([A-Za-z]+)2: ");
        String render = render(text -> {
            Matcher matcher = second.matcher(text);
            return matcher.find() && text.contains(matcher.group(2) + "1: ");
        });
        Matcher matcher = second.matcher(render);
        assertThat(matcher.find()).isTrue();
        String stem = matcher.group(2);
        String broken = render.replace("\n" + matcher.group(1) + stem + "2: ", "\n" + matcher.group(1) + stem + "3: ");

        // The renamed line skips number 2; when the prompt already had a third line, that one is now drawn twice.
        List<PromptInspectionFinding> findings = contract(broken).findings();
        assertThat(findings).isNotEmpty().allMatch(finding -> finding.entry().equals(stem + "3"));
        assertThat(findings.get(0).expected()).isEqualTo(stem + "2");
        assertThat(findings.get(0).reason()).contains("count from 1 without gaps");
        assertThat(findings.subList(1, findings.size())).allMatch(finding -> finding.reason().contains("drawn twice"));
    }

    @Test
    void anExtraBlankLineBetweenBlocksIsNoFinding() {
        String render = render(text -> text.contains("\n\n=== SESSION"));
        String broken = render.replace("\n\n=== SESSION", "\n\n\n=== SESSION");

        assertThat(contract(broken).findings()).isEmpty();
    }

    @Test
    void anEntryLineOutsideAnyBlockIsPointedAt() {
        String render = render(text -> true);
        String broken = "Time: Mon 16:15\n" + render;

        PromptInspectionFinding finding = single(contract(broken));
        assertThat(finding.lineNumber()).isEqualTo(1);
        assertThat(finding.reason()).contains("outside a block");
    }

    private static PromptInspectionCheckResult contract(String userPrompt) {
        PromptInspectionResult result = INSPECTOR.inspect(sealed(userPrompt));
        assertThat(result.checks()).hasSize(1);
        PromptInspectionCheckResult check = result.checks().get(0);
        assertThat(check.findings()).allMatch(finding -> finding.outcome() == PromptInspectionOutcome.MISMATCH);
        assertThat(check.findings()).allMatch(finding -> DictionaryContractCheck.CODE.equals(finding.checkCode()));
        return check;
    }

    /**
     * R1b-7 (P3 extra 17) on real data: packages the showcase engine drew in the v20 layout under an earlier bundle are
     * not read against this dictionary; the check says which bundle drew them.
     */
    @Test
    void realPackagesOfAnEarlierBundleAreNotReadAgainstThisDictionary() {
        List<SealedEvidencePackage> earlier = InspectionGolden.showcaseSealedOfAnEarlierBundle();
        assertThat(earlier).isNotEmpty();
        for (SealedEvidencePackage sealed : earlier) {
            PromptInspectionResult result = INSPECTOR.inspect(sealed);
            assertThat(result.checks()).singleElement().satisfies(check -> assertThat(check.findings())
                    .singleElement().satisfies(finding -> {
                        assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
                        assertThat(finding.sourceRef())
                                .isEqualTo("executionMetadata.governanceDescriptor.promptBundleVersion");
                        assertThat(finding.actual()).isEqualTo("2026.10.11-v19.8");
                    }));
        }
    }

    private static SealedEvidencePackage sealed(String userPrompt) {
        try {
            return SealedEvidencePackage.builder()
                    .packageId("golden")
                    .rawUserPrompt(userPrompt)
                    .userPromptText(userPrompt)
                    .promptExecutionMetadataJson(JSON.writeValueAsString(Map.of("governanceDescriptor",
                            Map.of("userPromptLayoutVersion", PromptInspector.V20_LAYOUT,
                                    "promptKey", "cortex.security-decision",
                                    "promptBundleVersion", SecurityDecisionPromptBundles.V20.descriptor().promptVersion()))))
                    .build();
        }
        catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static PromptInspectionFinding single(PromptInspectionCheckResult check) {
        assertThat(check.findings()).hasSize(1);
        return check.findings().get(0);
    }

    private static String render(Predicate<String> wanted) {
        return RENDERS.stream().filter(wanted).findFirst()
                .orElseThrow(() -> new IllegalStateException("no golden render has the wanted lines"));
    }

    private static String lineStarting(String text, String start) {
        return Arrays.stream(text.split("\n")).filter(line -> line.startsWith(start)).findFirst().orElseThrow();
    }

    private static String lineContaining(String text, String part) {
        return Arrays.stream(text.split("\n")).filter(line -> line.contains(part)).findFirst().orElseThrow();
    }

    private static int lineNumberOf(String text, String line) {
        List<String> lines = Arrays.asList(text.split("\n", -1));
        int index = lines.indexOf(line);
        assertThat(index).as(line).isNotNegative();
        return index + 1;
    }

    private static String insertAfterLineStarting(String text, String start, String inserted) {
        String line = lineStarting(text, start);
        return text.replaceFirst(Pattern.quote(line + "\n"), Matcher.quoteReplacement(line + "\n" + inserted + "\n"));
    }

    /** The header line and the lines of a block up to and including the blank line before the next header. */
    private static String block(String text, String headerStart) {
        int start = text.indexOf(headerStart);
        int next = text.indexOf("\n=== ", start + 1);
        return next < 0 ? text.substring(start) : text.substring(start, next + 1);
    }

    private static PromptDictionaryEntry entry(String block, String name) {
        return SecurityDecisionPromptDictionary.ENTRIES.stream()
                .filter(entry -> entry.block().title().equals(block) && entry.name().equals(name))
                .findFirst().orElseThrow();
    }
}
