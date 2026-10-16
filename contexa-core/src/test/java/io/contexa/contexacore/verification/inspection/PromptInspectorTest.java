package io.contexa.contexacore.verification.inspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDictionary;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElement;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleManifest;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PromptInspectorTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String V20_PROMPT = """
            === REQUEST ===
            Time: Mon 16:15
            """;

    @Test
    void theCoreChecksAreTheChecksOfTheSealedPackageAloneInReportOrder() {
        assertThat(PromptInspector.coreChecks()).extracting(PromptInspectionCheck::code).containsExactly(
                "SEAL_INTEGRITY", "DICTIONARY_CONTRACT", "DECISION_FACT_MATCH", "FACT_ACCURACY", "UNKNOWN_DECLARED",
                "PAST_RECORD_NOTATION", "SAME_FACT", "REASON_MATCH");
        assertThat(PromptInspector.coreChecks()).filteredOn(check -> !check.dictionaryPromptOnly())
                .extracting(PromptInspectionCheck::code).containsExactly("SEAL_INTEGRITY");
    }

    /**
     * The version moves when a check finds something else; each raise and its reason is kept in
     * {@link PromptInspectorVersions} (R1b-7). Before that list: 2 for the bundle trace (R3), 3 for the past records (W3-18),
     * 4 for the evidence line's baseline state (W3-19), 5 for the fact IDs of every cited block (P3 extra 12), 6 for the
     * coverage levels as parts of the line (W3-5), 7 for the evidence line without the baseline state (W3-19 Q-79), 8
     * for the status line compared with the sealed baseline state (R1b-1), 9 for the render's own value functions
     * (R1b-2: requests of the same time expected in the render's order), 10 for one place of each rule the render and
     * the checks share (R1b-3: an unknown kind is a word the renderer draws and its reason is compared as the renderer
     * trims it; P3 extra 39: the differences line without a difference may state the closest past record), 11 for the
     * usual lines of a user without any learning compared with the sealed NONE state (R1b-4, P3 extra 41), 12 for
     * one rule of sealed sources that do not read: named once and the lines drawn from them left unchecked (R1b-5).
     */
    @Test
    void theVersionIsTheOneOfTheCurrentChecks() {
        // 19: a source fact the UNKNOWN line names is its missing notation (N-SRC-1).
        assertThat(PromptInspector.INSPECTOR_VERSION).isEqualTo("prompt-inspector/19");
    }

    /**
     * R1b-7: the dictionary checks read a package drawn in this build's form only: its bundle has this build's
     * dictionary (B2) and the render of this build's v20 bundle (B3). The other elements do not change the form.
     */
    @Test
    void aBundleIsOfThisFormWithThisDictionaryAndThisRender() {
        PromptBundleManifest current = PromptBundleCatalog.shared()
                .find("cortex.security-decision", SecurityDecisionPromptBundles.V20.descriptor().promptVersion())
                .orElseThrow();
        String other = "0".repeat(64);

        assertThat(PromptInspector.drawnInThisForm(current, current)).isTrue();
        assertThat(PromptInspector.drawnInThisForm(withElement(current, "B2", other), current)).isFalse();
        assertThat(PromptInspector.drawnInThisForm(withElement(current, "B3", other), current)).isFalse();
        assertThat(PromptInspector.drawnInThisForm(withElement(current, "B4", other), current)).isTrue();
    }

    /** The manifest with one element's hash replaced, under another bundle version. */
    private static PromptBundleManifest withElement(PromptBundleManifest manifest, String elementId, String hash) {
        List<PromptBundleElement> elements = new ArrayList<>();
        for (PromptBundleElement element : manifest.elements()) {
            elements.add(element.id().equals(elementId)
                    ? new PromptBundleElement(element.id(), element.state(), hash, element.detail()) : element);
        }
        return new PromptBundleManifest(manifest.promptKey(), manifest.bundleVersion() + "-other",
                PromptBundleHashes.bundleHash(elements), elements, manifest.goldenInputs(), manifest.parentVersion(),
                manifest.changeSummary(), manifest.problemIds(), manifest.author(), manifest.frozenOn(),
                manifest.vocabularyVersion(), manifest.compatibleVocabularyVersions(), manifest.rollbackTargets(),
                manifest.declaredModelProfiles());
    }

    @Test
    void aV20PromptWithoutFindingsPasses() {
        PromptInspectionResult result = inspector(check("A", tally -> tally.matched()), check("B", tally -> tally.matched()))
                .inspect(sealed(V20_PROMPT, PromptInspector.V20_LAYOUT));

        assertThat(result.verdict()).isEqualTo(PromptInspectionVerdict.PASS);
        assertThat(result.matchedCount()).isEqualTo(2);
        assertThat(result.mismatchCount()).isZero();
        assertThat(result.unverifiableCount()).isZero();
        assertThat(result.packageId()).isEqualTo("pkg-1");
        assertThat(result.inspectorVersion()).isEqualTo(PromptInspector.INSPECTOR_VERSION);
        assertThat(result.dictionaryVersion()).isEqualTo(PromptInspector.DICTIONARY_VERSION);
        assertThat(result.layoutVersion()).isEqualTo(PromptInspector.V20_LAYOUT);
    }

    @Test
    void anUnverifiableItemMakesTheResultIncompleteNotPassing() {
        PromptInspectionResult result = inspector(
                check("A", tally -> tally.matched()),
                check("B", tally -> tally.unverifiable(finding("B", PromptInspectionOutcome.UNVERIFIABLE))))
                .inspect(sealed(V20_PROMPT, PromptInspector.V20_LAYOUT));

        assertThat(result.verdict()).isEqualTo(PromptInspectionVerdict.INCOMPLETE);
        assertThat(result.unverifiableCount()).isEqualTo(1);
        assertThat(result.findings()).extracting(PromptInspectionFinding::checkCode).containsExactly("B");
    }

    @Test
    void aMismatchFailsWhateverElseIsUnverifiable() {
        PromptInspectionResult result = inspector(
                check("A", tally -> tally.mismatch(finding("A", PromptInspectionOutcome.MISMATCH))),
                check("B", tally -> tally.unverifiable(finding("B", PromptInspectionOutcome.UNVERIFIABLE))))
                .inspect(sealed(V20_PROMPT, PromptInspector.V20_LAYOUT));

        assertThat(result.verdict()).isEqualTo(PromptInspectionVerdict.FAIL);
        assertThat(result.mismatchCount()).isEqualTo(1);
        assertThat(result.unverifiableCount()).isEqualTo(1);
    }

    @Test
    void aV19PromptRunsOnlyTheChecksThatDoNotReadTheDictionary() {
        PromptInspectionCheck dictionary = check("DICT", tally -> tally.mismatch(finding("DICT", PromptInspectionOutcome.MISMATCH)));
        PromptInspectionCheck seal = new FakeCheck("SEAL", false, tally -> tally.matched());

        PromptInspectionResult result = inspector(dictionary, seal)
                .inspect(sealed("=== CURRENT REQUEST ===\nRequestPath: /a\n", "2026.10.11-v19.8"));

        assertThat(result.verdict()).isEqualTo(PromptInspectionVerdict.NOT_APPLICABLE);
        assertThat(result.checks()).extracting(PromptInspectionCheckResult::checkCode).containsExactly("SEAL");
        assertThat(result.layoutVersion()).isEqualTo("2026.10.11-v19.8");
    }

    @Test
    void aMismatchOfACheckThatRunsOnEveryLayoutFailsAV19Prompt() {
        PromptInspectionCheck seal = new FakeCheck("SEAL", false,
                tally -> tally.mismatch(finding("SEAL", PromptInspectionOutcome.MISMATCH)));

        PromptInspectionResult result = inspector(seal)
                .inspect(sealed("=== CURRENT REQUEST ===\nRequestPath: /a\n", "2026.10.11-v19.8"));

        assertThat(result.verdict()).isEqualTo(PromptInspectionVerdict.FAIL);
    }

    @Test
    void aPackageWithoutASealedLayoutIsNotReadAsADictionaryPrompt() {
        PromptInspectionCheck dictionary = check("DICT", tally -> tally.matched());

        PromptInspectionResult result = inspector(dictionary).inspect(sealed(V20_PROMPT, null));

        assertThat(result.verdict()).isEqualTo(PromptInspectionVerdict.NOT_APPLICABLE);
        assertThat(result.checks()).isEmpty();
        assertThat(result.layoutVersion()).isNull();
    }

    @Test
    void anUnreadableExecutionMetadataIsAnError() {
        SealedEvidencePackage evidencePackage = sealed(V20_PROMPT, PromptInspector.V20_LAYOUT);
        evidencePackage.setPromptExecutionMetadataJson("{not json");

        PromptInspectionResult result = inspector(check("A", tally -> tally.matched())).inspect(evidencePackage);

        assertThat(result.verdict()).isEqualTo(PromptInspectionVerdict.ERROR);
        assertThat(result.errorReason()).contains("execution metadata");
        assertThat(result.checks()).isEmpty();
    }

    @Test
    void aPackageWithoutTheUserPromptTheModelGotIsAnError() {
        SealedEvidencePackage evidencePackage = sealed(V20_PROMPT, PromptInspector.V20_LAYOUT);
        evidencePackage.setUserPromptText(null);

        PromptInspectionResult result = inspector(check("A", tally -> tally.matched())).inspect(evidencePackage);

        assertThat(result.verdict()).isEqualTo(PromptInspectionVerdict.ERROR);
        assertThat(result.errorReason()).contains("user prompt");
    }

    @Test
    void aCheckThatThrowsIsAnErrorOfThatCheckNotOfTheOthers() {
        PromptInspectionCheck broken = check("BROKEN", tally -> {
            throw new IllegalStateException("boom");
        });

        PromptInspectionResult result = inspector(check("A", tally -> tally.matched()), broken)
                .inspect(sealed(V20_PROMPT, PromptInspector.V20_LAYOUT));

        assertThat(result.verdict()).isEqualTo(PromptInspectionVerdict.ERROR);
        assertThat(result.errorReason()).contains("BROKEN").contains("boom");
        assertThat(result.checks()).extracting(PromptInspectionCheckResult::checkCode).containsExactly("A");
    }

    @Test
    void theSubjectCarriesTheParsedPromptOfTheTextTheModelGot() {
        PromptInspectionCheck reader = check("READ", tally -> {
            assertThat(tally.subject().prompt().lines()).hasSize(2);
            assertThat(tally.subject().prompt().lines().get(1).entryLine().label()).isEqualTo("Time");
            tally.matched();
        });

        PromptInspectionResult result = inspector(reader).inspect(sealed(V20_PROMPT, PromptInspector.V20_LAYOUT));

        assertThat(result.verdict()).isEqualTo(PromptInspectionVerdict.PASS);
    }

    /** R1b-5: a source a check reads that cannot be read now leaves no result, not a lasting error. */
    @Test
    void aSourceACheckReadsThatIsUnavailableNowLeavesNoResult() {
        PromptInspector inspector = inspector(check("A", PromptInspectionTally::matched), check("B", tally -> {
            throw new PromptInspectionUnavailableException("the release registry is not available", null);
        }));

        assertThatThrownBy(() -> inspector.inspect(sealed(V20_PROMPT, PromptInspector.V20_LAYOUT)))
                .isInstanceOf(PromptInspectionUnavailableException.class);
    }

    /** R1b-7: a result names the dictionary it was read with by the digest of its content, not a fixed version. */
    @Test
    void aResultNamesTheDictionaryItWasReadWithByItsDigest() {
        PromptInspectionResult result = inspector(check("A", PromptInspectionTally::matched))
                .inspect(sealed(V20_PROMPT, PromptInspector.V20_LAYOUT));

        assertThat(SecurityDecisionPromptDictionary.contentDigest()).matches("[0-9a-f]{64}");
        assertThat(result.dictionaryVersion()).isEqualTo(SecurityDecisionPromptDictionary.VERSION + "@"
                + SecurityDecisionPromptDictionary.contentDigest().substring(0, 12));
    }

    /**
     * R1b-7 (P3 extra 17): a v20 package sealed under another bundle's dictionary is not read against this one: the
     * checks that read the dictionary prompt leave it unchecked and say why, the others run.
     */
    @Test
    void aPackageSealedUnderAnotherDictionaryIsNotReadAgainstThisOne() {
        int[] dictionaryReads = {0};
        PromptInspector inspector = inspector(check("D", tally -> {
            dictionaryReads[0]++;
            tally.matched();
        }), new FakeCheck("S", false, PromptInspectionTally::matched));

        PromptInspectionResult result = inspector.inspect(sealed(V20_PROMPT, PromptInspector.V20_LAYOUT,
                "2026.10.13-v20.4"));

        assertThat(dictionaryReads[0]).isZero();
        assertThat(result.verdict()).isEqualTo(PromptInspectionVerdict.INCOMPLETE);
        assertThat(result.checks()).extracting(PromptInspectionCheckResult::checkCode).containsExactly("D", "S");
        assertThat(result.checks().get(0).findings()).singleElement().satisfies(finding -> {
            assertThat(finding.outcome()).isEqualTo(PromptInspectionOutcome.UNVERIFIABLE);
            assertThat(finding.sourceRef()).isEqualTo("executionMetadata.governanceDescriptor.promptBundleVersion");
            assertThat(finding.actual()).isEqualTo("2026.10.13-v20.4");
        });
        assertThat(result.checks().get(1).matched()).isEqualTo(1);

        inspector.inspect(sealed(V20_PROMPT, PromptInspector.V20_LAYOUT));
        assertThat(dictionaryReads[0]).isEqualTo(1);
    }

    private static PromptInspector inspector(PromptInspectionCheck... checks) {
        return new PromptInspector(List.of(checks), JSON);
    }

    private static PromptInspectionCheck check(String code, Consumer<PromptInspectionTally> body) {
        return new FakeCheck(code, true, body);
    }

    private static PromptInspectionFinding finding(String code, PromptInspectionOutcome outcome) {
        return PromptInspectionFinding.builder(code, outcome).reason("fake").build();
    }

    static SealedEvidencePackage sealed(String userPrompt, String layout) {
        return sealed(userPrompt, layout, SecurityDecisionPromptBundles.V20.descriptor().promptVersion());
    }

    /** A package as the assembler seals it: the governance descriptor names the bundle the prompt was drawn with. */
    static SealedEvidencePackage sealed(String userPrompt, String layout, String bundleVersion) {
        String metadata;
        try {
            metadata = layout == null
                    ? JSON.writeValueAsString(Map.of("promptVersion", "2026.10.11-v19.8"))
                    : JSON.writeValueAsString(Map.of("governanceDescriptor",
                    Map.of("userPromptLayoutVersion", layout, "promptKey", "cortex.security-decision",
                            "promptBundleVersion", bundleVersion)));
        }
        catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
        return SealedEvidencePackage.builder()
                .packageId("pkg-1")
                .rawUserPrompt(userPrompt)
                .userPromptText(userPrompt)
                .promptExecutionMetadataJson(metadata)
                .build();
    }

    private record FakeCheck(String code, boolean dictionaryPromptOnly,
                             Consumer<PromptInspectionTally> body) implements PromptInspectionCheck {

        @Override
        public void inspect(PromptInspectionTally tally) {
            body.accept(tally);
        }
    }
}
