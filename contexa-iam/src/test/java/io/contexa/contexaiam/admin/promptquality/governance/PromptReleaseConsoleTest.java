package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElement;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElementState;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleManifest;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * W7-14 (version management design 11, PV-8, PV-14): the version screens' read model. A bundle shows its name, hash,
 * canonical state and scope, whether this build holds it, and the release gate's answer as it is; a bundle's detail
 * adds its manifest, gate and rollbacks; two bundles are compared element by element and by their sealed decisions.
 */
class PromptReleaseConsoleTest {

    private static final String SCOPE = "PLATFORM_GLOBAL";
    private static final String KEY = "test.prompt";
    private static final String V1 = "2026.10.16-v1";
    private static final String V2 = "2026.10.16-v2";
    private static final LocalDateTime AT = LocalDateTime.of(2026, 10, 16, 9, 0);
    private static final Instant FROM = Instant.parse("2026-10-09T00:00:00Z");
    private static final Instant TO = Instant.parse("2026-10-16T00:00:00Z");

    private final JdbcPromptReleaseQueryService releases = mock(JdbcPromptReleaseQueryService.class);
    private final PromptGovernanceReleaseGateService gate = mock(PromptGovernanceReleaseGateService.class);
    private final PromptBundleRollbackService rollbacks = mock(PromptBundleRollbackService.class);
    private final JdbcPromptInspectionQueries sealed = mock(JdbcPromptInspectionQueries.class);
    private final PromptBundleManifest v1 = manifest(V1, "system text one", "vocab-1", null);
    private final PromptBundleManifest v2 = manifest(V2, "system text two", "vocab-2", V1);
    private PromptReleaseConsole console;

    @BeforeEach
    void setUp() {
        console = new PromptReleaseConsole(releases, gate, rollbacks, new PromptBundleCatalog(List.of(v1, v2)), sealed);
        when(releases.releases(anyString())).thenReturn(new JdbcPromptReleaseQueryService.PromptReleaseSnapshot(List.of(
                row(V2, v2.bundleHash(), "EVAL_ONLY", 10, "tenant-a", "EXPORT"),
                row(V1, "0".repeat(64), "PRODUCTION", null, null, null),
                row("2026.01.01-v0", "1".repeat(64), "SOMETHING_ELSE", null, null, null),
                row("2025.12.01-v9", "2".repeat(64), "RETIRED", null, null, null))));
        when(gate.assessPromptRelease(SCOPE, KEY, V2)).thenReturn(assessment(V2, "SHADOW",
                target("CANARY", true), target("RETIRED", true)));
        when(gate.assessPromptRelease(SCOPE, KEY, V1)).thenReturn(assessment(V1, "ACTIVE",
                target("CANARY", false, "CHANGE_LEDGER_MISSING enterprise change evidence must exist."),
                target("DEPRECATED", true), target("RETIRED", true)));
        when(gate.assessPromptRelease(SCOPE, KEY, "2026.01.01-v0"))
                .thenThrow(new IllegalArgumentException("Unknown prompt governance artifact"));
    }

    @Test
    void aBundleShowsItsNameHashCanonicalStateScopeAndBuild() {
        List<PromptReleaseConsole.BundleRow> rows = console.bundles(SCOPE);

        assertThat(rows).extracting(PromptReleaseConsole.BundleRow::bundleVersion)
                .containsExactly(V2, V1, "2026.01.01-v0", "2025.12.01-v9");
        PromptReleaseConsole.BundleRow shadow = rows.get(0);
        assertThat(shadow.bundleHash()).isEqualTo(v2.bundleHash());
        assertThat(shadow.state()).isEqualTo("SHADOW");
        assertThat(shadow.unknownStatus()).isNull();
        assertThat(shadow.registryScope()).isEqualTo(SCOPE);
        assertThat(shadow.canary()).isEqualTo(new PromptReleaseConsole.Canary(10, "tenant-a", "EXPORT"));
        assertThat(shadow.inBuild()).isTrue();
        assertThat(shadow.hashMatchesBuild()).isTrue();
        PromptReleaseConsole.BundleRow active = rows.get(1);
        assertThat(active.state()).isEqualTo("ACTIVE");
        assertThat(active.hashMatchesBuild()).isFalse();
        PromptReleaseConsole.BundleRow unknown = rows.get(2);
        assertThat(unknown.state()).isNull();
        assertThat(unknown.unknownStatus()).isEqualTo("SOMETHING_ELSE");
        assertThat(unknown.inBuild()).isFalse();
    }

    @Test
    void readyIsTheGatesAnswerAndNothingElse() {
        List<PromptReleaseConsole.BundleRow> rows = console.bundles(SCOPE);

        assertThat(rows.get(0).gate()).isEqualTo(gate.assessPromptRelease(SCOPE, KEY, V2).targets());
        assertThat(rows.get(0).gateRead()).isTrue();
        assertThat(rows.get(1).gate()).extracting(PromptGovernanceReleaseGateService.ReleaseGateTarget::ready)
                .containsExactly(false, true, true);
        // A bundle the gate cannot read shows no answer at all, not a ready or a blocked one.
        assertThat(rows.get(2).gate()).isEmpty();
        assertThat(rows.get(2).gateRead()).isFalse();
        // A retired bundle has no next state; the gate is not asked.
        assertThat(rows.get(3).gate()).isEmpty();
        assertThat(rows.get(3).gateRead()).isTrue();
        verify(gate, never()).assessPromptRelease(SCOPE, KEY, "2025.12.01-v9");
    }

    @Test
    void aBundleDetailCarriesItsManifestGateAndRollbacks() {
        PromptBundleRollbackService.Execution execution = new PromptBundleRollbackService.Execution("RBX-1", V2, V1,
                "operator-a", "leak", true, PromptBundleRollbackService.AWAITING_APPROVAL, AT, null, null);
        when(rollbacks.executions(SCOPE, KEY, V2)).thenReturn(List.of(execution));

        PromptReleaseConsole.BundleDetail detail = console.detail(SCOPE, KEY, V2).orElseThrow();

        assertThat(detail.bundle().state()).isEqualTo("SHADOW");
        assertThat(detail.manifest().bundleHash()).isEqualTo(v2.bundleHash());
        assertThat(detail.manifest().parentVersion()).isEqualTo(V1);
        assertThat(detail.manifest().rollbackTargets()).containsExactly(V1);
        assertThat(detail.gate()).isEqualTo(gate.assessPromptRelease(SCOPE, KEY, V2));
        assertThat(detail.rollbacks()).containsExactly(execution);
    }

    @Test
    void aBundleTheRegistryDoesNotHoldHasNoDetail() {
        assertThat(console.detail(SCOPE, KEY, "2026.02.02-v3")).isEqualTo(Optional.empty());
        verify(gate, never()).assessPromptRelease(eq(SCOPE), eq(KEY), eq("2026.02.02-v3"));
    }

    @Test
    void twoBundlesAreComparedElementByElementAndByTheirSealedDecisions() {
        List<JdbcPromptInspectionQueries.BundleOutcome> outcomes = List.of(
                new JdbcPromptInspectionQueries.BundleOutcome(V1, JdbcPromptInspectionQueries.DECISION_STAGE, "ALLOW",
                        3, 1, 2, 0),
                new JdbcPromptInspectionQueries.BundleOutcome(V2, JdbcPromptInspectionQueries.SHADOW_STAGE, "BLOCK",
                        1, 0, 0, 1));
        when(sealed.bundleOutcomes(FROM, TO, List.of(V1, V2))).thenReturn(outcomes);

        PromptReleaseConsole.Comparison comparison = console.compare(SCOPE, KEY, V1, V2, FROM, TO);

        assertThat(comparison.elements()).hasSize(11);
        assertThat(comparison.elements()).filteredOn(PromptReleaseConsole.ElementChange::changed)
                .extracting(PromptReleaseConsole.ElementChange::id).containsExactly("B1", "B10");
        PromptReleaseConsole.ElementChange first = comparison.elements().get(0);
        assertThat(first.base().hash()).isEqualTo(v1.elements().get(0).hash());
        assertThat(first.candidate().hash()).isEqualTo(v2.elements().get(0).hash());
        assertThat(comparison.base().manifest().vocabularyVersion()).isEqualTo("vocab-1");
        assertThat(comparison.candidate().manifest().vocabularyVersion()).isEqualTo("vocab-2");
        assertThat(comparison.base().evidence()).isEqualTo(gate.assessPromptRelease(SCOPE, KEY, V1).evidence());
        assertThat(comparison.outcomes()).isEqualTo(outcomes);
        assertThat(comparison.cases().shadows()).isZero();
        assertThat(comparison.versions()).containsExactly(V2, V1);
    }

    /** N-SHD-1: each shadow run is paired with the decision of its request; those that answered otherwise first. */
    @Test
    void eachShadowRunIsPairedWithTheDecisionOfItsRequest() {
        Instant at = Instant.parse("2026-10-15T01:00:00Z");
        when(sealed.shadowPairs(FROM, TO, List.of(V1, V2))).thenReturn(List.of(
                new JdbcPromptInspectionQueries.ShadowPair("req-1", at, "s-1", V2, "ALLOW", "d-1", V1, "ALLOW"),
                new JdbcPromptInspectionQueries.ShadowPair("req-2", at.minusSeconds(60), "s-2", V2, "ALLOW", "d-2", V1,
                        "BLOCK"),
                new JdbcPromptInspectionQueries.ShadowPair("req-3", at.minusSeconds(120), "s-3", V2, "BLOCK", "d-3",
                        V1, "BLOCK"),
                new JdbcPromptInspectionQueries.ShadowPair("req-4", at.minusSeconds(180), "s-4", V2, "ALLOW", null,
                        null, null)));

        PromptReleaseConsole.ShadowCases cases = console.compare(SCOPE, KEY, V1, V2, FROM, TO).cases();

        assertThat(cases.shadows()).isEqualTo(4);
        assertThat(cases.paired()).isEqualTo(3);
        assertThat(cases.changed()).isEqualTo(1);
        assertThat(cases.changes()).containsExactlyInAnyOrder(
                new PromptReleaseConsole.ActionChange("ALLOW", "ALLOW", 1),
                new PromptReleaseConsole.ActionChange("BLOCK", "ALLOW", 1),
                new PromptReleaseConsole.ActionChange("BLOCK", "BLOCK", 1));
        assertThat(cases.pairs()).extracting(JdbcPromptInspectionQueries.ShadowPair::requestId)
                .containsExactly("req-2", "req-1", "req-3");
    }

    @Test
    void aBundleOutsideTheBuildHasNoElementsToCompare() {
        PromptReleaseConsole.Comparison comparison = console.compare(SCOPE, KEY, "2026.01.01-v0", V2, FROM, TO);

        assertThat(comparison.elements()).isEmpty();
        assertThat(comparison.base().manifest()).isNull();
        assertThat(comparison.base().evidence()).isNull();
        assertThat(comparison.candidate().manifest()).isNotNull();
    }

    private static JdbcPromptReleaseQueryService.PromptReleaseRow row(String version, String hash, String status,
                                                                      Integer canaryPercent, String tenants,
                                                                      String families) {
        return new JdbcPromptReleaseQueryService.PromptReleaseRow(SCOPE, KEY, "TestTemplate", version,
                "CORTEX_PROMPT_CONTRACT_V3", status, null, hash, null, null, null, null, null, null, null, null, null,
                null, AT, canaryPercent, tenants, families);
    }

    private static PromptGovernanceReleaseGateService.ReleaseGateTarget target(String state, boolean ready,
                                                                               String... blockers) {
        return new PromptGovernanceReleaseGateService.ReleaseGateTarget(state, ready, ready ? "READY" : "BLOCKED",
                List.of(blockers));
    }

    private static PromptGovernanceReleaseGateService.ReleaseGateAssessment assessment(
            String version, String state, PromptGovernanceReleaseGateService.ReleaseGateTarget... targets) {
        PromptGovernanceReleaseGateService.ReleaseGateEvidence evidence =
                new PromptGovernanceReleaseGateService.ReleaseGateEvidence(true, "EVAL-" + version, "PASSED",
                        "SATISFIED", "READY_FOR_PRODUCTION", "PASSED", "PASSED", "PASSED", "PASSED", "COVERED", 3, 3,
                        "hash-" + version, "protocol-" + version, true, AT, "APPROVED", "operator-a", V1, "READY",
                        List.of("PROFILE"), true, List.of("BUDGET"), true, true, true);
        return new PromptGovernanceReleaseGateService.ReleaseGateAssessment(SCOPE, KEY, version, state,
                List.of(targets), evidence);
    }

    private static PromptBundleManifest manifest(String version, String systemText, String vocabulary, String parent) {
        List<PromptBundleElement> elements = new ArrayList<>();
        for (String id : PromptBundleHashes.ELEMENT_IDS) {
            if ("B1".equals(id)) {
                elements.add(PromptBundleHashes.present(id, systemText, "rendered system text"));
            } else if ("B10".equals(id)) {
                elements.add(PromptBundleHashes.present(id, vocabulary, "vocabulary " + vocabulary));
            } else if ("B9".equals(id)) {
                elements.add(PromptBundleHashes.marker(id, PromptBundleElementState.ABSENT, "no verifier contracts"));
            } else {
                elements.add(PromptBundleHashes.present(id, "content of " + id, "element " + id));
            }
        }
        return new PromptBundleManifest(KEY, version, PromptBundleHashes.bundleHash(elements), elements, null, parent,
                "summary of " + version, List.of("W7-14"), "test", "2026-10-16", vocabulary, List.of(vocabulary),
                parent == null ? List.of() : List.of(parent), List.of("PROFILE"));
    }
}
