package io.contexa.contexaiam.admin.promptquality.governance;

import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElement;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleManifest;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceRegistryService;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * W7-14 (version management design 11, PV-8, PV-14): what the version screens show, composed from the OSS records
 * only. The bundle list gives each bundle's name, hash, canonical state and scope with the gate's answer for its next
 * states; a bundle's detail adds its manifest, the gate's evidence and its rollback executions; the comparison of two
 * bundles gives the element differences of their manifests and the behaviour difference of their sealed decisions and
 * evaluations. 'Ready' is only ever the release gate's answer; a state is named only by the canonical vocabulary.
 */
public class PromptReleaseConsole {

    private static final Logger log = LoggerFactory.getLogger(PromptReleaseConsole.class);

    private final JdbcPromptReleaseQueryService releases;
    private final PromptGovernanceReleaseGateService gate;
    private final PromptBundleRollbackService rollbacks;
    private final PromptBundleCatalog catalog;
    private final JdbcPromptInspectionQueries sealed;

    public PromptReleaseConsole(JdbcPromptReleaseQueryService releases, PromptGovernanceReleaseGateService gate,
                                PromptBundleRollbackService rollbacks, PromptBundleCatalog catalog,
                                JdbcPromptInspectionQueries sealed) {
        this.releases = Objects.requireNonNull(releases, "releases");
        this.gate = Objects.requireNonNull(gate, "gate");
        this.rollbacks = Objects.requireNonNull(rollbacks, "rollbacks");
        this.catalog = Objects.requireNonNull(catalog, "catalog");
        this.sealed = Objects.requireNonNull(sealed, "sealed");
    }

    /** The canary part of a bundle's scope: the share of subjects and the tenants and resource families it covers. */
    public record Canary(Integer percent, String tenants, String resourceFamilies) {
    }

    /**
     * One bundle of the list: its name, hash, canonical state (null when the stored status belongs to no vocabulary,
     * then the stored value is given), scope, whether this build holds it with the same hash, and the gate's answer.
     */
    public record BundleRow(String registryScope, String promptKey, String bundleVersion, String bundleHash,
                            String state, String unknownStatus, Canary canary, boolean inBuild,
                            boolean hashMatchesBuild, List<PromptGovernanceReleaseGateService.ReleaseGateTarget> gate,
                            boolean gateRead, LocalDateTime updatedAt) {
    }

    /** What the manifest of a bundle of this build declares. */
    public record Manifest(String bundleHash, String parentVersion, String changeSummary, List<String> problemIds,
                           String author, String frozenOn, String vocabularyVersion,
                           List<String> compatibleVocabularyVersions, List<String> rollbackTargets,
                           List<String> declaredModelProfiles) {
    }

    /** One bundle's detail: the list row, its manifest (null outside this build), the gate and its rollbacks. */
    public record BundleDetail(BundleRow bundle, Manifest manifest,
                               PromptGovernanceReleaseGateService.ReleaseGateAssessment gate,
                               List<PromptBundleRollbackService.Execution> rollbacks) {
    }

    /** One element (B1 to B11) of one side of a comparison. */
    public record ElementSide(String state, String hash, String detail) {
    }

    /** One element of two bundles and whether its hash differs. */
    public record ElementChange(String id, ElementSide base, ElementSide candidate, boolean changed) {
    }

    /** One side of a comparison: the bundle, its manifest in this build and the gate evidence its registry row has. */
    public record Side(String bundleVersion, Manifest manifest,
                       PromptGovernanceReleaseGateService.ReleaseGateEvidence evidence) {
    }

    /** N-SHD-1: on how many requests a decision action and a shadow action came together. */
    public record ActionChange(String decisionAction, String shadowAction, long requests) {
    }

    /**
     * N-SHD-1: the shadow runs of the period paired with the decisions of their requests: how many there were, how
     * many found their decision's seal, how many answered otherwise, the requests per decision and shadow action, and
     * the pairs, those that answered otherwise first.
     */
    public record ShadowCases(long shadows, long paired, long changed, List<ActionChange> changes,
                              List<JdbcPromptInspectionQueries.ShadowPair> pairs) {
    }

    /**
     * Two bundles compared: the elements, then the behaviour: the sealed decisions of the period per bundle, stage and
     * action, and each shadow run paired with the decision of the request it was copied from (N-SHD-1).
     */
    public record Comparison(String registryScope, String promptKey, Side base, Side candidate,
                             List<ElementChange> elements, Instant from, Instant to,
                             List<JdbcPromptInspectionQueries.BundleOutcome> outcomes, ShadowCases cases,
                             List<String> versions) {
    }

    public List<BundleRow> bundles(String registryScope) {
        return releases.releases(registryScope).releases().stream().map(this::row).toList();
    }

    public Optional<BundleDetail> detail(String registryScope, String promptKey, String bundleVersion) {
        String scope = scope(registryScope);
        Optional<JdbcPromptReleaseQueryService.PromptReleaseRow> release = release(scope, promptKey, bundleVersion);
        if (release.isEmpty()) {
            return Optional.empty();
        }
        PromptGovernanceReleaseGateService.ReleaseGateAssessment assessment = assess(scope, promptKey, bundleVersion);
        return Optional.of(new BundleDetail(row(release.get(), assessment), manifest(promptKey, bundleVersion),
                assessment, rollbacks.executions(scope, promptKey, bundleVersion)));
    }

    public Comparison compare(String registryScope, String promptKey, String base, String candidate, Instant from,
                              Instant to) {
        String scope = scope(registryScope);
        Optional<PromptBundleManifest> baseManifest = catalog.find(promptKey, base);
        Optional<PromptBundleManifest> candidateManifest = catalog.find(promptKey, candidate);
        List<ElementChange> elements = new ArrayList<>();
        if (baseManifest.isPresent() && candidateManifest.isPresent()) {
            Map<String, PromptBundleElement> before = byId(baseManifest.get());
            Map<String, PromptBundleElement> after = byId(candidateManifest.get());
            for (String id : PromptBundleHashes.ELEMENT_IDS) {
                PromptBundleElement left = before.get(id);
                PromptBundleElement right = after.get(id);
                elements.add(new ElementChange(id, side(left), side(right), !left.hash().equals(right.hash())));
            }
        }
        return new Comparison(scope, promptKey, side(scope, promptKey, base), side(scope, promptKey, candidate),
                List.copyOf(elements), from, to, sealed.bundleOutcomes(from, to, List.of(base, candidate)),
                cases(sealed.shadowPairs(from, to, List.of(base, candidate))), versions(promptKey));
    }

    /** The bundles of a prompt this build holds, newest first by the day they were frozen. */
    public List<String> versions(String promptKey) {
        return catalog.manifests().stream()
                .filter(manifest -> manifest.promptKey().equals(promptKey))
                .sorted(Comparator.comparing((PromptBundleManifest manifest) -> String.valueOf(manifest.frozenOn()))
                        .thenComparing(manifest -> manifest.bundleVersion().length())
                        .thenComparing(PromptBundleManifest::bundleVersion)
                        .reversed())
                .map(PromptBundleManifest::bundleVersion)
                .toList();
    }

    /** N-SHD-1: how many pairs the comparison lists. */
    static final int PAIR_LIMIT = 50;

    /** N-SHD-1: the shadow runs of the period with the decisions of their requests, counted and listed. */
    static ShadowCases cases(List<JdbcPromptInspectionQueries.ShadowPair> shadows) {
        List<JdbcPromptInspectionQueries.ShadowPair> paired = shadows.stream()
                .filter(pair -> pair.decisionPackageId() != null)
                .toList();
        Map<ActionPair, Long> byActions = paired.stream().collect(Collectors.groupingBy(
                pair -> new ActionPair(pair.decisionAction(), pair.shadowAction()), LinkedHashMap::new,
                Collectors.counting()));
        List<ActionChange> changes = byActions.entrySet().stream()
                .map(entry -> new ActionChange(entry.getKey().decision(), entry.getKey().shadow(), entry.getValue()))
                .sorted(Comparator.comparing(ActionChange::requests).reversed())
                .toList();
        long answeredOtherwise = paired.stream().filter(PromptReleaseConsole::answeredOtherwise).count();
        List<JdbcPromptInspectionQueries.ShadowPair> listed = paired.stream()
                .sorted(Comparator.comparing((JdbcPromptInspectionQueries.ShadowPair pair) -> !answeredOtherwise(pair)))
                .limit(PAIR_LIMIT)
                .toList();
        return new ShadowCases(shadows.size(), paired.size(), answeredOtherwise, changes, listed);
    }

    private static boolean answeredOtherwise(JdbcPromptInspectionQueries.ShadowPair pair) {
        return !Objects.equals(pair.decisionAction(), pair.shadowAction());
    }

    /** The decision action and the shadow action of one request. */
    private record ActionPair(String decision, String shadow) {
    }

    private BundleRow row(JdbcPromptReleaseQueryService.PromptReleaseRow release) {
        return row(release, PromptBundleState.is(release.releaseStatus(), PromptBundleState.RETIRED) ? null
                : assess(release.registryScope(), release.promptKey(), release.promptVersion()));
    }

    private BundleRow row(JdbcPromptReleaseQueryService.PromptReleaseRow release,
                          PromptGovernanceReleaseGateService.ReleaseGateAssessment assessment) {
        Optional<PromptBundleManifest> manifest = catalog.find(release.promptKey(), release.promptVersion());
        String state = PromptBundleState.fromStoredValue(release.releaseStatus()).map(Enum::name).orElse(null);
        boolean retired = PromptBundleState.RETIRED.name().equals(state);
        return new BundleRow(release.registryScope(), release.promptKey(), release.promptVersion(),
                release.artifactHash(), state, state == null ? release.releaseStatus() : null,
                new Canary(release.canaryPercent(), release.canaryTenants(), release.canaryResourceFamilies()),
                manifest.isPresent(),
                manifest.map(found -> found.bundleHash().equals(release.artifactHash())).orElse(false),
                assessment != null ? assessment.targets() : List.of(), retired || assessment != null,
                release.updatedAt());
    }

    /** The gate's answer, or none when the gate cannot read the bundle (the screen then shows no 'ready'). */
    private PromptGovernanceReleaseGateService.ReleaseGateAssessment assess(String scope, String promptKey,
                                                                           String bundleVersion) {
        try {
            return gate.assessPromptRelease(scope, promptKey, bundleVersion);
        } catch (RuntimeException e) {
            log.error("Release gate could not assess {}@{} in {}", promptKey, bundleVersion, scope, e);
            return null;
        }
    }

    private Optional<JdbcPromptReleaseQueryService.PromptReleaseRow> release(String scope, String promptKey,
                                                                            String bundleVersion) {
        return releases.releases(scope).releases().stream()
                .filter(row -> Objects.equals(row.promptKey(), promptKey)
                        && Objects.equals(row.promptVersion(), bundleVersion))
                .findFirst();
    }

    private Side side(String scope, String promptKey, String bundleVersion) {
        PromptGovernanceReleaseGateService.ReleaseGateAssessment assessment =
                release(scope, promptKey, bundleVersion).isPresent() ? assess(scope, promptKey, bundleVersion) : null;
        return new Side(bundleVersion, manifest(promptKey, bundleVersion),
                assessment != null ? assessment.evidence() : null);
    }

    private Manifest manifest(String promptKey, String bundleVersion) {
        return catalog.find(promptKey, bundleVersion)
                .map(found -> new Manifest(found.bundleHash(), found.parentVersion(), found.changeSummary(),
                        found.problemIds(), found.author(), found.frozenOn(), found.vocabularyVersion(),
                        found.compatibleVocabularyVersions(), found.rollbackTargets(), found.declaredModelProfiles()))
                .orElse(null);
    }

    private static Map<String, PromptBundleElement> byId(PromptBundleManifest manifest) {
        return manifest.elements().stream().collect(Collectors.toMap(PromptBundleElement::id, Function.identity()));
    }

    private static ElementSide side(PromptBundleElement element) {
        return new ElementSide(element.state().name(), element.hash(), element.detail());
    }

    private static String scope(String registryScope) {
        return StringUtils.hasText(registryScope) ? registryScope.trim()
                : PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE;
    }
}
