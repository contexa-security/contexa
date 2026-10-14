package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionTally;
import io.contexa.contexacore.verification.inspection.PromptInspectionUnavailableException;
import org.springframework.dao.DataAccessException;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Whether the governance descriptor the render sealed names a release of the prompt release registry, and the sealed
 * contract version, artifact hash and approval are that release's. The sealed version is compared with its own
 * release: the registry keeps no history of which release was executing when, so a later release never turns an
 * earlier prompt into a mismatch. It reads the registry, so the host adds it to the core checks; it runs on every user
 * prompt layout.
 */
public final class BundleTraceCheck implements PromptInspectionCheck {

    public static final String CODE = "BUNDLE_TRACE";

    private static final String SOURCE = "promptGovernanceRegistry";
    private static final String DESCRIPTOR = "executionMetadata." + PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR;
    private static final String GOVERNANCE_DESCRIPTOR = PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR;
    private static final List<String> FIELDS = List.of("registryScope", "promptKey", "templateKey", "promptVersion",
            "contractVersion", "promptArtifactHashSha256");

    private final PromptReleaseLookup releases;

    /** @param releases the registry, or null when no release registry is read */
    public BundleTraceCheck(PromptReleaseLookup releases) {
        this.releases = releases;
    }

    /** Whether the check reads a release registry; without one every trace is unverifiable. */
    public boolean readsRegistry() {
        return releases != null;
    }

    @Override
    public String code() {
        return CODE;
    }

    @Override
    public boolean dictionaryPromptOnly() {
        return false;
    }

    @Override
    public void inspect(PromptInspectionTally tally) {
        if (releases == null) {
            tally.unverifiable(tally.unverifiableFinding().sourceRef(SOURCE)
                    .reason("no prompt release registry is read for the trace").build());
            return;
        }
        Map<String, String> descriptor = descriptor(tally.subject().executionMetadata());
        if (descriptor == null) {
            tally.mismatch(tally.mismatchFinding().entry(GOVERNANCE_DESCRIPTOR).expected("the sealed descriptor")
                    .actual("missing").sourceRef(DESCRIPTOR)
                    .reason("the sealed package carries no governance descriptor").build());
            return;
        }
        boolean complete = true;
        for (String field : FIELDS) {
            if (StringUtils.hasText(descriptor.get(field))) {
                tally.matched();
                continue;
            }
            complete = false;
            tally.mismatch(tally.mismatchFinding().entry(field).expected("a value").actual("missing")
                    .sourceRef(DESCRIPTOR + "." + field).reason("the governance descriptor does not name its " + field)
                    .build());
        }
        if (!complete) {
            return;
        }
        String version = descriptor.get("promptVersion");
        Optional<PromptReleaseLookup.PromptRelease> found;
        try {
            found = releases.find(descriptor.get("registryScope"), descriptor.get("promptKey"),
                    descriptor.get("templateKey"), version);
        }
        catch (DataAccessException exception) {
            // R1b-5: the registry cannot be read now; the package is inspected again in a later round.
            throw new PromptInspectionUnavailableException("the prompt release registry cannot be read now", exception);
        }
        if (found.isEmpty()) {
            tally.mismatch(tally.mismatchFinding().entry("promptVersion").expected("a release of the registry")
                    .actual(version).sourceRef(SOURCE)
                    .reason("the sealed prompt version is not a release of the registry").build());
            return;
        }
        tally.matched();
        PromptReleaseLookup.PromptRelease release = found.get();
        compare(tally, "contractVersion", release.contractVersion(), descriptor.get("contractVersion"),
                "the sealed contract version is not the release's");
        compare(tally, "promptArtifactHashSha256", release.artifactHash(), descriptor.get("promptArtifactHashSha256"),
                "the sealed prompt artifact hash is not the release's");
        if (StringUtils.hasText(release.approvalReference())) {
            tally.matched();
        }
        else {
            tally.mismatch(tally.mismatchFinding().entry("releaseApprovalReference").expected("an approval reference")
                    .actual("missing").sourceRef(SOURCE + ".releaseApprovalReference")
                    .reason("the release the prompt was sealed under has no approval").build());
        }
    }

    private static void compare(PromptInspectionTally tally, String field, String released, String sealed,
                                String reason) {
        if (released != null && released.trim().equalsIgnoreCase(sealed.trim())) {
            tally.matched();
            return;
        }
        tally.mismatch(tally.mismatchFinding().entry(field).expected(released).actual(sealed)
                .sourceRef(SOURCE + "." + field).reason(reason).build());
    }

    private static Map<String, String> descriptor(Map<String, Object> metadata) {
        if (!(metadata.get(GOVERNANCE_DESCRIPTOR) instanceof Map<?, ?> map)) {
            return null;
        }
        Map<String, String> descriptor = new LinkedHashMap<>();
        map.forEach((key, value) -> descriptor.put(String.valueOf(key), value == null ? null : value.toString().trim()));
        return descriptor;
    }
}
