package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * R4-S6: a stable share of the requests is sealed, and every decision of the window after a start or a change of the
 * prompt version (K43: the version name and content hash, every version sharing one bundle).
 */
class VersionChangeCaptureSamplingTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void afterTheStartWindowOnlyAStableShareOfTheRequestsIsSealed() {
        VersionChangeCaptureSampling sampling = new VersionChangeCaptureSampling(1, 3, objectMapper);

        assertThat(IntStream.range(0, 3).mapToObj(index -> sampling.shouldSeal(sealed("start-" + index, "v20.12"))))
                .containsOnly(true);
        long sealedCount = IntStream.range(0, 4000)
                .filter(index -> sampling.shouldSeal(sealed("request-" + index, "v20.12"))).count();

        assertThat(sealedCount).isBetween(10L, 120L);
        assertThat(IntStream.range(0, 4000)
                .filter(index -> sampling.shouldSeal(sealed("request-" + index, "v20.12"))).count())
                .isEqualTo(sealedCount);
    }

    @Test
    void aBundleChangeOpensTheWindowAgain() {
        VersionChangeCaptureSampling sampling = new VersionChangeCaptureSampling(1, 3, objectMapper);
        IntStream.range(0, 3).forEach(index -> sampling.shouldSeal(sealed("start-" + index, "v20.11")));
        String outside = IntStream.range(0, 400).mapToObj(index -> "request-" + index)
                .filter(id -> !sampling.shouldSeal(sealed(id, "v20.11"))).findFirst().orElseThrow();

        assertThat(IntStream.range(0, 3).mapToObj(index -> sampling.shouldSeal(sealed(outside, "v20.12"))))
                .containsOnly(true);
        assertThat(sampling.shouldSeal(sealed(outside, "v20.12"))).isFalse();
    }

    /** K43: every version of v1.0 names the same bundle, so the window follows the version the decision ran. */
    @Test
    void aVersionChangeUnderTheSameBundleOpensTheWindowAgain() {
        VersionChangeCaptureSampling sampling = new VersionChangeCaptureSampling(1, 3, objectMapper);
        IntStream.range(0, 3).forEach(index -> sampling.shouldSeal(version("start-" + index, "v1.0", "aaa")));
        String outside = IntStream.range(0, 400).mapToObj(index -> "request-" + index)
                .filter(id -> !sampling.shouldSeal(version(id, "v1.0", "aaa"))).findFirst().orElseThrow();

        assertThat(IntStream.range(0, 3).mapToObj(index -> sampling.shouldSeal(version(outside, "v2.0", "bbb"))))
                .as("the label moved to v2.0").containsOnly(true);
        assertThat(sampling.shouldSeal(version(outside, "v2.0", "bbb"))).isFalse();
        // A version of the same name with another content (another scope's v2.0) is another version.
        assertThat(sampling.shouldSeal(version(outside, "v2.0", "ccc"))).isTrue();
        // A package that records only its bundle, as an earlier build's does, is keyed by the bundle.
        assertThat(sampling.shouldSeal(sealed(outside, "2026.11.16-v1.0"))).isTrue();
    }

    /** K43: a rollback is a change of the version decisions run, so it opens the window again. */
    @Test
    void aRollbackOpensTheWindowAgain() {
        VersionChangeCaptureSampling sampling = new VersionChangeCaptureSampling(1, 2, objectMapper);
        String outside = outside();

        assertThat(IntStream.range(0, 3).mapToObj(index -> sampling.shouldSeal(version(outside, "v1.0", "aaa"))))
                .containsExactly(true, true, false);
        assertThat(IntStream.range(0, 3).mapToObj(index -> sampling.shouldSeal(version(outside, "v2.0", "bbb"))))
                .containsExactly(true, true, false);
        assertThat(IntStream.range(0, 3).mapToObj(index -> sampling.shouldSeal(version(outside, "v1.0", "aaa"))))
                .as("rolled back to v1.0").containsExactly(true, true, false);
    }

    /**
     * K43: a canary's share runs another version beside the version in use, the two taking turns: the canary's version
     * has a window of its own and the turns do not open the window of the version in use again.
     */
    @Test
    void aCanarysVersionHasItsOwnWindowAndItsTurnsOpenNoOther() {
        VersionChangeCaptureSampling sampling = new VersionChangeCaptureSampling(1, 3, objectMapper);
        String outside = outside();

        assertThat(IntStream.range(0, 6).mapToObj(index -> sampling.shouldSeal(index % 2 == 0
                ? version(outside, "v1.0", "aaa", "REGISTRY") : version(outside, "v2.0", "bbb", "CANARY"))))
                .containsOnly(true);
        assertThat(sampling.shouldSeal(version(outside, "v1.0", "aaa", "REGISTRY"))).isFalse();
        assertThat(sampling.shouldSeal(version(outside, "v2.0", "bbb", "CANARY"))).isFalse();
        assertThat(sampling.shouldSeal(version(outside, "v1.0", "aaa", "REGISTRY"))).as("after a canary turn").isFalse();
        // The label moved to the canary's version: decisions run it now, so its window opens again.
        assertThat(sampling.shouldSeal(version(outside, "v2.0", "bbb", "REGISTRY"))).isTrue();
    }

    /** A request id the 1% share leaves out. */
    private static String outside() {
        return IntStream.range(0, 400).mapToObj(index -> "request-" + index)
                .filter(id -> Math.floorMod(id.hashCode(), 100) >= 1).findFirst().orElseThrow();
    }

    @Test
    void aHundredPercentSealsEveryRequest() {
        VersionChangeCaptureSampling sampling = new VersionChangeCaptureSampling(100, 0, objectMapper);

        assertThat(IntStream.range(0, 500).filter(index -> sampling.shouldSeal(sealed("request-" + index, "v20.12"))))
                .hasSize(500);
    }

    @Test
    void theShareAndTheWindowMustBeInRange() {
        assertThatThrownBy(() -> new VersionChangeCaptureSampling(0, 1000, objectMapper))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new VersionChangeCaptureSampling(101, 1000, objectMapper))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new VersionChangeCaptureSampling(1, -1, objectMapper))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** A package as the assembler writes it: the bundle every version shares, and the version with its content hash. */
    private static SealedEvidencePackage version(String correlationId, String versionName, String contentHash) {
        return version(correlationId, versionName, contentHash, null);
    }

    private static SealedEvidencePackage version(String correlationId, String versionName, String contentHash,
                                                 String source) {
        return SealedEvidencePackage.builder()
                .packageId("package-" + correlationId)
                .correlationId(correlationId)
                .promptExecutionMetadataJson("{\"governanceDescriptor\":{\"promptBundleVersion\":\"2026.11.16-v1.0\"},"
                        + "\"promptVersionName\":\"" + versionName + "\",\"promptContentHash\":\"" + contentHash + "\""
                        + (source != null ? ",\"promptBundleSelectionSource\":\"" + source + "\"" : "") + "}")
                .build();
    }

    private static SealedEvidencePackage sealed(String correlationId, String bundleVersion) {
        return SealedEvidencePackage.builder()
                .packageId("package-" + correlationId)
                .correlationId(correlationId)
                .promptExecutionMetadataJson("{\"governanceDescriptor\":{\"promptBundleVersion\":\"" + bundleVersion
                        + "\"}}")
                .build();
    }
}
