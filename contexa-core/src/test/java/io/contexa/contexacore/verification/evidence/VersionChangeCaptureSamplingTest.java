package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** R4-S6: a stable share of the requests is sealed, and every decision of the window after a start or a bundle change. */
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

    private static SealedEvidencePackage sealed(String correlationId, String bundleVersion) {
        return SealedEvidencePackage.builder()
                .packageId("package-" + correlationId)
                .correlationId(correlationId)
                .promptExecutionMetadataJson("{\"governanceDescriptor\":{\"promptBundleVersion\":\"" + bundleVersion
                        + "\"}}")
                .build();
    }
}
