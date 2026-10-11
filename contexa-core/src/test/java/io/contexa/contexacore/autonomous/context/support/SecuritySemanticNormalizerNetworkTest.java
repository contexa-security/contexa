package io.contexa.contexacore.autonomous.context.support;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The current request carries the canonical band (a.b.c.0/24) and learned baselines store the three-octet prefix
 * (a.b.c) when the host supplies no ipBand. Both name the same /24, so a request from the usual office network must
 * not be reported as outside the observed networks.
 */
class SecuritySemanticNormalizerNetworkTest {

    @Test
    void bothFormsOfTheSameBandAreTheSameNetwork() {
        assertThat(SecuritySemanticNormalizer.sameNetwork("10.40.21.0/24", "10.40.21")).isTrue();
        assertThat(SecuritySemanticNormalizer.sameNetwork("10.40.21", "10.40.21.0/24")).isTrue();
        assertThat(SecuritySemanticNormalizer.sameNetwork("10.40.21.0/24", "10.40.21.0/24")).isTrue();
        assertThat(SecuritySemanticNormalizer.sameNetwork("10.40.21", "10.40.21")).isTrue();
    }

    @Test
    void otherNetworksAndOtherFormsStayDifferent() {
        assertThat(SecuritySemanticNormalizer.sameNetwork("10.40.21.0/24", "10.40.22")).isFalse();
        assertThat(SecuritySemanticNormalizer.sameNetwork("10.40.21.0/16", "10.40.21")).isFalse();
        assertThat(SecuritySemanticNormalizer.sameNetwork("10.40.21.7", "10.40.21")).isFalse();
        assertThat(SecuritySemanticNormalizer.sameNetwork("2001:db8::/48", "2001:DB8::/48")).isTrue();
        assertThat(SecuritySemanticNormalizer.sameNetwork(null, "10.40.21")).isFalse();
        assertThat(SecuritySemanticNormalizer.sameNetwork("999.1.1.0/24", "999.1.1")).isFalse();
    }

    @Test
    void everyNetworkReadsInOneForm() {
        // W2-4, B-10: the address, a learned prefix and the band are one form; a host band keeps its own length.
        assertThat(SecuritySemanticNormalizer.normalizeNetwork("10.40.12.10", null)).isEqualTo("10.40.12.0/24");
        assertThat(SecuritySemanticNormalizer.normalizeNetwork(null, "10.40.12")).isEqualTo("10.40.12.0/24");
        assertThat(SecuritySemanticNormalizer.normalizeNetwork("10.40.12.10", "10.40.0.0/16")).isEqualTo("10.40.0.0/16");
        assertThat(SecuritySemanticNormalizer.normalizeNetwork("2001:DB8::1", null)).isEqualTo("2001:db8:0:0::/64");
        assertThat(SecuritySemanticNormalizer.normalizeNetwork("2001:db8:0:1:2:3:4:5", null))
                .isEqualTo("2001:db8:0:1::/64");
        // An address that is neither IPv4 nor IPv6 gives no network; a host band in an unknown form is kept.
        assertThat(SecuritySemanticNormalizer.normalizeNetwork("unknown", null)).isNull();
        assertThat(SecuritySemanticNormalizer.normalizeNetwork(null, " OFFICE-NET ")).isEqualTo("OFFICE-NET");
        assertThat(SecuritySemanticNormalizer.normalizeNetwork(null, null)).isNull();
    }
}
