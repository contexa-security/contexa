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
}
