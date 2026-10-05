package io.contexa.showcase.business.context;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class NetworksTest {

    @Test
    void addressesInsideTheBlockMatchAndOthersDoNot() {
        assertThat(Networks.contains("10.40.21.0/24", "10.40.21.77")).isTrue();
        assertThat(Networks.contains("10.40.21.0/24", "10.40.22.77")).isFalse();
        assertThat(Networks.contains("198.51.100.0/24", "198.51.100.9")).isTrue();
        assertThat(Networks.contains("10.40.0.0/16", "10.40.200.1")).isTrue();
        assertThat(Networks.contains("0.0.0.0/0", "203.0.113.9")).isTrue();
    }

    @Test
    void malformedInputNeverMatches() {
        assertThat(Networks.contains("10.40.21.0", "10.40.21.1")).isFalse();
        assertThat(Networks.contains("10.40.21.0/33", "10.40.21.1")).isFalse();
        assertThat(Networks.contains("10.40.21.0/24", "::1")).isFalse();
        assertThat(Networks.contains("10.40.21.0/24", "10.40.21.300")).isFalse();
        assertThat(Networks.contains(null, "10.40.21.1")).isFalse();
        assertThat(Networks.contains("10.40.21.0/24", null)).isFalse();
    }
}
