package io.contexa.contexacore.autonomous.repository;

import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

abstract class AbstractZeroTrustActionRepositoryFailCountContractTest {

    protected ZeroTrustActionRepository repository;

    protected abstract ZeroTrustActionRepository createRepository();

    protected abstract ZeroTrustActionRepository createRepositoryWithFailCountTtl(Duration failCountTtl);

    @BeforeEach
    void setUpRepository() {
        repository = createRepository();
    }

    @Test
    @DisplayName("getBlockMfaFailCount returns zero for unknown user")
    void failCount_unknown_returnsZero() {
        assertThat(repository.getBlockMfaFailCount("ghost")).isZero();
    }

    @Test
    @DisplayName("incrementBlockMfaFailCount accumulates the count")
    void failCount_incrementsAccumulate() {
        repository.incrementBlockMfaFailCount("u-inc");
        repository.incrementBlockMfaFailCount("u-inc");
        repository.incrementBlockMfaFailCount("u-inc");

        assertThat(repository.getBlockMfaFailCount("u-inc")).isEqualTo(3L);
    }

    @Test
    @DisplayName("Fail count is zero after the configured TTL expires")
    void failCount_expiresAfterTtl() {
        ZeroTrustActionRepository ttlRepository = createRepositoryWithFailCountTtl(Duration.ofMillis(500));
        ttlRepository.incrementBlockMfaFailCount("u-ttl");
        ttlRepository.incrementBlockMfaFailCount("u-ttl");

        assertThat(ttlRepository.getBlockMfaFailCount("u-ttl"))
                .as("count must be visible right after increment")
                .isEqualTo(2L);

        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .untilAsserted(() -> assertThat(ttlRepository.getBlockMfaFailCount("u-ttl"))
                        .as("fail count must return 0 after the TTL expires in both modes")
                        .isZero());
    }
}
