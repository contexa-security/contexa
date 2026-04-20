package io.contexa.contexacore.autonomous.repository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

abstract class AbstractProtectableRapidReentryRepositoryContractTest {

    protected ProtectableRapidReentryRepository repository;

    protected abstract ProtectableRapidReentryRepository createRepository();

    @BeforeEach
    void setUpRepository() {
        repository = createRepository();
    }

    @Test
    @DisplayName("First acquire within a fresh window returns true")
    void first_acquire_returnsTrue() {
        boolean acquired = repository.tryAcquire("u1", "hash1", "/api/x", Duration.ofSeconds(10));
        assertThat(acquired).isTrue();
    }

    @Test
    @DisplayName("Second acquire inside the window for the same triple returns false")
    void second_acquire_inWindow_returnsFalse() {
        repository.tryAcquire("u1", "hash1", "/api/x", Duration.ofSeconds(10));

        boolean acquired = repository.tryAcquire("u1", "hash1", "/api/x", Duration.ofSeconds(10));
        assertThat(acquired).isFalse();
    }

    @Test
    @DisplayName("Different resource keys do not collide")
    void differentResourceKey_doesNotCollide() {
        repository.tryAcquire("u1", "hash1", "/api/x", Duration.ofSeconds(10));

        boolean acquired = repository.tryAcquire("u1", "hash1", "/api/y", Duration.ofSeconds(10));
        assertThat(acquired).isTrue();
    }

    @Test
    @DisplayName("Different users do not collide for the same resource")
    void differentUser_doesNotCollide() {
        repository.tryAcquire("u1", "hash1", "/api/x", Duration.ofSeconds(10));

        boolean acquired = repository.tryAcquire("u2", "hash1", "/api/x", Duration.ofSeconds(10));
        assertThat(acquired).isTrue();
    }

    @Test
    @DisplayName("Invalid inputs (null/blank/zero window) are treated as pass-through")
    void invalid_inputs_passThrough() {
        assertThat(repository.tryAcquire(null, "h", "/r", Duration.ofSeconds(10))).isTrue();
        assertThat(repository.tryAcquire("", "h", "/r", Duration.ofSeconds(10))).isTrue();
        assertThat(repository.tryAcquire("u", null, "/r", Duration.ofSeconds(10))).isTrue();
        assertThat(repository.tryAcquire("u", "h", null, Duration.ofSeconds(10))).isTrue();
        assertThat(repository.tryAcquire("u", "h", "/r", null)).isTrue();
    }

    @Test
    @DisplayName("Colon characters inside fields do not create false positive collisions")
    void colonInField_doesNotCollideAcrossDifferentLogicalInputs() {
        boolean first = repository.tryAcquire("a:b", "c", "d", Duration.ofSeconds(10));
        assertThat(first).isTrue();

        boolean second = repository.tryAcquire("a", "b:c", "d", Duration.ofSeconds(10));

        assertThat(second)
                .as("logically distinct inputs must not collide just because naive concatenation happens to match")
                .isTrue();
    }
}
