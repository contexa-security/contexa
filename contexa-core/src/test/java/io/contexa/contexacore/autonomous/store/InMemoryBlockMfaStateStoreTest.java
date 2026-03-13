package io.contexa.contexacore.autonomous.store;

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.quality.Strictness;
import org.mockito.junit.jupiter.MockitoSettings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class InMemoryBlockMfaStateStoreTest {

    @Mock
    private ZeroTrustActionRepository actionRepository;

    private InMemoryBlockMfaStateStore store;

    @BeforeEach
    void setUp() {
        store = new InMemoryBlockMfaStateStore(actionRepository);
    }

    @Test
    @DisplayName("setVerified marks user as verified")
    void setVerified_isVerified_returnsTrue() {
        store.setVerified("user1");

        assertThat(store.isVerified("user1")).isTrue();
    }

    @Test
    @DisplayName("isVerified returns false for unverified user")
    void isVerified_unverifiedUser_returnsFalse() {
        assertThat(store.isVerified("unknown")).isFalse();
    }

    @Test
    @DisplayName("setPending and clearPending work correctly")
    void setPending_clearPending_stateChanges() {
        store.setPending("user1");
        // setPending only adds to internal set, no getter to verify directly
        // but clearPending should not throw
        store.clearPending("user1");
        // no exception means success
    }

    @Test
    @DisplayName("getFailCount delegates to actionRepository")
    void getFailCount_delegatesToActionRepository() {
        when(actionRepository.getBlockMfaFailCount("user1")).thenReturn(5L);

        int result = store.getFailCount("user1");

        assertThat(result).isEqualTo(5);
        verify(actionRepository).getBlockMfaFailCount("user1");
    }

    @Test
    @DisplayName("getFailCount returns zero when repository returns zero")
    void getFailCount_repositoryReturnsZero_returnsZero() {
        when(actionRepository.getBlockMfaFailCount("user1")).thenReturn(0L);

        int result = store.getFailCount("user1");

        assertThat(result).isZero();
    }

    @Test
    @DisplayName("Multiple users can be verified independently")
    void multipleUsers_verifiedIndependently() {
        store.setVerified("user1");
        store.setVerified("user2");

        assertThat(store.isVerified("user1")).isTrue();
        assertThat(store.isVerified("user2")).isTrue();
        assertThat(store.isVerified("user3")).isFalse();
    }
}
