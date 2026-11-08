package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("What SHADOW remembers of its decisions")
class ShadowAwareActionRepositoryTest {

    private final InMemoryZeroTrustActionRepository store = new InMemoryZeroTrustActionRepository();

    /** A final decision is bound to the observation that records it. */
    private static Map<String, Object> bound() {
        return Map.of("observationId", "observation-1", "processingGeneration", "generation-1");
    }

    @Test
    @DisplayName("a decision of SHADOW is in the memory and never in the store that enforces")
    void aDecisionOfShadowIsNotInTheStoreThatEnforces() {
        ZeroTrustActionRepository memory = ShadowAwareActionRepository.always(store);

        ZeroTrustActionRepository.FinalActionWrite written = memory.writeFinalAction("alice", ZeroTrustAction.BLOCK, bound());

        assertThat(written).isEqualTo(ZeroTrustActionRepository.FinalActionWrite.APPLIED);
        assertThat(memory.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(store.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(store.getCurrentAction(ZeroTrustUserKey.shadow("alice"))).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("the counting reads the memory while decisions are not enforced and the store when they are")
    void theCountingReadsByMode() {
        AtomicBoolean enforcing = new AtomicBoolean(false);
        ZeroTrustActionRepository memory = ShadowAwareActionRepository.always(store);
        ZeroTrustActionRepository counting = ShadowAwareActionRepository.whenNotEnforcing(store, enforcing::get);
        memory.writeFinalAction("alice", ZeroTrustAction.ALLOW, bound());
        store.writeFinalAction("alice", ZeroTrustAction.BLOCK, bound());

        assertThat(counting.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.ALLOW);

        enforcing.set(true);
        assertThat(counting.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("the memory keeps the rules of the store: a stricter decision stays")
    void aStricterDecisionStays() {
        ZeroTrustActionRepository memory = ShadowAwareActionRepository.always(store);

        memory.writeFinalAction("alice", ZeroTrustAction.BLOCK, bound());
        ZeroTrustActionRepository.FinalActionWrite later = memory.writeFinalAction("alice", ZeroTrustAction.ALLOW, bound());

        assertThat(later).isEqualTo(ZeroTrustActionRepository.FinalActionWrite.KEPT_STRICTER);
        assertThat(memory.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("the memory is kept apart for the person and for an agent of the person")
    void aSubjectReadsItsOwnKeyInTheMemory() {
        AtomicBoolean enforcing = new AtomicBoolean(false);
        ZeroTrustActionRepository memory = ShadowAwareActionRepository.always(store);
        ZeroTrustActionRepository counting = ShadowAwareActionRepository.whenNotEnforcing(store, enforcing::get);
        ZeroTrustSubject person = ZeroTrustSubject.person("alice");
        memory.writeFinalAction(person.storageKey(), ZeroTrustAction.CHALLENGE, bound());

        assertThat(counting.currentActionOf(person)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(store.currentActionOf(person)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("the data of a deleted account leaves the memory and the store's decisions stay")
    void removingTheMemoryLeavesTheStore() {
        ZeroTrustActionRepository memory = ShadowAwareActionRepository.always(store);
        memory.writeFinalAction("alice", ZeroTrustAction.ALLOW, bound());
        store.writeFinalAction("alice", ZeroTrustAction.CHALLENGE, bound());

        memory.removeAllUserData("alice");

        assertThat(memory.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(store.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("a name spelled as a key of the memory is moved off it, so that no person reads another's memory")
    void aNameThatLooksLikeAKeyOfTheMemoryIsMovedOff() {
        String person = ZeroTrustUserKey.person("shadow::alice");

        assertThat(person).isNotEqualTo("shadow::alice");
        assertThat(person).doesNotStartWith(ZeroTrustUserKey.SHADOW_KEY);
        assertThat(ZeroTrustUserKey.person("alice")).isEqualTo("alice");
    }
}
