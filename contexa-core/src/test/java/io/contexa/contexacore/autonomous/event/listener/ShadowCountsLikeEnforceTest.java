package io.contexa.contexacore.autonomous.event.listener;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ShadowAwareActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The count of model calls of a trial in SHADOW is the count of ENFORCE: a user whose request was decided is answered by
 * the decision for the next requests in either mode, and only the store the filters read differs.
 */
@DisplayName("SHADOW answers the next requests of a decided user as ENFORCE does")
class ShadowCountsLikeEnforceTest {

    private static final String CONTEXT = "ctx-1";

    private static SecurityZeroTrustProperties in(SecurityZeroTrustProperties.EnforcementMode mode) {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setMode(mode);
        return properties;
    }

    private static ZeroTrustSpringEvent request() {
        return ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("alice")
                .sessionId("session-1")
                .clientIp("10.0.0.1")
                .userAgent("JUnit")
                .payload(new HashMap<>(Map.of("contextBindingHash", CONTEXT)))
                .build();
    }

    private static Map<String, Object> decided() {
        return Map.of("observationId", "observation-1", "processingGeneration", "generation-1", "contextBindingHash", CONTEXT);
    }

    private static ZeroTrustEventListener listener(ZeroTrustActionRepository counting, SecurityZeroTrustProperties properties) {
        return new ZeroTrustEventListener(mock(SecurityEventPublisher.class), counting, properties);
    }

    @ParameterizedTest
    @EnumSource(value = ZeroTrustAction.class, names = {"ALLOW", "CHALLENGE", "BLOCK"})
    @DisplayName("a decided user is not analysed again in SHADOW, as in ENFORCE")
    void aDecidedUserIsNotAnalysedAgain(ZeroTrustAction decision) {
        InMemoryZeroTrustActionRepository enforcedStore = new InMemoryZeroTrustActionRepository();
        ZeroTrustEventListener enforce = listener(
                ShadowAwareActionRepository.whenNotEnforcing(enforcedStore, () -> true), in(SecurityZeroTrustProperties.EnforcementMode.ENFORCE));

        InMemoryZeroTrustActionRepository shadowStore = new InMemoryZeroTrustActionRepository();
        ZeroTrustEventListener shadow = listener(
                ShadowAwareActionRepository.whenNotEnforcing(shadowStore, () -> false), in(SecurityZeroTrustProperties.EnforcementMode.SHADOW));

        assertThat(enforce.shouldPublishAuthorizationEvent(request())).isTrue();
        assertThat(shadow.shouldPublishAuthorizationEvent(request())).isTrue();

        enforcedStore.writeFinalAction("alice", decision, decided());
        ShadowAwareActionRepository.always(shadowStore).writeFinalAction("alice", decision, decided());

        assertThat(enforce.shouldPublishAuthorizationEvent(request())).isFalse();
        assertThat(shadow.shouldPublishAuthorizationEvent(request())).isEqualTo(enforce.shouldPublishAuthorizationEvent(request()));
        assertThat(shadow.shouldPublishSynchronousAuthorizationEvent(request()))
                .isEqualTo(enforce.shouldPublishSynchronousAuthorizationEvent(request()));
    }

    @Test
    @DisplayName("what the filters read holds no decision of SHADOW, whatever SHADOW decided")
    void theStoreThatEnforcesHoldsNoDecisionOfShadow() {
        InMemoryZeroTrustActionRepository store = new InMemoryZeroTrustActionRepository();
        ZeroTrustActionRepository memory = ShadowAwareActionRepository.always(store);

        for (ZeroTrustAction decision : new ZeroTrustAction[]{ZeroTrustAction.ALLOW, ZeroTrustAction.CHALLENGE, ZeroTrustAction.BLOCK}) {
            memory.writeFinalAction("alice", decision, decided());

            assertThat(store.getCurrentAction("alice", CONTEXT)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
            assertThat(store.getCurrentAction("alice")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        }
    }
}
