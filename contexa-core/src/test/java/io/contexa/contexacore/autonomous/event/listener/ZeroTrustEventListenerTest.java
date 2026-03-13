package io.contexa.contexacore.autonomous.event.listener;

import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ZeroTrustEventListenerTest {

    @Mock
    private SecurityEventPublisher securityEventPublisher;

    @Mock
    private ZeroTrustActionRepository actionRepository;

    @Mock
    private SecurityZeroTrustProperties securityZeroTrustProperties;

    private ZeroTrustEventListener listener;

    @BeforeEach
    void setUp() {
        listener = new ZeroTrustEventListener(
                securityEventPublisher, actionRepository, securityZeroTrustProperties);
        when(securityZeroTrustProperties.isEnabled()).thenReturn(true);
    }

    @Test
    @DisplayName("AUTHENTICATION event should invoke publishGenericSecurityEvent")
    void authenticationEvent_shouldPublish() {
        // given
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType("SUCCESS")
                .userId("user-1")
                .sessionId("session-1")
                .clientIp("10.0.0.1")
                .build();

        // when
        listener.handleZeroTrustEvent(event);

        // then
        verify(securityEventPublisher).publishGenericSecurityEvent(event);
    }

    @Test
    @DisplayName("AUTHORIZATION event should apply duplicate filtering logic")
    void authorizationEvent_shouldApplyDuplicateFiltering() {
        // given
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-2")
                .sessionId("session-2")
                .clientIp("10.0.0.2")
                .userAgent("TestAgent")
                .build();

        when(actionRepository.getCurrentAction(anyString(), anyString()))
                .thenReturn(ZeroTrustAction.ALLOW);

        // when
        listener.handleZeroTrustEvent(event);

        // then - ALLOW action means shouldSkipPublishing returns true
        verify(securityEventPublisher, never()).publishGenericSecurityEvent(event);
    }

    @Test
    @DisplayName("shouldPublishAuthorizationEvent with PENDING_ANALYSIS should return true")
    void shouldPublishAuthorizationEvent_pendingAnalysis_shouldReturnTrue() {
        // given
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-3")
                .sessionId("session-3")
                .clientIp("10.0.0.3")
                .build();

        when(actionRepository.getCurrentAction(anyString(), any()))
                .thenReturn(ZeroTrustAction.PENDING_ANALYSIS);

        // when
        boolean shouldPublish = listener.shouldPublishAuthorizationEvent(event);

        // then
        assertThat(shouldPublish).isTrue();
    }

    @Test
    @DisplayName("shouldPublishAuthorizationEvent with non-PENDING action should skip")
    void shouldPublishAuthorizationEvent_nonPendingAction_shouldSkip() {
        // given
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-4")
                .sessionId("session-4")
                .clientIp("10.0.0.4")
                .build();

        when(actionRepository.getCurrentAction(anyString(), any()))
                .thenReturn(ZeroTrustAction.BLOCK);

        // when
        boolean shouldPublish = listener.shouldPublishAuthorizationEvent(event);

        // then
        assertThat(shouldPublish).isFalse();
    }

    @Test
    @DisplayName("Disabled zero trust should ignore events")
    void disabled_shouldIgnoreEvents() {
        // given
        when(securityZeroTrustProperties.isEnabled()).thenReturn(false);

        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType("SUCCESS")
                .userId("user-5")
                .build();

        // when
        listener.handleZeroTrustEvent(event);

        // then
        verify(securityEventPublisher, never()).publishGenericSecurityEvent(any());
    }
}
