package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.context.collector.ContextObservationRecorder;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * SHADOW decides as ENFORCE does and applies nothing. What it decided is kept in the memory of SHADOW, and what counts
 * of a decision (the memory that answers the next requests, what is learned of an ALLOW) counts as it does in ENFORCE;
 * what restricts the user (the block, the stored action the filters read) is not done.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("A decision of SHADOW counts as ENFORCE's and restricts no one")
class SecurityDecisionEnforcementHandlerShadowMemoryTest {

    private static final String USER = "user-shadow-memory";

    @Mock
    private ZeroTrustActionRepository enforcedStore;
    @Mock
    private ZeroTrustActionRepository shadowMemory;
    @Mock
    private SecurityLearningService learning;
    @Mock
    private IBlockedUserRecorder blockedUserRecorder;
    @Mock
    private BlockingSignalBroadcaster broadcaster;
    @Mock
    private AiSecurityDecisionObservationWriter writer;

    private final InMemorySecurityContextDataStore contextStore = new InMemorySecurityContextDataStore();
    private final ContextObservationRecorder recorder = new ContextObservationRecorder(contextStore);
    private SecurityDecisionEnforcementHandler handler;

    @BeforeEach
    void setUp() {
        when(writer.recordDecision(any(), any(), any())).thenReturn("observation-1");
        when(writer.isStoreConfigured()).thenReturn(true);
        when(shadowMemory.writeFinalAction(anyString(), any(ZeroTrustAction.class), anyMap()))
                .thenReturn(ZeroTrustActionRepository.FinalActionWrite.APPLIED);
        handler = handlerFor(SecurityZeroTrustProperties.EnforcementMode.SHADOW, true);
    }

    private SecurityDecisionEnforcementHandler handlerFor(SecurityZeroTrustProperties.EnforcementMode mode, boolean withMemory) {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setMode(mode);
        SecurityDecisionEnforcementHandler built = new SecurityDecisionEnforcementHandler(
                enforcedStore, learning, blockedUserRecorder, broadcaster, properties, Runnable::run,
                () -> writer, contextStore, recorder);
        if (withMemory) {
            built.setShadowMemory(shadowMemory);
        }
        return built;
    }

    private static SecurityEvent event(String requestId) {
        SecurityEvent event = SecurityEvent.builder()
                .userId(USER).sessionId("session-shadow-memory").sourceIp("10.0.0.30").userAgent("TestAgent").build();
        event.addMetadata("requestId", requestId);
        return event;
    }

    private static SecurityEventContext contextWith(SecurityEvent event, ZeroTrustAction action) {
        SecurityEventContext context = SecurityEventContext.builder().securityEvent(event).build();
        context.addMetadata("processingResult", ProcessingResult.builder().success(true).action(action.name())
                .riskScore(0.5).confidence(0.9).reasoning("shadow").build());
        return context;
    }

    @Test
    @DisplayName("a BLOCK is remembered, bound to its observation, and the store and the block stay untouched")
    void aBlockIsRememberedAndNotApplied() {
        SecurityEvent event = event("request-block");

        assertThat(handler.handle(contextWith(event, ZeroTrustAction.BLOCK))).isTrue();

        ArgumentCaptor<Map<String, Object>> fields = ArgumentCaptor.forClass(Map.class);
        verify(shadowMemory).writeFinalAction(eq(USER), eq(ZeroTrustAction.BLOCK), fields.capture());
        assertThat(fields.getValue()).containsEntry("observationId", "observation-1");
        verify(enforcedStore, never()).writeFinalAction(anyString(), any(), anyMap());
        verify(enforcedStore, never()).setBlockedFlag(anyString());
        verify(shadowMemory, never()).setBlockedFlag(anyString());
        verify(broadcaster, never()).registerBlock(anyString());
        verify(broadcaster, never()).registerBlockAndAwait(anyString());
        verifyNoInteractions(blockedUserRecorder);
    }

    @Test
    @DisplayName("an ALLOW of SHADOW is learned as the ALLOW of ENFORCE is")
    void anAllowIsLearned() {
        SecurityEvent event = event("request-allow");

        handler.handle(contextWith(event, ZeroTrustAction.ALLOW));

        verify(shadowMemory).writeFinalAction(eq(USER), eq(ZeroTrustAction.ALLOW), anyMap());
        verify(learning).learnBaselineOnly(eq(USER), any(), any());
    }

    @Test
    @DisplayName("an ALLOW kept out by a stricter decision in the memory is not learned, as in ENFORCE")
    void anAllowKeptOutByAStricterDecisionIsNotLearned() {
        when(shadowMemory.writeFinalAction(anyString(), any(ZeroTrustAction.class), anyMap()))
                .thenReturn(ZeroTrustActionRepository.FinalActionWrite.KEPT_STRICTER);

        handler.handle(contextWith(event("request-kept"), ZeroTrustAction.ALLOW));

        verify(learning, never()).learnBaselineOnly(anyString(), any(), any());
    }

    @Test
    @DisplayName("the usual behaviour is learned from an ALLOW of SHADOW and from no other decision")
    void theObservationsOfAnAllowAreLearnable() {
        List<String> recorded = new ArrayList<>();
        for (ZeroTrustAction action : List.of(ZeroTrustAction.ALLOW, ZeroTrustAction.CHALLENGE, ZeroTrustAction.BLOCK)) {
            SecurityEvent event = event("request-" + action);
            recorder.stage(event, ContextObservationRecorder.WORK_PROFILE, null,
                    commit -> recorded.add(commit.outcome() + " learnable=" + commit.learnable()));
            handler.handle(contextWith(event, action));
        }

        assertThat(recorded).containsExactlyInAnyOrder("ALLOW learnable=true", "CHALLENGE learnable=false", "BLOCK learnable=false");
    }

    @Test
    @DisplayName("without a memory a decision of SHADOW is only observed, as before")
    void withoutAMemoryNothingIsRemembered() {
        SecurityDecisionEnforcementHandler bare = handlerFor(SecurityZeroTrustProperties.EnforcementMode.SHADOW, false);

        assertThat(bare.handle(contextWith(event("request-bare"), ZeroTrustAction.ALLOW))).isTrue();

        verifyNoInteractions(shadowMemory);
        verify(learning, never()).learnBaselineOnly(anyString(), any(), any());
    }

    @Test
    @DisplayName("a decision whose observation could not be recorded is not remembered and does not fail")
    void aDecisionWithoutItsObservationIsNotRemembered() {
        when(writer.recordDecision(any(), any(), any())).thenReturn(null);

        assertThat(handler.handle(contextWith(event("request-unaudited"), ZeroTrustAction.ALLOW))).isTrue();

        verify(shadowMemory, never()).writeFinalAction(anyString(), any(ZeroTrustAction.class), anyMap());
    }

    @Test
    @DisplayName("a memory that fails does not fail a decision that applies nothing")
    void aFailingMemoryDoesNotFailTheDecision() {
        when(shadowMemory.writeFinalAction(anyString(), any(ZeroTrustAction.class), anyMap()))
                .thenThrow(new IllegalStateException("store down"));

        assertThat(handler.handle(contextWith(event("request-down"), ZeroTrustAction.ALLOW))).isTrue();

        verify(learning, never()).learnBaselineOnly(anyString(), any(), any());
    }

    @Test
    @DisplayName("under ENFORCE the memory of SHADOW is never written")
    void underEnforceTheMemoryIsNotWritten() {
        when(enforcedStore.writeFinalAction(anyString(), any(ZeroTrustAction.class), anyMap()))
                .thenReturn(ZeroTrustActionRepository.FinalActionWrite.APPLIED);
        SecurityDecisionEnforcementHandler enforcing = handlerFor(SecurityZeroTrustProperties.EnforcementMode.ENFORCE, true);

        enforcing.handle(contextWith(event("request-enforce"), ZeroTrustAction.ALLOW));

        verify(enforcedStore).writeFinalAction(eq(USER), eq(ZeroTrustAction.ALLOW), anyMap());
        verifyNoInteractions(shadowMemory);
    }
}
