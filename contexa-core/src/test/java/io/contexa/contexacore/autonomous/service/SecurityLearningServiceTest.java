package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityLearningServiceTest {

    @Mock
    private BaselineLearningService baselineLearningService;

    @Mock
    private SecurityDecisionPostProcessor postProcessor;

    private SecurityLearningService service;

    private SecurityEvent event;
    private SecurityDecision decision;

    @BeforeEach
    void setUp() {
        service = new SecurityLearningService(baselineLearningService, postProcessor);

        event = SecurityEvent.builder()
                .eventId("evt-1")
                .sessionId("session-1")
                .sourceIp("10.0.0.1")
                .build();

        decision = SecurityDecision.builder()
                .action(ZeroTrustAction.ALLOW)
                .riskScore(0.1)
                .build();
    }

    @Test
    @DisplayName("learnAndStore should invoke both baseline learning and post-processing")
    void shouldInvokeBothBaselineLearningAndPostProcessing() {
        // when
        service.learnAndStore("user1", decision, event);

        // then
        verify(baselineLearningService).learnIfNormal(eq("user1"), eq(decision), eq(event));
        verify(postProcessor).updateSessionContext(event, decision);
        verify(postProcessor).storeInVectorDatabase(event, decision);
    }

    @Test
    @DisplayName("learnBaselineOnly should invoke learnIfNormal only, not post-processing")
    void shouldInvokeLearnIfNormalOnly() {
        // when
        service.learnBaselineOnly("user1", decision, event);

        // then
        verify(baselineLearningService).learnIfNormal(eq("user1"), eq(decision), eq(event));
        verify(postProcessor, never()).updateSessionContext(any(), any());
        verify(postProcessor, never()).storeInVectorDatabase(any(), any());
    }

    @Test
    @DisplayName("postProcessDecision should invoke only post-processing, not baseline learning")
    void shouldInvokePostProcessingOnly() {
        // when
        service.postProcessDecision(event, decision);

        // then
        verify(baselineLearningService, never()).learnIfNormal(any(), any(), any());
        verify(postProcessor).updateSessionContext(event, decision);
        verify(postProcessor).storeInVectorDatabase(event, decision);
    }

    @Test
    @DisplayName("learnAndStore should skip baseline learning for null userId")
    void shouldSkipBaselineLearningForNullUserId() {
        // when
        service.learnAndStore(null, decision, event);

        // then
        verify(baselineLearningService, never()).learnIfNormal(any(), any(), any());
        // Post-processing should still be called
        verify(postProcessor).updateSessionContext(event, decision);
        verify(postProcessor).storeInVectorDatabase(event, decision);
    }

    @Test
    @DisplayName("learnAndStore should skip baseline learning for blank userId")
    void shouldSkipBaselineLearningForBlankUserId() {
        // when
        service.learnAndStore("  ", decision, event);

        // then
        verify(baselineLearningService, never()).learnIfNormal(any(), any(), any());
        verify(postProcessor).updateSessionContext(event, decision);
    }
}
