package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.SecurityLearningService;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityDecisionEnforcementHandlerTest {

    @Mock
    private ZeroTrustActionRepository actionRepository;

    @Mock
    private SecurityLearningService securityLearningService;

    @Mock
    private BlockingSignalBroadcaster blockingSignalBroadcaster;

    private SecurityDecisionEnforcementHandler handler;

    @BeforeEach
    void setUp() {
        handler = new SecurityDecisionEnforcementHandler(
                actionRepository, securityLearningService);
        handler.setBlockingDecisionRegistry(blockingSignalBroadcaster);
    }

    @Test
    @DisplayName("BLOCK decision should save action, set blocked flag, and register block")
    void blockDecision_shouldSaveAndSetBlockedFlag() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-1")
                .sourceIp("10.0.0.1")
                .userAgent("TestAgent")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();

        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.BLOCK.name())
                .riskScore(0.95)
                .confidence(0.9)
                .reasoning("Malicious activity detected")
                .build();
        context.addMetadata("processingResult", processingResult);

        // when
        boolean result = handler.handle(context);

        // then
        assertThat(result).isTrue();
        verify(actionRepository).saveAction(eq("user-1"), eq(ZeroTrustAction.BLOCK), anyMap());
        verify(actionRepository).setBlockedFlag("user-1");
        verify(blockingSignalBroadcaster).registerBlock("user-1");
    }

    @Test
    @DisplayName("ALLOW decision should trigger learning")
    void allowDecision_shouldTriggerLearning() throws Exception {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-2")
                .sourceIp("10.0.0.2")
                .userAgent("TestAgent")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();

        ProcessingResult processingResult = ProcessingResult.builder()
                .success(true)
                .action(ZeroTrustAction.ALLOW.name())
                .riskScore(0.1)
                .confidence(0.95)
                .build();
        context.addMetadata("processingResult", processingResult);

        // when
        boolean result = handler.handle(context);

        // then
        assertThat(result).isTrue();
        verify(actionRepository).saveAction(eq("user-2"), eq(ZeroTrustAction.ALLOW), anyMap());
        verify(actionRepository, never()).setBlockedFlag(anyString());
    }

    @Test
    @DisplayName("Default handler should accept active context")
    void canHandle_shouldAcceptActiveContext() {
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-3")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();

        // when
        boolean canHandle = handler.canHandle(context);

        // then
        assertThat(canHandle).isTrue();
    }

    @Test
    @DisplayName("Null processingResult should pass through")
    void nullProcessingResult_shouldPassThrough() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user-4")
                .build();
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(event)
                .build();
        // no processingResult in metadata

        // when
        boolean result = handler.handle(context);

        // then
        assertThat(result).isTrue();
        verify(actionRepository, never()).saveAction(anyString(), any(ZeroTrustAction.class), anyMap());
    }

    @Test
    @DisplayName("getOrder should return 55")
    void getOrder_shouldReturn55() {
        // when
        int order = handler.getOrder();

        // then
        assertThat(order).isEqualTo(55);
    }
}
