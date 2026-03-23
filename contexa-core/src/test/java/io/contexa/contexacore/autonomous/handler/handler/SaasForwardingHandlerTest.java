package io.contexa.contexacore.autonomous.handler.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.saas.SaasDecisionOutboxService;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class SaasForwardingHandlerTest {

    private SaasDecisionOutboxService outboxService;
    private SaasForwardingProperties properties;
    private SaasForwardingHandler handler;

    @BeforeEach
    void setUp() {
        outboxService = mock(SaasDecisionOutboxService.class);
        properties = SaasForwardingProperties.builder()
                .enabled(true)
                .endpoint("https://saas.example.com")
                .pseudonymizationSecret("top-secret-key")
                .globalCorrelationSecret("global-correlation-secret")
                .oauth2(SaasForwardingProperties.OAuth2.builder()
                        .enabled(true)
                        .registrationId("reg")
                        .tokenUri("https://auth.example.com/oauth2/token")
                        .clientId("client")
                        .clientSecret("secret")
                        .scope("saas.xai.decision.ingest")
                        .expirySkewSeconds(30)
                        .build())
                .build();
        handler = new SaasForwardingHandler(outboxService, properties);
    }

    @Test
    void canHandleReturnsTrueForBlock() {
        SecurityEventContext context = context("BLOCK");

        assertThat(handler.canHandle(context)).isTrue();
    }

    @Test
    void canHandleReturnsFalseForAllow() {
        SecurityEventContext context = context("ALLOW");

        assertThat(handler.canHandle(context)).isFalse();
    }

    @Test
    void handleCapturesContextAndContinuesChain() {
        SecurityEventContext context = context("CHALLENGE");

        boolean result = handler.handle(context);

        assertThat(result).isTrue();
        verify(outboxService).capture(context);
    }

    private SecurityEventContext context(String action) {
        SecurityEventContext context = SecurityEventContext.builder()
                .securityEvent(SecurityEvent.builder().eventId("evt-001").build())
                .build();
        context.addMetadata("processingResult", ProcessingResult.builder()
                .success(true)
                .action(action)
                .build());
        return context;
    }
}
