package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityPromptTemplateTest {

    @Mock
    private SecurityEventEnricher eventEnricher;

    private TieredStrategyProperties tieredStrategyProperties;

    private SecurityPromptTemplate promptTemplate;

    @BeforeEach
    void setUp() {
        tieredStrategyProperties = new TieredStrategyProperties();
        promptTemplate = new SecurityPromptTemplate(eventEnricher, tieredStrategyProperties);
    }

    @Test
    @DisplayName("buildStructuredPrompt should separate systemText and userText")
    void buildStructuredPrompt_separatesSystemAndUserText() {
        SecurityEvent event = buildTestEvent();
        SecurityPromptTemplate.SessionContext sessionCtx = buildSessionContext();
        SecurityPromptTemplate.BehaviorAnalysis behaviorCtx = buildBehaviorAnalysis();

        SecurityPromptTemplate.StructuredPrompt prompt =
                promptTemplate.buildStructuredPrompt(event, sessionCtx, behaviorCtx, Collections.emptyList());

        assertThat(prompt).isNotNull();
        assertThat(prompt.systemText()).isNotNull();
        assertThat(prompt.systemText()).isNotEmpty();
        assertThat(prompt.userText()).isNotNull();
        assertThat(prompt.userText()).isNotEmpty();
        assertThat(prompt.systemText()).isNotEqualTo(prompt.userText());
    }

    @Test
    @DisplayName("systemText should contain ACTION DECISION GUIDE")
    void buildStructuredPrompt_systemTextContainsActionDecisionGuide() {
        SecurityEvent event = buildTestEvent();
        SecurityPromptTemplate.SessionContext sessionCtx = buildSessionContext();
        SecurityPromptTemplate.BehaviorAnalysis behaviorCtx = buildBehaviorAnalysis();

        SecurityPromptTemplate.StructuredPrompt prompt =
                promptTemplate.buildStructuredPrompt(event, sessionCtx, behaviorCtx, Collections.emptyList());

        assertThat(prompt.systemText()).contains("ACTION DECISION GUIDE");
        assertThat(prompt.systemText()).contains("BLOCK");
        assertThat(prompt.systemText()).contains("CHALLENGE");
        assertThat(prompt.systemText()).contains("ALLOW");
        assertThat(prompt.systemText()).contains("ESCALATE");
    }

    @Test
    @DisplayName("userText should contain EVENT section with key fields")
    void buildStructuredPrompt_userTextContainsEventSection() {
        SecurityEvent event = buildTestEvent();
        SecurityPromptTemplate.SessionContext sessionCtx = buildSessionContext();
        SecurityPromptTemplate.BehaviorAnalysis behaviorCtx = buildBehaviorAnalysis();

        SecurityPromptTemplate.StructuredPrompt prompt =
                promptTemplate.buildStructuredPrompt(event, sessionCtx, behaviorCtx, Collections.emptyList());

        assertThat(prompt.userText()).contains("=== EVENT ===");
        assertThat(prompt.userText()).contains("User: user-test-001");
        assertThat(prompt.userText()).contains("CurrentHour:");
    }

    @Test
    @DisplayName("userText should contain HTTP method from event metadata")
    void buildStructuredPrompt_userTextContainsHttpMethod() {
        SecurityEvent event = buildTestEvent();
        SecurityPromptTemplate.SessionContext sessionCtx = buildSessionContext();
        SecurityPromptTemplate.BehaviorAnalysis behaviorCtx = buildBehaviorAnalysis();

        SecurityPromptTemplate.StructuredPrompt prompt =
                promptTemplate.buildStructuredPrompt(event, sessionCtx, behaviorCtx, Collections.emptyList());

        assertThat(prompt.userText()).contains("HttpMethod: GET");
    }

    @Test
    @DisplayName("buildStructuredPrompt should handle null sessionContext gracefully")
    void buildStructuredPrompt_nullSessionContext_noException() {
        SecurityEvent event = buildTestEvent();
        SecurityPromptTemplate.BehaviorAnalysis behaviorCtx = buildBehaviorAnalysis();

        SecurityPromptTemplate.StructuredPrompt prompt =
                promptTemplate.buildStructuredPrompt(event, null, behaviorCtx, null);

        assertThat(prompt).isNotNull();
        assertThat(prompt.systemText()).isNotEmpty();
        assertThat(prompt.userText()).isNotEmpty();
    }

    @Test
    @DisplayName("buildStructuredPrompt should handle null behaviorAnalysis gracefully")
    void buildStructuredPrompt_nullBehaviorAnalysis_noException() {
        SecurityEvent event = buildTestEvent();
        SecurityPromptTemplate.SessionContext sessionCtx = buildSessionContext();

        SecurityPromptTemplate.StructuredPrompt prompt =
                promptTemplate.buildStructuredPrompt(event, sessionCtx, null, null);

        assertThat(prompt).isNotNull();
        assertThat(prompt.systemText()).isNotEmpty();
        assertThat(prompt.userText()).isNotEmpty();
    }

    @Test
    @DisplayName("buildStructuredPrompt should include request path in user text")
    void buildStructuredPrompt_includesRequestPath() {
        SecurityEvent event = buildTestEvent();
        SecurityPromptTemplate.SessionContext sessionCtx = buildSessionContext();
        SecurityPromptTemplate.BehaviorAnalysis behaviorCtx = buildBehaviorAnalysis();

        SecurityPromptTemplate.StructuredPrompt prompt =
                promptTemplate.buildStructuredPrompt(event, sessionCtx, behaviorCtx, Collections.emptyList());

        assertThat(prompt.userText()).contains("/api/test/resource");
    }

    @Test
    @DisplayName("systemText should contain Zero Trust security analyst instruction")
    void buildStructuredPrompt_systemTextContainsZeroTrustInstruction() {
        SecurityEvent event = buildTestEvent();
        SecurityPromptTemplate.SessionContext sessionCtx = buildSessionContext();

        SecurityPromptTemplate.StructuredPrompt prompt =
                promptTemplate.buildStructuredPrompt(event, sessionCtx, null, null);

        assertThat(prompt.systemText()).contains("Zero Trust security analyst");
        assertThat(prompt.systemText()).contains("JSON");
    }

    private SecurityEvent buildTestEvent() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("httpMethod", "GET");
        metadata.put("requestPath", "/api/test/resource");

        return SecurityEvent.builder()
                .eventId("prompt-test-event")
                .userId("user-test-001")
                .sessionId("session-test-001")
                .sourceIp("192.168.0.10")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                .timestamp(LocalDateTime.now())
                .metadata(metadata)
                .build();
    }

    private SecurityPromptTemplate.SessionContext buildSessionContext() {
        SecurityPromptTemplate.SessionContext ctx = new SecurityPromptTemplate.SessionContext();
        ctx.setSessionId("session-test-001");
        ctx.setUserId("user-test-001");
        ctx.setAuthMethod("JWT");
        ctx.setRecentActions(List.of("GET /api/users", "POST /api/data"));
        ctx.setSessionAgeMinutes(15);
        ctx.setRequestCount(5);
        return ctx;
    }

    private SecurityPromptTemplate.BehaviorAnalysis buildBehaviorAnalysis() {
        SecurityPromptTemplate.BehaviorAnalysis ctx = new SecurityPromptTemplate.BehaviorAnalysis();
        ctx.setSimilarEvents(List.of("event-1", "event-2"));
        ctx.setBaselineContext("Normal baseline established");
        ctx.setBaselineEstablished(true);
        ctx.setCurrentUserAgentOS("Windows");
        ctx.setCurrentUserAgentBrowser("Chrome/120.0");
        return ctx;
    }
}
