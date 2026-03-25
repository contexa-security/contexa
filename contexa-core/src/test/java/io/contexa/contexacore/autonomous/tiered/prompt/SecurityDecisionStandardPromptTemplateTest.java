package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionStandardPromptTemplateTest {

    @Test
    void generatePromptShouldDelegateToSecurityPromptTemplate() {
        SecurityPromptTemplate delegate = new SecurityPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties()
        );
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(delegate);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-001")
                .timestamp(LocalDateTime.of(2026, 3, 24, 10, 30))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("203.0.113.10")
                .description("POST /api/customer/export")
                .build();
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("requestPath", "/api/customer/export");

        SecurityPromptTemplate.SessionContext sessionContext = new SecurityPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");
        sessionContext.setRequestCount(5);

        SecurityPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineContext("[NO_DATA] Baseline not loaded");

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())
        );

        String systemPrompt = template.generateSystemPrompt(request, "");
        String userPrompt = template.generateUserPrompt(request, "");

        assertThat(systemPrompt).contains("You are a Zero Trust security analyst AI.");
        assertThat(userPrompt).contains("=== EVENT ===");
        assertThat(userPrompt).contains("=== CURRENT REQUEST ===");
        assertThat(userPrompt).contains("/api/customer/export");
        assertThat(userPrompt).contains("alice");
    }
}
