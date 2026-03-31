package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.context.ContextCoverageEvaluator;
import io.contexa.contexacore.autonomous.context.DefaultCanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.InMemoryResourceContextRegistry;
import io.contexa.contexacore.autonomous.context.PromptContextComposer;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import org.springframework.ai.document.Document;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionStandardPromptTemplateTest {

    @Test
    @DisplayName("표준 프롬프트는 5개 필드 계약과 핵심 섹션만 포함해야 한다")
    void generatePromptShouldUseGovernedStandardTemplate() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

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

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");
        sessionContext.setRequestCount(5);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineContext("[NO_DATA] Baseline not loaded");

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())
        );

        String systemPrompt = template.generateSystemPrompt(request, "");
        String userPrompt = template.generateUserPrompt(request, "");
        PromptGovernanceDescriptor descriptor = template.getPromptGovernanceDescriptor();
        PromptExecutionMetadata executionMetadata = template.buildStructuredPrompt(
                event,
                sessionContext,
                behaviorAnalysis,
                List.of()
        ).executionMetadata();

        // 시스템 프롬프트는 모델에게 고정된 판단 규칙과 출력 계약만 전달해야 한다.
        // 여기서 불필요한 런타임 메타데이터가 노출되면 소형 모델의 출력 순응도가 흔들릴 수 있다.
        assertThat(systemPrompt).contains("You are a Zero Trust security analyst AI.");
        assertThat(systemPrompt).contains("<output_format>");
        assertThat(template.getAIGenerationType()).isEqualTo(SecurityDecisionResponseLite.class);
        assertThat(systemPrompt)
                .doesNotContain("errorMessage")
                .doesNotContain("executionTime")
                .doesNotContain("\"metadata\"");
        // 사용자 프롬프트는 현재 요청의 보안 판단에 필요한 핵심 사실을 포함해야 한다.
        assertThat(userPrompt).contains("=== CURRENT REQUEST AND EVENT ===");
        assertThat(userPrompt).contains("/api/customer/export");
        assertThat(userPrompt).contains("alice");
        // omission/completeness 메타데이터는 "무엇이 빠졌는지"를 추적하기 위한 근거여야 한다.
        assertThat(executionMetadata.budgetProfile().profileKey()).isEqualTo("CORTEX_L1_STANDARD");
        assertThat(executionMetadata.promptEvidenceCompleteness().name()).isEqualTo("INCOMPLETE");
        assertThat(executionMetadata.omittedSections()).contains("BRIDGE_AND_COVERAGE", "IDENTITY_AND_ROLE");
        assertThat(descriptor.promptVersion()).isEqualTo("2026.03.26-e0.1");
        assertThat(descriptor.contractVersion()).isEqualTo("CORTEX_PROMPT_CONTRACT_V2");
        assertThat(descriptor.releaseStatus().name()).isEqualTo("PRODUCTION");
        assertThat(descriptor.supportedModelProfiles()).contains("STRICT_JSON_SCHEMA");
    }

    @Test
    @DisplayName("현재 요청 섹션은 행동 분석 fallback보다 canonical session narrative를 우선해야 한다")
    void generateUserPromptShouldPreferCanonicalSessionNarrativeOverBehaviorFallback() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                null,
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-002")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 31))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("203.0.113.10")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("previousPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("previousActionFamily", "READ");
        event.addMetadata("lastRequestIntervalMs", 42000L);
        event.addMetadata("sessionActionSequence", List.of("READ", "READ"));
        event.addMetadata("sessionProtectableSequence", List.of("/admin/api/security-test/sensitive/resource-001", "/admin/api/security-test/sensitive/resource-001"));
        event.addMetadata("bridgeCoverageLevel", "AUTHORIZATION_CONTEXT");
        event.addMetadata("bridgeCoverageSummary", "Bridge resolved authentication and authorization context for the current request.");
        event.addMetadata("bridgeAuthenticationSource", "SECURITY_CONTEXT");
        event.addMetadata("bridgeAuthorizationSource", "HEADER");
        event.addMetadata("userRoles", List.of("ROLE_ADMIN"));
        event.addMetadata("effectivePermissions", List.of("report.read"));
        event.addMetadata("scopeTags", List.of("customer_data"));
        event.addMetadata("mfaVerified", true);
        event.addMetadata("resourceSensitivity", "HIGH");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");
        sessionContext.setRequestCount(2);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setPreviousPath("/admin/api/security-test/evidence/server-truth");
        behaviorAnalysis.setLastRequestIntervalMs(0L);

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())
        );

        String userPrompt = template.generateUserPrompt(request, "");

        // 이전 경로와 요청 간격은 UI 부가 호출이 아니라 실제 보호 리소스 흐름을 기준으로 해야 한다.
        // 이 값이 흔들리면 LLM은 "직전 행위가 무엇이었는지"를 잘못 이해하게 된다.
        assertThat(userPrompt).contains("Previous request path: /admin/api/security-test/sensitive/resource-001.");
        assertThat(userPrompt).contains("Time since last request: 42 seconds.");
        assertThat(userPrompt).doesNotContain("Previous request path: /admin/api/security-test/evidence/server-truth.");
        assertThat(userPrompt).doesNotContain("Time since last request: 0 seconds.");
    }

    @Test
    @DisplayName("개인 기준선이 아직 얇을 때는 정상 패턴으로 과장하지 말고 잠정 상태로만 렌더링해야 한다")
    void generateUserPromptShouldKeepBaselineNarrativeProvisionalUntilPersonalBaselineIsEstablished() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-003")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 35))
                .userId("alice")
                .sessionId("session-1")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("userRoles", List.of("ADMIN"));

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineContext("User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)");
        behaviorAnalysis.setBaselineEstablished(true);
        behaviorAnalysis.setPersonalBaselineAvailable(true);
        behaviorAnalysis.setPersonalBaselineEstablished(false);
        behaviorAnalysis.setBaselineUpdateCount(1L);

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, behaviorAnalysis, List.of())
        );

        String userPrompt = template.generateUserPrompt(request, "");

        // 관측 수가 얇은 상태를 "정상 행동"으로 단정하면 이후 탈취 시나리오에서 허위 정상 근거가 생긴다.
        assertThat(userPrompt).contains("Provisional baseline evidence (learning in progress):");
        assertThat(userPrompt).doesNotContain("This user normally");
        assertThat(userPrompt).doesNotContain("Frequent paths:");
        assertThat(userPrompt).doesNotContain("Established baseline (from learned behavior):");
    }

    @Test
    @DisplayName("RAG 문서가 존재하면 historical comparable evidence가 userPrompt에 구조적으로 포함되어야 한다")
    void generateUserPromptShouldRenderHistoricalComparableEventsWhenRagDocumentsExist() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-004")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 40))
                .userId("alice")
                .sessionId("session-1")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineContext("[NO_DATA] Baseline not loaded");

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        behaviorAnalysis,
                        List.of(new Document("User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)"))));

        String userPrompt = template.generateUserPrompt(request, "");

        // relatedDocuments가 실제로 prompt에 반영되지 않으면 2차/3차 회차의 학습 이점이 사라진다.
        assertThat(userPrompt).contains("HistoricalComparableEvents:");
        assertThat(userPrompt).contains("Historical records for context:");
        assertThat(userPrompt).contains("/admin/api/security-test/sensitive/resource-001");
    }

    @Test
    @DisplayName("브라우저 후속 요청 프롬프트에는 bridge와 friction 근거가 함께 나타나야 한다")
    void generateUserPromptShouldRenderBridgeAndFrictionEvidenceForBrowserStyleFollowUpRequest() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties(),
                null,
                new DefaultCanonicalSecurityContextProvider(
                        new InMemoryResourceContextRegistry(),
                        new ContextCoverageEvaluator()),
                new PromptContextComposer());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-005")
                .timestamp(LocalDateTime.of(2026, 3, 30, 11, 45))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("192.168.1.100")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("previousPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("lastRequestIntervalMs", 42000L);
        event.addMetadata("sessionActionSequence", List.of(
                "11:30 | MFA_COMPLETED (Zero Trust Challenge verified) | 192.168.1.100",
                "11:31 | GET /admin/api/security-test/sensitive/resource-001 | 192.168.1.100"));
        event.addMetadata("bridgeCoverageLevel", "AUTHORIZATION_CONTEXT");
        event.addMetadata("bridgeCoverageSummary", "Bridge completeness reached authentication and authorization context for the current request.");
        event.addMetadata("bridgeAuthenticationSource", "SECURITY_CONTEXT");
        event.addMetadata("bridgeAuthorizationSource", "HEADER");
        event.addMetadata("effectiveRoles", List.of("ADMIN"));
        event.addMetadata("effectivePermissions", List.of("report.read"));
        event.addMetadata("scopeTags", List.of("customer_data"));
        event.addMetadata("authorizationEffect", "ALLOW");
        event.addMetadata("mfaVerified", true);
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("resourceLabel", "Sensitive Security Test Resource");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");
        sessionContext.setRequestCount(2);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        behaviorAnalysis.setBaselineContext("[NO_DATA] Baseline not loaded");

        SecurityDecisionRequest request = new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        behaviorAnalysis,
                        List.of(new Document("User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)"))));

        String userPrompt = template.generateUserPrompt(request, "");

        // bridge는 현재 요청의 인증/인가 맥락을 설명하고,
        // friction은 challenge/MFA 같은 실제 통제 이력을 구조화해서 보여줘야 한다.
        assertThat(userPrompt).contains("=== BRIDGE RESOLUTION CONTEXT ===");
        assertThat(userPrompt).contains("AuthorizationEffect: ALLOW");
        assertThat(userPrompt).contains("=== FRICTION AND APPROVAL HISTORY ===");
        assertThat(userPrompt).contains("RecentChallengeCount: 1");
        assertThat(userPrompt).contains("HistoricalComparableEvents:");
    }

    @Test
    @DisplayName("1차에서 3차로 갈수록 RAG와 기준선은 역행하지 않고 더 풍부한 근거를 제공해야 한다")
    void generateUserPromptShouldEvolveEvidenceAcrossRoundsWithoutRegression() {
        SecurityDecisionStandardPromptTemplate template = new SecurityDecisionStandardPromptTemplate(
                new SecurityEventEnricher(),
                new TieredStrategyProperties());

        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-security-standard-006")
                .timestamp(LocalDateTime.of(2026, 3, 30, 12, 10))
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("192.168.1.100")
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
                .description("GET /admin/api/security-test/sensitive/resource-001")
                .build();
        event.addMetadata("httpMethod", "GET");
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");
        event.addMetadata("resourceSensitivity", "HIGH");
        event.addMetadata("mfaVerified", true);
        event.addMetadata("effectiveRoles", List.of("ADMIN"));
        event.addMetadata("effectivePermissions", List.of("report.read"));
        event.addMetadata("authorizationEffect", "ALLOW");

        SecurityDecisionStandardPromptTemplate.SessionContext sessionContext = new SecurityDecisionStandardPromptTemplate.SessionContext();
        sessionContext.setUserId("alice");
        sessionContext.setSessionId("session-1");

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis round1 = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        round1.setBaselineContext("[NO_DATA] Baseline not loaded");
        round1.setPersonalBaselineAvailable(false);
        round1.setPersonalBaselineEstablished(false);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis round2 = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        round2.setBaselineContext("User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)");
        round2.setBaselineEstablished(true);
        round2.setPersonalBaselineAvailable(true);
        round2.setPersonalBaselineEstablished(false);
        round2.setBaselineUpdateCount(1L);

        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis round3 = new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        round3.setBaselineContext("User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)");
        round3.setBaselineEstablished(true);
        round3.setPersonalBaselineAvailable(true);
        round3.setPersonalBaselineEstablished(true);
        round3.setBaselineUpdateCount(5L);

        String round1Prompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(event, sessionContext, round1, List.of())), "");
        String round2Prompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        round2,
                        List.of(new Document("Round2: previously allowed access for the same sensitive resource")))), "");
        String round3Prompt = template.generateUserPrompt(new SecurityDecisionRequest(
                new SecurityDecisionContext(
                        event,
                        sessionContext,
                        round3,
                        List.of(
                                new Document("Round2: previously allowed access for the same sensitive resource"),
                                new Document("Round3: repeated follow-up access from the same session and environment")))), "");

        // 1차는 최초 접근이므로 RAG 비교 근거가 없어야 한다.
        assertThat(round1Prompt).doesNotContain("HistoricalComparableEvents:");
        // 2차는 1차에서 저장된 memory가 들어와야 하며, 기준선은 아직 잠정 상태여야 한다.
        assertThat(round2Prompt).contains("HistoricalComparableEvents:");
        assertThat(round2Prompt).contains("Provisional baseline evidence (learning in progress):");
        // 3차는 더 많은 memory를 활용해야 하며, 개인 기준선이 성숙했다면 established 상태로 승격되어야 한다.
        assertThat(round3Prompt).contains("HistoricalComparableEvents:");
        assertThat(round3Prompt).contains("Established baseline (from learned behavior):");
        assertThat(round3Prompt).doesNotContain("Provisional baseline evidence (learning in progress):");
        // 회차가 누적될수록 historical evidence는 줄어들면 안 된다. 줄어들면 RAG 회수나 저장 경로가 깨진 것이다.
        assertThat(countOccurrences(round2Prompt, "Round2:")).isGreaterThanOrEqualTo(1);
        assertThat(countOccurrences(round3Prompt, "Round")).isGreaterThanOrEqualTo(2);
    }

    private int countOccurrences(String text, String token) {
        int count = 0;
        int cursor = 0;
        while (cursor >= 0) {
            cursor = text.indexOf(token, cursor);
            if (cursor >= 0) {
                count++;
                cursor += token.length();
            }
        }
        return count;
    }
}
