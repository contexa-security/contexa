package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Layer 2: 전문가 분석 프롬프트 템플릿 (최적화 버전)
 *
 * v5.1.0: 플랫폼 명제 기반 리팩토링
 * - THREAT INTELLIGENCE 섹션 제거 (익명 공격자 탐지용 - 플랫폼 역할 아님)
 * - createIncident 필드 제거 (미사용)
 * - userId 중복 제거 (토큰 효율화)
 * - Layer2 결과 표시 제거 (항상 기본값)
 *
 * 플랫폼 핵심 명제:
 * "인증에 성공하더라도 이 사용자가 공격자인지를 계속 탐지하는 제로트러스트"
 * - 인증된 사용자 검증에 포커스
 * - 익명 공격자 탐지는 플랫폼 역할 아님 (APT, Campaign 등)
 */
@Slf4j
public class Layer2PromptTemplate {

    private final SecurityEventEnricher eventEnricher;
    private final TieredStrategyProperties tieredStrategyProperties;

    @Autowired
    public Layer2PromptTemplate(
            @Autowired(required = false) SecurityEventEnricher eventEnricher,
            @Autowired(required = false) TieredStrategyProperties tieredStrategyProperties) {
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.tieredStrategyProperties = tieredStrategyProperties != null
            ? tieredStrategyProperties : new TieredStrategyProperties();
    }

    /**
     * AI Native v5.1.0: Layer2 프롬프트 생성 (플랫폼 명제 기반 최적화)
     *
     * Layer2도 Layer1과 동일한 원본 데이터를 직접 분석하여 독립적인 검증 수행.
     * 다른 AI 모델이 동일한 데이터를 분석하여 편향 없는 다중 검증 가능.
     *
     * v5.1.0 변경사항:
     * - threatIntel 파라미터 제거 (익명 공격자 탐지용 - 플랫폼 역할 아님)
     * - THREAT INTELLIGENCE 섹션 제거
     * - Layer2 결과 표시 제거 (항상 기본값)
     *
     * @param event 보안 이벤트
     * @param sessionContext 세션 컨텍스트 (Layer1 원본 데이터)
     * @param behaviorAnalysis 행동 분석 (Layer1 원본 데이터)
     * @param relatedDocuments RAG 관련 문서 (Layer1 원본 데이터)
     * @param historicalContext 과거 이력 컨텍스트 (Layer2 전용)
     * @param layer1Decision Layer1 결정 (참고용, 편향 방지)
     * @return LLM 프롬프트 문자열
     */
    public String buildPrompt(SecurityEvent event,
                               SessionContext sessionContext,
                               BehaviorAnalysis behaviorAnalysis,
                               List<Document> relatedDocuments,
                               HistoricalContext historicalContext,
                               SecurityDecision layer1Decision) {

        Optional<String> decodedPayload = eventEnricher.getDecodedPayload(event);
        String userId = PromptTemplateUtils.sanitizeUserInput(event.getUserId());
        String fullPayload = PromptTemplateUtils.sanitizeUserInput(decodedPayload.orElse("empty"));

        // Truncation 정책 적용 (Layer2 설정 사용)
        TieredStrategyProperties.Truncation.Layer2Truncation layer2Truncation =
            tieredStrategyProperties.getTruncation().getLayer2();

        StringBuilder prompt = new StringBuilder();
        prompt.append("Expert forensic security analysis with independent verification.\n");
        prompt.append("Analyze raw data directly - previous layer results are for reference only.\n\n");

        // 1. 이벤트 기본 정보
        // AI Native v5.1.0: userId를 EVENT 섹션에 출력 (Layer1과 동일)
        prompt.append("=== EVENT ===\n");
        if (userId != null && !userId.isEmpty()) {
            prompt.append("User: ").append(userId).append("\n");
        }

        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null) {
            appendMetadataIfPresent(prompt, metadata, "auth.failure_count", "FailureCount");
        }

        // 2. 네트워크 정보 (Zero Trust)
        prompt.append("\n=== NETWORK ===\n");
        prompt.append(buildNetworkSection(event)).append("\n");

        // 3. 페이로드 정보
        if (!"empty".equals(fullPayload)) {
            prompt.append("\n=== PAYLOAD ===\n");
            int maxPayload = layer2Truncation.getPayload();
            String payloadSummary = fullPayload.length() > maxPayload
                ? fullPayload.substring(0, maxPayload) + "..." : fullPayload;
            prompt.append(payloadSummary).append("\n");
        }

        // 4. 세션 컨텍스트 (Layer1 원본 데이터)
        // AI Native v5.1.0: userId 중복 제거 - event.getUserId()로 이미 조회됨 (Line 71)
        prompt.append("\n=== SESSION CONTEXT ===\n");
        if (sessionContext != null) {
            if (sessionContext.getSessionId() != null) {
                prompt.append("SessionId: ").append(sessionContext.getSessionId()).append("\n");
            }
            // userId는 event에서 이미 조회됨 - 중복 출력 제거
            if (sessionContext.getAuthMethod() != null) {
                prompt.append("AuthMethod: ").append(sessionContext.getAuthMethod()).append("\n");
            }
            if (sessionContext.getRecentActions() != null && !sessionContext.getRecentActions().isEmpty()) {
                prompt.append("RecentActions: ").append(String.join(", ", sessionContext.getRecentActions())).append("\n");
            }
        } else {
            prompt.append("[NO_DATA] Session context unavailable\n");
        }

        // 5. 행동 분석 (Layer1 원본 데이터)
        prompt.append("\n=== BEHAVIOR ANALYSIS ===\n");
        if (behaviorAnalysis != null) {
            if (behaviorAnalysis.getSimilarEvents() != null && !behaviorAnalysis.getSimilarEvents().isEmpty()) {
                prompt.append("SimilarEvents: ").append(String.join(", ", behaviorAnalysis.getSimilarEvents())).append("\n");
            }
            prompt.append("BaselineStatus: ").append(behaviorAnalysis.isBaselineEstablished() ? "Available" : "Not established").append("\n");
            if (behaviorAnalysis.getBaselineContext() != null) {
                String sanitizedBaseline = PromptTemplateUtils.sanitizeUserInput(behaviorAnalysis.getBaselineContext());
                prompt.append("BaselineContext: ").append(sanitizedBaseline).append("\n");
            }
        } else {
            prompt.append("[NO_DATA] Behavior analysis unavailable\n");
        }

        // 6. RAG 관련 문서 (Layer1 원본 데이터)
        prompt.append("\n=== RELATED DOCUMENTS (RAG) ===\n");
        if (relatedDocuments != null && !relatedDocuments.isEmpty()) {
            int docCount = 0;
            int maxDocs = 5;
            for (Document doc : relatedDocuments) {
                if (docCount >= maxDocs) break;
                String content = doc.getText();
                if (content != null && !content.isEmpty()) {
                    int maxDocContent = 150;
                    String docSummary = content.length() > maxDocContent
                        ? content.substring(0, maxDocContent) + "..." : content;
                    prompt.append("- ").append(docSummary).append("\n");
                    docCount++;
                }
            }
        } else {
            prompt.append("[NO_DATA] No related documents found\n");
        }

        // v5.1.0: THREAT INTELLIGENCE 섹션 제거
        // - 익명 공격자 탐지용 (APT29, Lazarus 등) - 플랫폼 역할 아님
        // - 플랫폼 핵심: "인증된 사용자가 진짜인가?" 검증
        // - threatIntel 파라미터도 제거됨

        // 7. 사용자 이력 (AI Native v5.1.0: IP -> userId 기반으로 변경)
        // 플랫폼 명제: "인증된 사용자가 진짜인가?" 검증
        // - IP 기반이 아닌 userId 기반으로 과거 BLOCK/CHALLENGE 이력 제공
        prompt.append("\n=== USER HISTORY ===\n");
        StringBuilder historyBuilder = new StringBuilder();
        if (historicalContext != null) {
            // 이 사용자의 과거 BLOCK 횟수 (userId 기반)
            if (historicalContext.getPreviousAttacks() > 0) {
                historyBuilder.append("Previous BLOCKs: ")
                        .append(historicalContext.getPreviousAttacks())
                        .append(" (as this user)");
            }
            // 이 사용자의 과거 CHALLENGE 횟수 (userId 기반)
            if (historicalContext.getPreviousChallenges() > 0) {
                if (historyBuilder.length() > 0) historyBuilder.append(" | ");
                historyBuilder.append("Previous CHALLENGEs: ")
                        .append(historicalContext.getPreviousChallenges())
                        .append(" (as this user)");
            }
            // 유사 인시던트
            if (historicalContext.getSimilarIncidents() != null && !historicalContext.getSimilarIncidents().isEmpty()) {
                if (historyBuilder.length() > 0) historyBuilder.append(" | ");
                historyBuilder.append("Similar: ").append(String.join(", ", historicalContext.getSimilarIncidents()));
            }
        }
        if (historyBuilder.length() > 0) {
            prompt.append(historyBuilder).append("\n");
        } else {
            prompt.append("[NO_DATA] No user history available\n");
        }

        // 9. 데이터 품질 평가
        prompt.append("\n=== DATA QUALITY ===\n");
        String dataQualitySection = PromptTemplateUtils.buildDataQualitySection(event,
            behaviorAnalysis != null ? behaviorAnalysis.getBaselineContext() : null);
        prompt.append(dataQualitySection);

        // 9. 이전 레이어 분석 결과 (Layer1만 - 참고용)
        // v5.1.0: Layer2 결과 표시 제거 (분석 전이므로 항상 기본값)
        prompt.append("\n=== PREVIOUS LAYER ANALYSIS (Reference Only) ===\n");
        prompt.append("Note: Use raw data above for independent analysis. Layer1 result is for reference only.\n");

        // Layer1 결과만 표시
        double l1RiskScore = layer1Decision.getRiskScore();
        String l1RiskStr = Double.isNaN(l1RiskScore) ? "[NOT_ANALYZED]" : String.format("%.2f", l1RiskScore);
        prompt.append("Layer1: Risk=").append(l1RiskStr);
        if (layer1Decision.getAction() != null) {
            prompt.append(" | Action=").append(layer1Decision.getAction().toString());
        }
        Double l1Confidence = layer1Decision.getConfidence();
        if (l1Confidence != null && !l1Confidence.isNaN()) {
            prompt.append(" | Confidence=").append(String.format("%.2f", l1Confidence));
        }
        prompt.append("\n");

        // 10. 응답 형식 (v5.1.0: createIncident 필드 제거 - 미사용)
        prompt.append("""

            === ACTIONS ===
            ALLOW: Permit the request
            BLOCK: Deny the request
            CHALLENGE: Request additional verification (MFA)
            ESCALATE: Requires human security analyst review

            === RESPONSE FORMAT ===
            {"riskScore":<0-1>,"confidence":<0-1>,"action":"ALLOW|BLOCK|CHALLENGE|ESCALATE","reasoning":"<reason>","mitre":"<MITRE>","recommendation":"<recommendation>"}

            riskScore: Your risk assessment (0=safe, 1=critical threat)
            confidence: Your confidence level (0=uncertain, 1=certain)
            action: Your action decision
            reasoning: Detailed reasoning (max 50 tokens)
            mitre: MITRE ATT&CK technique if applicable (e.g., T1078, T1566)
            recommendation: Recommendation for SOC (max 20 tokens)
            """);

        return prompt.toString();
    }

    // AI Native v5.0.0: buildPrompt(5-param) 및 buildPromptLegacy() 삭제
    // - Inner Class 타입 변경 (String -> List<String>)으로 인한 비호환
    // - 새로운 buildPrompt(8-param) 메서드로 대체됨

    /**
     * 네트워크 정보 섹션 구성 (Zero Trust: 필수 필드 누락 시 경고)
     *
     * AI Native + Zero Trust 원칙:
     * - IP, SessionId는 검증 필수 필드
     * - 누락 시 NOT_PROVIDED [CRITICAL] 표시
     * - LLM이 데이터 부재를 인식하여 CHALLENGE/ESCALATE 판단
     *
     * AI Native v3.3.0: 프롬프트 인젝션 방어
     * - 모든 사용자 입력값은 sanitizeUserInput()으로 새니타이징
     */
    private String buildNetworkSection(SecurityEvent event) {
        StringBuilder network = new StringBuilder();

        // IP (Zero Trust Critical) - 프롬프트 인젝션 방어 적용
        if (isValidData(event.getSourceIp())) {
            String sanitizedIp = PromptTemplateUtils.sanitizeUserInput(event.getSourceIp());
            network.append("IP: ").append(sanitizedIp).append("\n");
        } else {
            network.append("IP: NOT_PROVIDED [CRITICAL: Cannot verify origin]\n");
        }

        // SessionId (Zero Trust Critical) - 프롬프트 인젝션 방어 적용
        if (isValidData(event.getSessionId())) {
            String sanitizedSessionId = PromptTemplateUtils.sanitizeUserInput(event.getSessionId());
            network.append("SessionId: ").append(sanitizedSessionId).append("\n");
        } else {
            network.append("SessionId: NOT_PROVIDED [CRITICAL: Cannot verify session]\n");
        }

        // UserAgent (선택) - 프롬프트 인젝션 방어 적용
        if (isValidData(event.getUserAgent())) {
            String ua = PromptTemplateUtils.sanitizeUserInput(event.getUserAgent());
            int maxUserAgent = tieredStrategyProperties.getTruncation().getLayer2().getUserAgent();
            if (ua.length() > maxUserAgent) {
                ua = ua.substring(0, maxUserAgent - 3) + "...";
            }
            network.append("UserAgent: ").append(ua).append("\n");
        }

        return network.toString().trim();
    }

    /**
     * 데이터가 유효한지 검사 (null, empty, "unknown" 제외)
     * PromptTemplateUtils로 위임
     */
    private boolean isValidData(String value) {
        return PromptTemplateUtils.isValidData(value);
    }

    // AI Native v5.0.0: getStringFromMetadata(), extractSimpleClassName(), calculateDataQuality() 삭제
    // - PromptTemplateUtils에 위임하는 wrapper 메서드들 (호출부 없음)
    // - 직접 PromptTemplateUtils 사용으로 대체됨

    /**
     * AI Native v4.1.0: metadata에서 값을 추출하여 프롬프트에 추가
     * Severity 대신 원시 메트릭을 LLM에게 제공
     *
     * @param sb 프롬프트 StringBuilder
     * @param metadata 이벤트 메타데이터
     * @param metadataKey metadata에서 조회할 키
     * @param promptLabel 프롬프트에 표시할 라벨
     */
    private void appendMetadataIfPresent(StringBuilder sb, Map<String, Object> metadata, String metadataKey, String promptLabel) {
        if (metadata == null) {
            return;
        }
        Object value = metadata.get(metadataKey);
        if (value != null) {
            sb.append(promptLabel).append(": ").append(value).append("\n");
        }
    }

    // AI Native v5.0.0: isValidBaseline() 삭제 - buildPromptLegacy() 삭제로 인한 Dead Code

    /**
     * AI Native v5.0.0: 세션 컨텍스트 (신규)
     * Layer2도 원본 데이터를 직접 분석하여 독립적인 검증 수행
     */
    public static class SessionContext {
        private String sessionId;
        private String userId;
        private String authMethod;
        private java.util.List<String> recentActions;

        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getAuthMethod() { return authMethod; }
        public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

        public java.util.List<String> getRecentActions() { return recentActions; }
        public void setRecentActions(java.util.List<String> recentActions) { this.recentActions = recentActions; }
    }

    /**
     * AI Native v5.0.0: 행동 분석 (신규)
     * Layer2도 원본 데이터를 직접 분석하여 독립적인 검증 수행
     */
    public static class BehaviorAnalysis {
        private java.util.List<String> similarEvents;
        private String baselineContext;
        private boolean baselineEstablished;

        public java.util.List<String> getSimilarEvents() { return similarEvents; }
        public void setSimilarEvents(java.util.List<String> events) { this.similarEvents = events; }

        public String getBaselineContext() { return baselineContext; }
        public void setBaselineContext(String baselineContext) { this.baselineContext = baselineContext; }

        public boolean isBaselineEstablished() { return baselineEstablished; }
        public void setBaselineEstablished(boolean baselineEstablished) { this.baselineEstablished = baselineEstablished; }
    }

    // v5.1.0: ThreatIntelligence 클래스 삭제
    // - 익명 공격자 탐지용 (APT29, Lazarus 등) - 플랫폼 역할 아님
    // - buildPrompt()에서 threatIntel 파라미터 및 THREAT INTELLIGENCE 섹션 제거됨
    // - 플랫폼 핵심: "인증된 사용자가 진짜인가?" 검증

    /**
     * AI Native v5.0.0: HistoricalContext - 타입 변경 (String -> List<String>, int)
     *
     * AI Native 원칙: 기본값 "none" 제거
     * - 값이 없으면 null 반환
     * - 호출부에서 null 체크 후 프롬프트 생략
     * - Strategy에서 List<String>으로 관리하여 타입 일관성 유지
     */
    /**
     * AI Native v5.1.0: 과거 이력 컨텍스트
     *
     * 플랫폼 명제: "인증된 사용자가 진짜인가?" 검증
     * - previousAttacks: 이 사용자의 과거 BLOCK 횟수 (IP가 아닌 userId 기반)
     * - previousChallenges: 이 사용자의 과거 CHALLENGE 횟수
     */
    public static class HistoricalContext {
        private java.util.List<String> similarIncidents;
        private int previousAttacks;  // userId 기반 과거 BLOCK 횟수
        private int previousChallenges;  // userId 기반 과거 CHALLENGE 횟수

        public java.util.List<String> getSimilarIncidents() { return similarIncidents; }
        public void setSimilarIncidents(java.util.List<String> similarIncidents) { this.similarIncidents = similarIncidents; }

        public int getPreviousAttacks() { return previousAttacks; }
        public void setPreviousAttacks(int previousAttacks) { this.previousAttacks = previousAttacks; }

        public int getPreviousChallenges() { return previousChallenges; }
        public void setPreviousChallenges(int previousChallenges) { this.previousChallenges = previousChallenges; }
    }

    // AI Native v4.2.0: SystemContext 클래스 삭제
    // - asset.criticality, data.sensitivity, compliance.requirements, security.posture
    //   모두 metadata에 설정 코드 없음 (항상 null, 죽은 데이터)
    // - buildPrompt()에서 프롬프트에 포함되지 않음 (Line 247 주석 참조)
    // - LLM이 targetResource 경로를 보고 직접 판단
}