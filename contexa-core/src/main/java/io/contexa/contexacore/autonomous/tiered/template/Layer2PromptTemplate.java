package io.contexa.contexacore.autonomous.tiered.template;

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
 * Layer 2: 컨텍스트 분석 프롬프트 템플릿 (최적화 버전)
 *
 * BeanOutputConverter 제거로 프롬프트 크기 대폭 감소:
 * - 변경 전: 2500+ 토큰 (JSON Schema 포함)
 * - 변경 후: 500 토큰 (80% 감소!)
 *
 * 예상 성능:
 * - Llama3.1:8b: 3-5초 → 100-300ms (15-50배 개선!)
 */
@Slf4j
public class Layer2PromptTemplate {

    private final SecurityEventEnricher eventEnricher;

    @Autowired
    public Layer2PromptTemplate(@Autowired(required = false) SecurityEventEnricher eventEnricher) {
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
    }

    public String buildPrompt(SecurityEvent event,
                               SecurityDecision layer1Decision,
                               SessionContext sessionContext,
                               BehaviorAnalysis behaviorAnalysis,
                               List<Document> relatedDocuments) {

        Optional<String> targetResource = eventEnricher.getTargetResource(event);
        Optional<String> httpMethod = eventEnricher.getHttpMethod(event);
        Optional<Object> payload = eventEnricher.getRequestPayload(event);

        // AI Native: "UNKNOWN" 기본값 제거, null 그대로 처리
        String eventType = event.getEventType() != null ? event.getEventType().toString() : null;
        String severity = event.getSeverity() != null ? event.getSeverity().name() : "MEDIUM";
        String payloadSummary = summarizePayload(payload.map(Object::toString).orElse(null));

        // Phase 5: metadata에서 authz 정보 추출 (Layer1 패턴 적용)
        String authzSection = buildAuthzSection(event);
        String networkSection = buildNetworkSection(event);
        int dataQuality = calculateDataQuality(event);

        // Layer1 결과 핵심만 (AI Native: "UNKNOWN" 기본값 제거)
        String actionStr = layer1Decision.getAction() != null ? layer1Decision.getAction().toString() : null;
        String layer1Summary = actionStr != null
            ? String.format("Risk: %.1f | Action: %s", layer1Decision.getRiskScore(), actionStr)
            : String.format("Risk: %.1f", layer1Decision.getRiskScore());

        // Session Context 핵심만 (AI Native: null 값 처리)
        String userId = sessionContext.getUserId();
        String accessPattern = sessionContext.getAccessPattern();
        StringBuilder sessionBuilder = new StringBuilder();
        if (userId != null) sessionBuilder.append("User: ").append(userId);
        sessionBuilder.append(" | Duration: ").append(sessionContext.getSessionDuration()).append("m");
        if (accessPattern != null) sessionBuilder.append(" | Pattern: ").append(accessPattern);
        String sessionSummary = sessionBuilder.toString();

        // Behavior 핵심만 - Phase 9: deviationScore 제거 (AI Native 위반)
        // AI Native 원칙: 플랫폼은 raw 데이터만 제공, LLM이 직접 판단
        String behaviorSummary = String.format("Similar Events: %d",
            behaviorAnalysis.getSimilarEvents().size());

        // AI Native (Phase 9): Baseline 컨텍스트 섹션
        // buildBaselinePromptContext()가 raw 데이터 제공 (Normal IPs, Current IP, Hours 등)
        // LLM이 직접 비교하여 ALLOW/BLOCK/ESCALATE 판단
        String baselineSection = (behaviorAnalysis.getBaselineContext() != null && !behaviorAnalysis.getBaselineContext().isEmpty())
            ? "=== USER BEHAVIOR BASELINE ===\n" + behaviorAnalysis.getBaselineContext()
            : "=== USER BEHAVIOR BASELINE ===\nBaseline: " + (behaviorAnalysis.isBaselineEstablished() ? "Available but not loaded" : "Not established (new user)");

        // Related Documents - 최대 5개까지 사용, 각 300자 제한
        // Phase 9: RAG 문서 메타데이터 포함 (유사도 점수, 문서 타입)
        StringBuilder relatedContextBuilder = new StringBuilder();
        int maxDocs = Math.min(5, relatedDocuments.size());
        for (int i = 0; i < maxDocs; i++) {
            Document doc = relatedDocuments.get(i);
            String content = doc.getText();
            if (content != null && !content.isBlank()) {
                if (i > 0) {
                    relatedContextBuilder.append("\n");
                }

                // 문서 메타데이터 추출
                String docMeta = buildDocumentMetadata(doc, i + 1);
                int maxLength = 300;
                String truncatedContent = content.length() > maxLength
                    ? content.substring(0, maxLength) + "..."
                    : content;

                relatedContextBuilder.append(docMeta).append(" ").append(truncatedContent);
            }
        }
        String relatedContext = relatedContextBuilder.length() > 0 ?
            relatedContextBuilder.toString() : "No related context found";

        // HCAD 유사도 분석 결과 추가
        String hcadSection = buildHCADSection(event);

        // Phase 9: deviationSection 제거 (AI Native 위반)
        // LLM이 baselineSection의 raw 데이터를 직접 비교하여 판단
        // AI Native v3.3.0: 4개 Action (ALLOW/BLOCK/CHALLENGE/ESCALATE)
        // Phase 5: metadata에서 추출한 풍부한 컨텍스트 정보 제공
        StringBuilder prompt = new StringBuilder();
        prompt.append("Contextual security analysis. Analyze with session/behavior patterns and user baseline.\n\n");

        // 1. 이벤트 기본 정보 (AI Native: null 값 조건부 출력)
        prompt.append("=== EVENT ===\n");
        if (eventType != null) {
            prompt.append("Type: ").append(eventType).append(" | Severity: ").append(severity).append("\n");
        } else {
            prompt.append("Severity: ").append(severity).append("\n");
        }
        if (userId != null) {
            prompt.append("User: ").append(userId).append("\n");
        }

        // 2. 네트워크 정보 (유효한 데이터만)
        if (!networkSection.isEmpty()) {
            prompt.append("\n=== NETWORK ===\n");
            prompt.append(networkSection).append("\n");
        }

        // 3. Authorization 정보 (metadata에서 추출)
        if (!authzSection.isEmpty()) {
            prompt.append("\n=== AUTHORIZATION ===\n");
            prompt.append(authzSection).append("\n");
        }

        // 4. 페이로드 정보 (있는 경우만)
        if (!"empty".equals(payloadSummary)) {
            prompt.append("\n=== PAYLOAD ===\n");
            prompt.append(payloadSummary).append("\n");
        }

        // 5. Layer1 분석 결과
        prompt.append("\n=== LAYER1 ANALYSIS ===\n");
        prompt.append(layer1Summary).append("\n");
        if (layer1Decision.getReasoning() != null && !layer1Decision.getReasoning().isEmpty()) {
            String reasoning = layer1Decision.getReasoning();
            if (reasoning.length() > 100) {
                reasoning = reasoning.substring(0, 97) + "...";
            }
            prompt.append("Reason: ").append(reasoning).append("\n");
        }

        // 6. 세션 컨텍스트 (Priority 1: authMethod, recentActions 추가)
        prompt.append("\n=== SESSION ===\n");
        prompt.append(sessionSummary).append("\n");
        // authMethod 추가 (Priority 1 Critical)
        String authMethod = sessionContext.getAuthMethod();
        if (isValidData(authMethod)) {
            prompt.append("AuthMethod: ").append(authMethod).append("\n");
        }
        // recentActions 추가 (Priority 1 Critical) - 최대 5개
        List<String> recentActions = sessionContext.getRecentActions();
        if (recentActions != null && !recentActions.isEmpty()) {
            int maxActions = Math.min(5, recentActions.size());
            String actionsStr = String.join(", ", recentActions.subList(
                Math.max(0, recentActions.size() - maxActions), recentActions.size()));
            prompt.append("RecentActions: [").append(actionsStr).append("]\n");
        }

        // 7. 행동 분석 (Priority 1: similarEvents 상세 내용 추가)
        prompt.append("\n=== BEHAVIOR ===\n");
        prompt.append(behaviorSummary).append("\n");
        // similarEvents 상세 내용 (Priority 1 Critical) - 최대 3개
        List<String> similarEvents = behaviorAnalysis.getSimilarEvents();
        if (similarEvents != null && !similarEvents.isEmpty()) {
            int maxEvents = Math.min(3, similarEvents.size());
            prompt.append("SimilarEvents Detail:\n");
            for (int i = 0; i < maxEvents; i++) {
                prompt.append("  ").append(i + 1).append(". ").append(similarEvents.get(i)).append("\n");
            }
        }

        // 8. 관련 문서 (RAG)
        if (!"No related context found".equals(relatedContext)) {
            prompt.append("\n=== RELATED CONTEXT ===\n");
            prompt.append(relatedContext).append("\n");
        }

        // 9. HCAD 분석
        prompt.append("\n").append(hcadSection).append("\n");

        // 10. 사용자 Baseline
        prompt.append("\n").append(baselineSection).append("\n");

        // 11. 데이터 품질 평가 (AI Native: 임계값 제거)
        // LLM이 데이터 필드 수를 보고 직접 신뢰도 결정
        prompt.append("\n=== DATA QUALITY ===\n");
        prompt.append("Available info: ").append(dataQuality).append("/10 fields\n");

        // 12. 응답 형식
        prompt.append("""

            === RESPONSE FORMAT ===
            {"r":<0-1>,"c":<0-1>,"a":"A|B|C|E","d":"<reason>"}
            r: riskScore (0.0=safe, 1.0=attack), based on baseline comparison
            c: confidence (0.0-1.0)
            a: Action (one of A/B/C/E)
            d: Brief reason (max 20 tokens)

            === ACTION GUIDE ===
            A (ALLOW): Safe - Normal pattern, matches baseline
            B (BLOCK): CRITICAL RISK - Confirmed attack, malicious payload, SQL injection, XSS
            C (CHALLENGE): HIGH RISK - Suspicious deviation from baseline. Requires MFA.
               Examples: [NEW_IP], [ODD_HOUR], [NEW_DEVICE], multiple failed attempts
            E (ESCALATE): Uncertain - Need expert analysis by Layer3

            KEY: B=Definite threat | C=Baseline deviation, needs MFA | E=Need expert review
            """);

        return prompt.toString();
    }

    /**
     * RAG 문서 메타데이터 추출 (Phase 9)
     *
     * 문서 메타데이터를 [Doc1|sim=0.92|type=threat] 형식으로 반환
     * - sim: 유사도 점수 (벡터 검색 결과)
     * - type: 문서 타입 (threat, incident, behavior, policy 등)
     *
     * @param doc RAG 검색 결과 문서
     * @param docIndex 문서 순번
     * @return 메타데이터 포맷 문자열
     */
    private String buildDocumentMetadata(Document doc, int docIndex) {
        StringBuilder meta = new StringBuilder();
        meta.append("[Doc").append(docIndex);

        // 유사도 점수 추출
        if (doc.getMetadata() != null) {
            // Spring AI Document의 score 필드 또는 메타데이터에서 유사도 추출
            Object scoreObj = doc.getMetadata().get("score");
            if (scoreObj == null) {
                scoreObj = doc.getMetadata().get("similarity_score");
            }
            if (scoreObj == null) {
                scoreObj = doc.getMetadata().get("distance");
            }

            if (scoreObj instanceof Number) {
                double score = ((Number) scoreObj).doubleValue();
                meta.append("|sim=").append(String.format("%.2f", score));
            }

            // 문서 타입 추출
            Object typeObj = doc.getMetadata().get("type");
            if (typeObj == null) {
                typeObj = doc.getMetadata().get("document_type");
            }
            if (typeObj == null) {
                typeObj = doc.getMetadata().get("category");
            }

            if (typeObj != null) {
                meta.append("|type=").append(typeObj.toString());
            }

            // 소스 정보 (있는 경우)
            Object sourceObj = doc.getMetadata().get("source");
            if (sourceObj != null) {
                String source = sourceObj.toString();
                // 소스가 너무 길면 축약
                if (source.length() > 20) {
                    source = source.substring(0, 17) + "...";
                }
                meta.append("|src=").append(source);
            }
        }

        meta.append("]");
        return meta.toString();
    }

    /**
     * HCAD 위험도 분석 결과 섹션 구성 (AI Native)
     *
     * AI Native 원칙:
     * - 플랫폼은 raw 데이터만 제공
     * - 임계값 기반 판단(assessment) 제거
     * - LLM이 riskScore를 해석하고 action을 직접 결정
     */
    private String buildHCADSection(SecurityEvent event) {
        // AI Native: SecurityEvent.riskScore 필드 제거됨
        // HCAD 분석 결과는 ThreatAssessment에서 관리
        // LLM이 세션/행동 컨텍스트를 직접 분석하여 위험도 결정
        return "HCAD Analysis: LLM analysis with session/behavior context required";
    }

    private String summarizePayload(String payload) {
        if (payload == null || payload.isEmpty()) {
            return "empty";
        }
        if (payload.length() > 300) {
            return payload.substring(0, 300) + "... (truncated)";
        }
        return payload;
    }

    /**
     * Phase 5: metadata에서 Authorization 정보 추출 (Layer1 패턴 적용)
     *
     * authz.resource, authz.action, authz.result, authz.reason,
     * methodClass, methodName 등 풍부한 컨텍스트 정보 제공
     */
    private String buildAuthzSection(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return "";
        }

        StringBuilder authz = new StringBuilder();

        // authz.resource - 접근 대상 리소스
        String authzResource = getStringFromMetadata(metadata, "authz.resource");
        if (isValidData(authzResource)) {
            authz.append("Resource: ").append(authzResource).append("\n");
        }

        // methodClass, methodName - 호출된 메서드 정보
        String methodClass = getStringFromMetadata(metadata, "methodClass");
        String methodName = getStringFromMetadata(metadata, "methodName");
        if (isValidData(methodClass) || isValidData(methodName)) {
            String classSimpleName = extractSimpleClassName(methodClass);
            authz.append("Method: ").append(classSimpleName).append(".").append(methodName).append("\n");
        }

        // authz.action - 수행 액션
        String authzAction = getStringFromMetadata(metadata, "authz.action");
        if (isValidData(authzAction)) {
            authz.append("Action: ").append(authzAction).append("\n");
        }

        // authz.result - 인가 결과
        String authzResult = getStringFromMetadata(metadata, "authz.result");
        if (isValidData(authzResult)) {
            authz.append("Result: ").append(authzResult).append("\n");
        }

        // authz.reason - 거부 이유 (있는 경우)
        String authzReason = getStringFromMetadata(metadata, "authz.reason");
        if (isValidData(authzReason)) {
            // 이유가 너무 길면 요약
            if (authzReason.length() > 80) {
                authzReason = authzReason.substring(0, 77) + "...";
            }
            authz.append("Reason: ").append(authzReason).append("\n");
        }

        return authz.toString().trim();
    }

    /**
     * 네트워크 정보 섹션 구성 (유효한 데이터만)
     */
    private String buildNetworkSection(SecurityEvent event) {
        StringBuilder network = new StringBuilder();

        if (isValidData(event.getSourceIp())) {
            network.append("IP: ").append(event.getSourceIp()).append("\n");
        }

        if (isValidData(event.getUserAgent())) {
            String ua = event.getUserAgent();
            if (ua.length() > 80) {
                ua = ua.substring(0, 77) + "...";
            }
            network.append("UserAgent: ").append(ua).append("\n");
        }

        // targetResource, httpMethod는 eventEnricher에서 추출
        Optional<String> targetResource = eventEnricher.getTargetResource(event);
        Optional<String> httpMethod = eventEnricher.getHttpMethod(event);

        if (targetResource.isPresent() && isValidData(targetResource.get())) {
            network.append("Target: ").append(targetResource.get()).append("\n");
        }

        if (httpMethod.isPresent() && isValidData(httpMethod.get())) {
            network.append("Method: ").append(httpMethod.get()).append("\n");
        }

        return network.toString().trim();
    }

    /**
     * 데이터가 유효한지 검사 (null, empty, "unknown" 제외)
     */
    private boolean isValidData(String value) {
        return value != null && !value.isEmpty() && !value.equalsIgnoreCase("unknown");
    }

    /**
     * metadata에서 문자열 값 안전하게 추출 (AI Native)
     *
     * AI Native 원칙: 기본값 "unknown" 제거
     * - 값이 없으면 null 반환
     * - 호출부에서 null 체크 후 프롬프트 생략
     * - LLM이 "unknown" 문자열을 실제 데이터로 오인하는 문제 방지
     */
    private String getStringFromMetadata(Map<String, Object> metadata, String key) {
        Object value = metadata.get(key);
        if (value == null) {
            return null;
        }
        String strValue = value.toString();
        return strValue.isEmpty() ? null : strValue;
    }

    /**
     * 클래스 풀네임에서 심플 클래스명 추출 (AI Native)
     * 예: "io.contexa.service.TestService" -> "TestService"
     *
     * AI Native 원칙: 기본값 "unknown" 제거
     * - 값이 없으면 null 반환
     */
    private String extractSimpleClassName(String fullClassName) {
        if (fullClassName == null || fullClassName.isEmpty()) {
            return null;
        }
        int lastDot = fullClassName.lastIndexOf('.');
        if (lastDot >= 0 && lastDot < fullClassName.length() - 1) {
            return fullClassName.substring(lastDot + 1);
        }
        return fullClassName;
    }

    /**
     * 데이터 품질 점수 계산 (0-10)
     * LLM이 판단의 신뢰도를 조절하는 데 참고
     */
    private int calculateDataQuality(SecurityEvent event) {
        int score = 0;

        // 필수 정보
        if (event.getEventType() != null) score++;
        if (event.getSeverity() != null) score++;
        if (isValidData(event.getUserId())) score++;
        if (isValidData(event.getSourceIp())) score++;
        if (isValidData(event.getUserAgent())) score++;

        // 추가 정보
        if (isValidData(event.getSessionId())) score++;
        if (isValidData(event.getTargetResource())) score++;
        if (event.getTimestamp() != null) score++;

        // metadata 정보
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && !metadata.isEmpty()) {
            if (metadata.containsKey("authz.resource")) score++;
            if (metadata.containsKey("methodClass")) score++;
        }

        return Math.min(10, score);
    }

    /**
     * SessionContext - AI Native
     *
     * AI Native 원칙: 기본값 "unknown" 제거
     * - 값이 없으면 null 반환
     * - 호출부에서 null 체크 후 프롬프트 생략
     */
    public static class SessionContext {
        private String sessionId;
        private String userId;
        private String authMethod;
        private List<String> recentActions;
        private long sessionDuration;
        private String accessPattern;

        // AI Native: 기본값 없이 null 반환
        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getAuthMethod() { return authMethod; }
        public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

        public List<String> getRecentActions() { return recentActions != null ? recentActions : List.of(); }
        public void setRecentActions(List<String> recentActions) { this.recentActions = recentActions; }

        public long getSessionDuration() { return sessionDuration; }
        public void setSessionDuration(long sessionDuration) { this.sessionDuration = sessionDuration; }

        public String getAccessPattern() { return accessPattern; }
        public void setAccessPattern(String accessPattern) { this.accessPattern = accessPattern; }
    }

    /**
     * 행동 분석 결과 - AI Native (v4.0)
     *
     * Phase 8 리팩토링: 점수 기반 필드 제거
     * - normalBehaviorScore 제거: 플랫폼 계산 점수 (AI Native 위반)
     * - anomalyIndicators 제거: detectAnomalies() 제거로 미사용
     * - temporalPattern 제거: analyzeTemporalPattern() 제거로 미사용
     *
     * Phase 9 리팩토링: 추가 점수 기반 필드 제거
     * - deviationAnalysis 제거: analyzeDeviations() 제거로 미사용
     * - deviationScore 제거: calculateDeviationScore() 제거로 미사용
     *
     * AI Native 원칙: 플랫폼은 raw 데이터만 제공, LLM이 직접 판단
     */
    public static class BehaviorAnalysis {
        private List<String> similarEvents;

        // AI Native (Phase 9): Baseline 상세 정보 필드
        // buildBaselinePromptContext()가 raw 데이터 제공 (Normal IPs, Current IP, Hours 등)
        private String baselineContext;
        // baseline 존재 여부
        private boolean baselineEstablished;

        public List<String> getSimilarEvents() { return similarEvents != null ? similarEvents : List.of(); }
        public void setSimilarEvents(List<String> events) { this.similarEvents = events; }

        // AI Native: Baseline 필드 Getter/Setter
        public String getBaselineContext() { return baselineContext; }
        public void setBaselineContext(String baselineContext) { this.baselineContext = baselineContext; }

        public boolean isBaselineEstablished() { return baselineEstablished; }
        public void setBaselineEstablished(boolean baselineEstablished) { this.baselineEstablished = baselineEstablished; }
    }
}