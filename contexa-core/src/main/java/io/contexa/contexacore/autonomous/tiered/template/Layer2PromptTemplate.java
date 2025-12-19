package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
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

        String eventType = event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN";
        String sourceIp = event.getSourceIp() != null ? event.getSourceIp() : "unknown";
        String userAgent = event.getUserAgent() != null ? event.getUserAgent() : "unknown";
        String target = targetResource.orElse("unknown");
        String method = httpMethod.orElse("unknown");
        String payloadSummary = summarizePayload(payload.map(Object::toString).orElse(null));

        // Layer1 결과 핵심만
        String layer1Summary = String.format("Risk: %.1f | Action: %s",
            layer1Decision.getRiskScore(),
            layer1Decision.getAction() != null ? layer1Decision.getAction().toString() : "UNKNOWN");

        // Session Context 핵심만
        String sessionSummary = String.format("User: %s | Duration: %dm | Pattern: %s",
            sessionContext.getUserId(),
            sessionContext.getSessionDuration(),
            sessionContext.getAccessPattern());

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
        return String.format("""
            Contextual security analysis. Analyze with session/behavior patterns and user baseline.

            Event: %s | IP: %s | UA: %s | Target: %s | Method: %s | Payload: %s
            Layer1: %s
            Session: %s
            Behavior: %s
            Context: %s
            %s

            %s

            RULES:
            - ZERO TRUST: Unknown != Safe. Verify everything.
            - Analyze baseline raw data (Normal IPs vs Current IP, Normal Hours vs Current Hour)
            - Determine action (ALLOW/BLOCK/ESCALATE) based on deviation from baseline

            Response: JSON only, max 20 tokens for "d" field
            {"r":<0-1>,"c":<0-1>,"a":"A|E|B","d":"<20 tokens max>"}

            Fields:
            r: riskScore (0.0=safe, 1.0=attack), based on baseline comparison
            c: confidence (0.0-1.0)
            a: A=Allow, E=Escalate, B=Block
            d: Brief reason (max 20 tokens, include [NEW_IP] or [ODD_HOUR] if baseline deviation)
            """,
            eventType, sourceIp, userAgent, target, method, payloadSummary,
            layer1Summary, sessionSummary, behaviorSummary, relatedContext, hcadSection,
            baselineSection);
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
        Double riskScore = event.getRiskScore();

        if (riskScore == null || Double.isNaN(riskScore)) {
            return "HCAD Analysis: Not available (requires LLM analysis)";
        }

        // AI Native: raw 데이터만 제공, 임계값 기반 assessment 제거
        // LLM이 riskScore를 해석하여 action(ALLOW/BLOCK/ESCALATE/INVESTIGATE)을 결정
        return String.format("""
            HCAD Risk Analysis:
            - Risk Score: %.3f
            - Determine action based on this score and session/behavior context""",
            riskScore
        );
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

    public static class SessionContext {
        private String sessionId;
        private String userId;
        private String authMethod;
        private List<String> recentActions;
        private long sessionDuration;
        private String accessPattern;

        public String getSessionId() { return sessionId != null ? sessionId : "unknown"; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        public String getUserId() { return userId != null ? userId : "unknown"; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getAuthMethod() { return authMethod != null ? authMethod : "unknown"; }
        public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

        public List<String> getRecentActions() { return recentActions != null ? recentActions : List.of(); }
        public void setRecentActions(List<String> recentActions) { this.recentActions = recentActions; }

        public long getSessionDuration() { return sessionDuration; }
        public void setSessionDuration(long sessionDuration) { this.sessionDuration = sessionDuration; }

        public String getAccessPattern() { return accessPattern != null ? accessPattern : "unknown"; }
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