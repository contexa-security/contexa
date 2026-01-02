package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Layer 1: 컨텍스트 분석 프롬프트 템플릿 (최적화 버전)
 *
 * BeanOutputConverter 제거로 프롬프트 크기 대폭 감소:
 * - 변경 전: 2500+ 토큰 (JSON Schema 포함)
 * - 변경 후: 500 토큰 (80% 감소!)
 *
 * 예상 성능:
 * - Llama3.1:8b: 3-5초 → 100-300ms (15-50배 개선!)
 */
@Slf4j
public class Layer1PromptTemplate {

    private final SecurityEventEnricher eventEnricher;
    private final TieredStrategyProperties tieredStrategyProperties;

    @Autowired
    public Layer1PromptTemplate(
            @Autowired(required = false) SecurityEventEnricher eventEnricher,
            @Autowired(required = false) TieredStrategyProperties tieredStrategyProperties) {
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.tieredStrategyProperties = tieredStrategyProperties != null
            ? tieredStrategyProperties : new TieredStrategyProperties();
    }

    public String buildPrompt(SecurityEvent event,
                               SessionContext sessionContext,
                               BehaviorAnalysis behaviorAnalysis,
                               List<Document> relatedDocuments) {

        Optional<String> httpMethod = eventEnricher.getHttpMethod(event);
        // Phase 4: getDecodedPayload() 사용 (Base64/URL 인코딩 자동 디코딩)
        Optional<String> decodedPayload = eventEnricher.getDecodedPayload(event);

        // AI Native v4.1.0: Severity 변수 제거 - LLM이 원시 데이터로 직접 판단
        String payloadSummary = summarizePayload(decodedPayload.orElse(null));

        String networkSection = buildNetworkSection(event);
        // Phase 22: buildDataQualitySection() 사용 - 누락 필드 명시적 표시
        String dataQualitySection = PromptTemplateUtils.buildDataQualitySection(event);

        // Session Context 핵심만 (AI Native: null 값 처리)
        // AI Native v3.0: accessPattern 제거 - "AccessFrequency: N" 형식만 제공하여 혼란 유발
        // AI Native v4.0: sessionDuration 제거 - isNewSession + recentRequestCount로 대체 가능한 중복 데이터
        // recentActions가 실제 행동 정보 제공
        String userId = sessionContext.getUserId();
        StringBuilder sessionBuilder = new StringBuilder();
        if (userId != null) sessionBuilder.append("User: ").append(userId);
        String sessionSummary = sessionBuilder.toString();

        // Behavior 핵심만 - Phase 9: deviationScore 제거 (AI Native 위반)
        // AI Native 원칙: 플랫폼은 raw 데이터만 제공, LLM이 직접 판단
        String behaviorSummary = String.format("Similar Events: %d",
            behaviorAnalysis.getSimilarEvents().size());

        // AI Native v4.0: Baseline 컨텍스트 섹션 (항상 출력 - Zero Trust)
        // STATUS 라벨 추가: 상태 메시지와 실제 데이터를 명확히 구분하여 LLM 오인 방지
        // buildBaselinePromptContext()가 raw 데이터 제공 (Normal IPs, Current IP, Hours 등)
        // LLM이 직접 비교하여 ALLOW/BLOCK/ESCALATE 판단
        StringBuilder baselineSectionBuilder = new StringBuilder();
        baselineSectionBuilder.append("=== USER BEHAVIOR BASELINE ===\n");
        String baselineContext = behaviorAnalysis.getBaselineContext();
        if (isValidBaseline(baselineContext)) {
            // 유효한 baseline 데이터 - sanitization 적용
            String sanitizedBaseline = PromptTemplateUtils.sanitizeUserInput(baselineContext);
            baselineSectionBuilder.append("STATUS: Available\n");
            baselineSectionBuilder.append(sanitizedBaseline);
        } else if (baselineContext != null && baselineContext.startsWith("[")) {
            // 상태 메시지 (SERVICE_UNAVAILABLE, NO_USER_ID, NO_DATA)
            baselineSectionBuilder.append("STATUS: ").append(baselineContext).append("\n");
            baselineSectionBuilder.append("IMPACT: Anomaly detection unavailable");
        } else if (behaviorAnalysis.isBaselineEstablished()) {
            baselineSectionBuilder.append("STATUS: [NO_DATA] Baseline available but not loaded\n");
            baselineSectionBuilder.append("IMPACT: Anomaly detection unavailable");
        } else {
            baselineSectionBuilder.append("STATUS: [NEW_USER] No baseline established for this user\n");
            baselineSectionBuilder.append("IMPACT: Cannot compare against historical patterns");
        }
        String baselineSection = baselineSectionBuilder.toString();

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

                // 문서 메타데이터 추출 (Truncation 정책 적용)
                String docMeta = buildDocumentMetadata(doc, i + 1);
                int maxLength = tieredStrategyProperties.getTruncation().getLayer2().getRagDocument();
                String truncatedContent = content.length() > maxLength
                    ? content.substring(0, maxLength) + "..."
                    : content;

                relatedContextBuilder.append(docMeta).append(" ").append(truncatedContent);
            }
        }
        String relatedContext = relatedContextBuilder.length() > 0 ?
            relatedContextBuilder.toString() : "No related context found";

        // Phase 9: deviationSection 제거 (AI Native 위반)
        // LLM이 baselineSection의 raw 데이터를 직접 비교하여 판단
        // AI Native v3.3.0: 4개 Action (ALLOW/BLOCK/CHALLENGE/ESCALATE)
        // Phase 5: metadata에서 추출한 풍부한 컨텍스트 정보 제공
        StringBuilder prompt = new StringBuilder();
        prompt.append("Contextual security analysis. Analyze with session/behavior patterns and user baseline.\n\n");

        // 1. 이벤트 기본 정보 (AI Native v4.1.0: Severity 제거, 원시 데이터 제공)
        prompt.append("=== EVENT ===\n");
        if (userId != null) {
            prompt.append("User: ").append(userId).append("\n");
        }

        // AI Native: 원시 메트릭 제공 (Severity 대신 LLM이 직접 위험도 평가)
        // AI Native v4.3.0: TrustScore 제거 - LLM은 riskScore만 반환하며
        // TrustScore(=1-riskScore)는 역관계로 혼란 유발. EMA 학습에서만 내부 사용.
        Object metadataObj = event.getMetadata();
        if (metadataObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> metadata = (Map<String, Object>) metadataObj;
            appendMetadataIfPresent(prompt, metadata, "auth.failure_count", "FailureCount");
        }

        // 2. 네트워크 정보 (Zero Trust: 필수 출력)
        // IP, SessionId 누락 시 NOT_PROVIDED 표시하여 LLM에게 경고
        prompt.append("\n=== NETWORK ===\n");
        prompt.append(networkSection).append("\n");

        // 3. 페이로드 정보 (있는 경우만)
        if (!"empty".equals(payloadSummary)) {
            prompt.append("\n=== PAYLOAD ===\n");
            prompt.append(payloadSummary).append("\n");
        }

        // 4. 세션 컨텍스트 (Priority 1: authMethod, recentActions 추가)
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

        // 8. 관련 문서 (RAG) - 항상 출력 (Zero Trust)
        prompt.append("\n=== RELATED CONTEXT ===\n");
        if (!"No related context found".equals(relatedContext) && !relatedContext.isEmpty()) {
            // 유효한 RAG 문서 - sanitization 적용
            String sanitizedContext = PromptTemplateUtils.sanitizeUserInput(relatedContext);
            prompt.append(sanitizedContext).append("\n");
        } else {
            prompt.append("[NO_DATA] No related context found in vector store\n");
        }

        // 9. 사용자 Baseline
        prompt.append("\n").append(baselineSection).append("\n");

        // 11. 데이터 품질 평가 (AI Native: 누락 필드 명시)
        // buildDataQualitySection()이 누락 필드 목록과 CRITICAL 경고 포함
        prompt.append("\n=== DATA QUALITY ===\n");
        prompt.append(dataQualitySection);

        // 12. 응답 형식 (AI Native v4.0.0 - 중립적 정보 제공, 유도 금지)
        prompt.append("""

            === ACTIONS ===
            A (ALLOW): Permit the request
            B (BLOCK): Deny the request
            C (CHALLENGE): Request additional verification (MFA)
            E (ESCALATE): Forward to Layer 3 expert analysis

            === RESPONSE FORMAT ===
            {"r":<0-1>,"c":<0-1>,"a":"A|B|C|E","d":"<reason>"}

            r: Your risk assessment (0=safe, 1=critical threat)
            c: Your confidence level (0=uncertain, 1=certain)
            a: Your action decision
            d: Brief reasoning (max 30 tokens)
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
            // AI Native v5.0: VectorDocumentMetadata 표준 필드 사용
            // 표준 필드명: "similarityScore" (VectorDocumentMetadata.java:72)
            // VectorStore: PgVector (PostgreSQL + pgvector)
            Object scoreObj = doc.getMetadata().get(VectorDocumentMetadata.SIMILARITY_SCORE);
            // "score" 필드는 일부 프로세서에서 사용하므로 fallback 유지
            if (scoreObj == null) {
                scoreObj = doc.getMetadata().get("score");
            }
            // "distance"는 유사도와 역관계이므로 제거 (혼란 유발)

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

            // 소스 정보 (있는 경우) - Truncation 정책 적용
            Object sourceObj = doc.getMetadata().get("source");
            if (sourceObj != null) {
                String source = sourceObj.toString();
                int maxSource = tieredStrategyProperties.getTruncation().getLayer2().getSource();
                if (source.length() > maxSource) {
                    source = source.substring(0, maxSource - 3) + "...";
                }
                meta.append("|src=").append(source);
            }
        }

        meta.append("]");
        return meta.toString();
    }

    /**
     * Payload 요약 (Truncation 정책 적용)
     * SQLi, XSS, Webshell 등 분석을 위해 페이로드 확장
     */
    private String summarizePayload(String payload) {
        if (payload == null || payload.isEmpty()) {
            return "empty";
        }
        int maxPayload = tieredStrategyProperties.getTruncation().getLayer2().getPayload();
        if (payload.length() > maxPayload) {
            return payload.substring(0, maxPayload) + "... (truncated)";
        }
        return payload;
    }

    /**
     * 네트워크 정보 섹션 구성 (Zero Trust: 필수 필드 누락 시 경고)
     *
     * AI Native + Zero Trust 원칙:
     * - IP, SessionId는 검증 필수 필드
     * - 누락 시 NOT_PROVIDED [CRITICAL] 표시
     * - LLM이 데이터 부재를 인식하여 CHALLENGE/ESCALATE 판단
     */
    private String buildNetworkSection(SecurityEvent event) {
        StringBuilder network = new StringBuilder();

        // IP (Zero Trust Critical)
        if (isValidData(event.getSourceIp())) {
            network.append("IP: ").append(event.getSourceIp()).append("\n");
        } else {
            network.append("IP: NOT_PROVIDED [CRITICAL: Cannot verify origin]\n");
        }

        // SessionId (Zero Trust Critical)
        if (isValidData(event.getSessionId())) {
            network.append("SessionId: ").append(event.getSessionId()).append("\n");
        } else {
            network.append("SessionId: NOT_PROVIDED [CRITICAL: Cannot verify session]\n");
        }

        // UserAgent (선택)
        if (isValidData(event.getUserAgent())) {
            String ua = event.getUserAgent();
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

    // AI Native v4.2.0: Dead Code 삭제
    // - getStringFromMetadata(): 호출부 없음
    // - extractSimpleClassName(): 호출부 없음
    // - calculateDataQuality(): buildDataQualitySection()으로 대체됨

    /**
     * Baseline 데이터가 유효한지 검사 (Zero Trust)
     *
     * 상태 메시지는 유효한 데이터가 아님:
     * - [SERVICE_UNAVAILABLE]: 서비스 미구성
     * - [NO_USER_ID]: 사용자 ID 없음
     * - [NO_DATA]: 데이터 없음
     *
     * @param baseline baseline 컨텍스트 문자열
     * @return 유효하면 true
     */
    private boolean isValidBaseline(String baseline) {
        if (baseline == null || baseline.isEmpty()) {
            return false;
        }
        // Zero Trust: 상태 메시지는 유효한 데이터가 아님
        if (baseline.startsWith("[SERVICE_UNAVAILABLE]") ||
            baseline.startsWith("[NO_USER_ID]") ||
            baseline.startsWith("[NO_DATA]")) {
            return false;
        }
        // Zero Trust: CRITICAL 경고가 포함된 신규 사용자 메시지는 반드시 출력
        if (baseline.contains("CRITICAL") || baseline.contains("NO USER BASELINE")) {
            return true;
        }
        return !baseline.equalsIgnoreCase("Not available")
            && !baseline.equalsIgnoreCase("none")
            && !baseline.equalsIgnoreCase("N/A");
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
        // AI Native v4.2.0: accessPattern 삭제 - 프롬프트에서 미사용 (라인 73 주석 참조)

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
        // AI Native v4.2.0: getAccessPattern(), setAccessPattern() 삭제 - 프롬프트 미사용
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

    /**
     * AI Native v4.1.0: metadata에서 원시 메트릭을 프롬프트에 추가
     *
     * Severity 대신 원시 데이터를 제공하여 LLM이 직접 위험도를 판단하도록 함
     * - failureCount, trustScore, riskScore 등 원시 값 제공
     * - LLM이 컨텍스트를 고려하여 독립적으로 판단
     *
     * @param sb StringBuilder
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
}