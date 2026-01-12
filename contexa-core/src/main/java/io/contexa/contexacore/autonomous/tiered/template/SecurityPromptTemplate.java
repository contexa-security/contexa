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
 * AI Native v6.6: 통합 보안 프롬프트 템플릿
 *
 * Layer1과 Layer2를 위한 단일 프롬프트 템플릿입니다.
 * L1 = L2 원칙: 프롬프트와 응답 형식이 완전히 동일하며, 차이점은 LLM 모델만 다릅니다.
 *
 * 핵심 원칙:
 * - 동일한 프롬프트 → 동일한 응답 형식 (5필드)
 * - LLM 모델이 판단 품질 결정 (layer1.model vs layer2.model)
 * - AI Native: 플랫폼은 raw 데이터만 제공, LLM이 판단
 * - Zero Trust: Baseline 없이 ALLOW 불가
 *
 * 통합으로 제거된 항목:
 * - USER HISTORY 섹션 (순환 논리, LLM 편향 유발)
 * - PREVIOUS LAYER 섹션 (프롬프트 통일로 불필요)
 * - recommendation 필드 (action과 중복)
 * - HistoricalContext 클래스 (USER HISTORY 제거로 불필요)
 *
 * @since AI Native v6.6
 */
@Slf4j
public class SecurityPromptTemplate {

    private final SecurityEventEnricher eventEnricher;
    private final TieredStrategyProperties tieredStrategyProperties;

    @Autowired
    public SecurityPromptTemplate(
            @Autowired(required = false) SecurityEventEnricher eventEnricher,
            @Autowired(required = false) TieredStrategyProperties tieredStrategyProperties) {
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.tieredStrategyProperties = tieredStrategyProperties != null
            ? tieredStrategyProperties : new TieredStrategyProperties();
    }

    /**
     * 통합 프롬프트 생성
     *
     * Layer1과 Layer2 모두 이 메서드를 사용하여 동일한 프롬프트를 생성합니다.
     * 차이점은 호출하는 LLM 모델 (layer1.model vs layer2.model)만 다릅니다.
     *
     * @param event 보안 이벤트
     * @param sessionContext 세션 컨텍스트
     * @param behaviorAnalysis 행동 분석 결과
     * @param relatedDocuments RAG 관련 문서
     * @return LLM 프롬프트 문자열
     */
    public String buildPrompt(SecurityEvent event,
                               SessionContext sessionContext,
                               BehaviorAnalysis behaviorAnalysis,
                               List<Document> relatedDocuments) {

        // Phase 4: getDecodedPayload() 사용 (Base64/URL 인코딩 자동 디코딩)
        Optional<String> decodedPayload = eventEnricher.getDecodedPayload(event);

        // AI Native v6.0: Optional 패턴으로 변경 - 마법 문자열 "empty" 제거
        Optional<String> payloadSummary = summarizePayload(decodedPayload.orElse(null));

        String networkSection = buildNetworkSection(event);

        // AI Native v6.0: baseline 포함 Data Quality 섹션
        String baselineContextForQuality = (behaviorAnalysis != null) ? behaviorAnalysis.getBaselineContext() : null;
        String dataQualitySection = PromptTemplateUtils.buildDataQualitySection(event, baselineContextForQuality);

        // Session Context 핵심만 (AI Native: null 값 처리)
        String userId = (sessionContext != null) ? sessionContext.getUserId() : null;

        // AI Native v6.2: BaselineStatus enum 적용으로 로직 단순화
        String baselineContext = (behaviorAnalysis != null) ? behaviorAnalysis.getBaselineContext() : null;
        BaselineStatus baselineStatus = determineBaselineStatus(behaviorAnalysis, baselineContext);

        // Baseline 섹션 구성 - enum 기반
        StringBuilder baselineSectionBuilder = new StringBuilder();
        baselineSectionBuilder.append("=== BASELINE ===\n");

        // AI Native v6.6: confidence 값 포함하여 상태 표시 (Layer2에서 가져옴)
        Double baselineConfidence = (behaviorAnalysis != null) ? behaviorAnalysis.getBaselineConfidence() : null;

        if (baselineStatus == BaselineStatus.ESTABLISHED) {
            String statusWithConfidence = baselineConfidence != null
                ? String.format("Available (confidence=%.2f)", baselineConfidence)
                : "Available";
            baselineSectionBuilder.append("STATUS: ").append(statusWithConfidence).append("\n");

            if (baselineContext != null) {
                String sanitizedBaseline = PromptTemplateUtils.sanitizeUserInput(baselineContext);
                baselineSectionBuilder.append(sanitizedBaseline).append("\n");
            }
        } else {
            baselineSectionBuilder.append("STATUS: ").append(baselineStatus.getStatusLabel()).append("\n");
            baselineSectionBuilder.append("IMPACT: ").append(baselineStatus.getImpactDescription()).append("\n");

            // 신규 사용자에게 CRITICAL 경고 메시지 포함 (있는 경우)
            if (baselineStatus == BaselineStatus.NEW_USER && baselineContext != null
                && (baselineContext.contains("CRITICAL") || baselineContext.contains("NO USER BASELINE"))) {
                String sanitizedBaseline = PromptTemplateUtils.sanitizeUserInput(baselineContext);
                baselineSectionBuilder.append(sanitizedBaseline).append("\n");
            }
        }

        // AI Native v6.4: ZERO TRUST WARNING 추가
        // 신규 사용자에게 ALLOW 부여 방지 - Zero Trust 핵심 원칙
        // Baseline 없음 = 정상 행동 패턴 검증 불가 = ALLOW 불가능
        if (baselineStatus == BaselineStatus.NEW_USER) {
            baselineSectionBuilder.append("\nZERO TRUST WARNING:\n");
            baselineSectionBuilder.append("- This is a new user without established behavioral baseline.\n");
            baselineSectionBuilder.append("- Cannot verify if this is the legitimate user or an attacker.\n");
            baselineSectionBuilder.append("- confidence MUST be <= 0.5 due to insufficient historical data.\n");
            baselineSectionBuilder.append("- riskScore should be >= 0.5 for unverified users.\n");
        }

        String baselineSection = baselineSectionBuilder.toString();

        // Related Documents - 설정에서 최대 개수 읽기
        StringBuilder relatedContextBuilder = new StringBuilder();
        int maxRagDocs = tieredStrategyProperties.getLayer1().getPrompt().getMaxRagDocuments();
        int maxDocs = (relatedDocuments != null) ? Math.min(maxRagDocs, relatedDocuments.size()) : 0;
        for (int i = 0; i < maxDocs; i++) {
            Document doc = relatedDocuments.get(i);
            String content = doc.getText();
            if (content != null && !content.isBlank()) {
                if (i > 0) {
                    relatedContextBuilder.append("\n");
                }

                String docMeta = buildDocumentMetadata(doc, i + 1);
                int maxLength = tieredStrategyProperties.getTruncation().getLayer1().getRagDocument();
                String truncatedContent = content.length() > maxLength
                    ? content.substring(0, maxLength) + "..."
                    : content;

                relatedContextBuilder.append(docMeta).append(" ").append(truncatedContent);
            }
        }
        boolean hasRelatedDocs = relatedContextBuilder.length() > 0;
        String relatedContext = hasRelatedDocs ? relatedContextBuilder.toString() : null;

        // 프롬프트 구성
        // AI Native v6.7: JSON 전용 응답 강제 - 시스템 역할 명시
        StringBuilder prompt = new StringBuilder();
        prompt.append("""
            You are a security analyst AI. Analyze the security event below and respond with ONLY a JSON object.
            DO NOT include any explanation, markdown, or text before/after the JSON.
            Your response must be a single valid JSON object starting with { and ending with }.

            """);

        // 1. 이벤트 기본 정보
        prompt.append("=== EVENT ===\n");
        if (isValidData(event.getEventId())) {
            prompt.append("EventId: ").append(PromptTemplateUtils.sanitizeUserInput(event.getEventId())).append("\n");
        }
        if (event.getTimestamp() != null) {
            prompt.append("Timestamp: ").append(event.getTimestamp()).append("\n");
        }
        if (userId != null) {
            prompt.append("User: ").append(PromptTemplateUtils.sanitizeUserInput(userId)).append("\n");
        }
        if (isValidData(event.getDescription())) {
            int maxDescLen = tieredStrategyProperties.getLayer1().getPrompt().getMaxDescriptionLength();
            String desc = PromptTemplateUtils.sanitizeAndTruncate(event.getDescription(), maxDescLen);
            prompt.append("Description: ").append(desc).append("\n");
        }

        // AI Native: 원시 메트릭 제공 (Severity 대신 LLM이 직접 위험도 평가)
        Map<String, Object> metadataObj = event.getMetadata();
        if (metadataObj instanceof Map) {
            appendMetadataIfPresent(prompt, metadataObj, "auth.failure_count", "FailureCount");
        }

        // 2. 네트워크 정보 (Zero Trust: 필수 출력)
        prompt.append("\n=== NETWORK ===\n");
        prompt.append(networkSection).append("\n");

        // 3. 페이로드 정보 (있는 경우만)
        if (payloadSummary.isPresent()) {
            prompt.append("\n=== PAYLOAD ===\n");
            prompt.append(payloadSummary.get()).append("\n");
        }

        // 4. 세션 컨텍스트
        prompt.append("\n=== SESSION ===\n");
        if (sessionContext != null) {
            List<String> recentActions = sessionContext.getRecentActions();
            if (recentActions != null && !recentActions.isEmpty()) {
                int maxRecentActions = tieredStrategyProperties.getLayer1().getPrompt().getMaxRecentActions();
                int maxActions = Math.min(maxRecentActions, recentActions.size());
                List<String> subList = recentActions.subList(
                    Math.max(0, recentActions.size() - maxActions), recentActions.size());
                String actionsStr = subList.stream()
                    .map(PromptTemplateUtils::sanitizeUserInput)
                    .collect(java.util.stream.Collectors.joining(", "));
                prompt.append("RecentActions: [").append(actionsStr).append("]\n");
            }
            // AI Native v6.0 Critical: authMethod 출력 추가
            String authMethod = sessionContext.getAuthMethod();
            if (authMethod != null && !authMethod.isEmpty()) {
                String sanitizedAuthMethod = PromptTemplateUtils.sanitizeUserInput(authMethod);
                prompt.append("AuthMethod: ").append(sanitizedAuthMethod).append("\n");
            }
            // Zero Trust 신호 출력 (isNewUser, isNewSession, isNewDevice)
            appendZeroTrustSignals(prompt, event, behaviorAnalysis);
        } else {
            prompt.append("[NO_DATA] Session context unavailable\n");
        }

        // AI Native v6.6: 세션 디바이스 변경 감지 (중립적 정보 제공)
        // 판단은 LLM에게 위임 - 플랫폼은 데이터만 제공
        if (behaviorAnalysis != null) {
            String previousOS = behaviorAnalysis.getPreviousUserAgentOS();
            String currentOS = behaviorAnalysis.getCurrentUserAgentOS();

            if (previousOS != null && currentOS != null && !previousOS.equals(currentOS)) {
                prompt.append("\n=== SESSION DEVICE CHANGE ===\n");
                prompt.append("OBSERVATION: Same SessionId with different device fingerprint detected.\n");
                prompt.append("Previous OS: ").append(previousOS).append("\n");
                prompt.append("Current OS: ").append(currentOS).append("\n");
                prompt.append("OS Transition: ").append(previousOS).append(" -> ").append(currentOS).append("\n");
                // AI Native: 판단은 LLM에게 위임 - 플랫폼은 "CRITICAL", "Do NOT" 등 강제 표현 사용 금지
            }
        }

        // 5. 행동 분석
        prompt.append("\n=== BEHAVIOR ===\n");
        if (behaviorAnalysis != null) {
            List<String> similarEvents = behaviorAnalysis.getSimilarEvents();
            if (similarEvents != null && !similarEvents.isEmpty()) {
                int maxSimilarEvents = tieredStrategyProperties.getLayer1().getPrompt().getMaxSimilarEvents();
                int maxEvents = Math.min(maxSimilarEvents, similarEvents.size());
                prompt.append("SimilarEvents Detail:\n");
                for (int i = 0; i < maxEvents; i++) {
                    String sanitizedEvent = PromptTemplateUtils.sanitizeUserInput(similarEvents.get(i));
                    prompt.append("  ").append(i + 1).append(". ").append(sanitizedEvent).append("\n");
                }
            } else {
                prompt.append("[NO_DATA] No similar events found\n");
            }
        } else {
            prompt.append("[NO_DATA] Behavior analysis unavailable\n");
        }

        // 6. 관련 문서 (RAG)
        prompt.append("\n=== RELATED CONTEXT ===\n");
        if (hasRelatedDocs) {
            String sanitizedContext = PromptTemplateUtils.sanitizeUserInput(relatedContext);
            prompt.append(sanitizedContext).append("\n");
        } else {
            prompt.append("[NO_DATA] No related context found in vector store\n");
        }

        // 7. 사용자 Baseline
        prompt.append("\n").append(baselineSection).append("\n");

        // 8. 데이터 품질 평가
        prompt.append("\n=== DATA QUALITY ===\n");
        prompt.append(dataQualitySection);

        // 9. 응답 형식 (통일된 5필드)
        // AI Native v6.7: JSON 전용 응답 강제
        prompt.append("""

            === RESPONSE INSTRUCTIONS ===
            IMPORTANT: Respond with ONLY a single JSON object. No explanation, no markdown, no text before or after.

            ACTIONS:
            - ALLOW: Permit (ONLY when baseline ESTABLISHED and patterns match)
            - BLOCK: Deny (strong malicious evidence)
            - CHALLENGE: Request MFA (suspicious but inconclusive)
            - ESCALATE: Forward to Layer 2 (complex/ambiguous)

            REQUIRED JSON FORMAT (respond with ONLY this, nothing else):
            {"riskScore":0.5,"confidence":0.5,"confidenceReasoning":"reason for confidence","action":"CHALLENGE","reasoning":"reason for action","mitre":"T1078"}

            FIELD RULES:
            - riskScore: number 0-1 (0=safe, 1=critical)
            - confidence: number 0-1 (0=uncertain, 1=certain)
            - confidenceReasoning: string (why this confidence)
            - action: string (ALLOW|BLOCK|CHALLENGE|ESCALATE)
            - reasoning: string (max 30 tokens)
            - mitre: string or null (MITRE ATT&CK ID if threat detected)

            OUTPUT ONLY THE JSON. NO OTHER TEXT.
            """);

        return prompt.toString();
    }

    /**
     * Zero Trust 신호 출력 (isNewUser, isNewSession, isNewDevice)
     *
     * BehaviorAnalysis와 event metadata에서 Zero Trust 신호를 가져옵니다.
     * AI Native v6.6: Layer1과 Layer2 통합으로 양쪽 소스에서 데이터 수집
     */
    private void appendZeroTrustSignals(StringBuilder prompt, SecurityEvent event, BehaviorAnalysis behaviorAnalysis) {
        // 1. BehaviorAnalysis에서 Zero Trust 신호 가져오기 (Layer2 방식)
        if (behaviorAnalysis != null) {
            Boolean isNewUser = behaviorAnalysis.getIsNewUser();
            Boolean isNewSession = behaviorAnalysis.getIsNewSession();
            Boolean isNewDevice = behaviorAnalysis.getIsNewDevice();

            if (isNewUser != null) {
                prompt.append("IsNewUser: ").append(isNewUser).append("\n");
            }
            if (isNewSession != null) {
                prompt.append("IsNewSession: ").append(isNewSession).append("\n");
            }
            if (isNewDevice != null) {
                prompt.append("IsNewDevice: ").append(isNewDevice).append("\n");
            }

            // BehaviorAnalysis에 값이 있으면 사용
            if (isNewUser != null || isNewSession != null || isNewDevice != null) {
                return;
            }
        }

        // 2. event.metadata에서 Zero Trust 신호 가져오기 (Layer1 방식)
        Object metadataObj = event.getMetadata();
        if (metadataObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> metadata = (Map<String, Object>) metadataObj;

            Object isNewUserObj = metadata.get("isNewUser");
            if (isNewUserObj != null) {
                prompt.append("IsNewUser: ").append(isNewUserObj).append("\n");
            }
            Object isNewSessionObj = metadata.get("isNewSession");
            if (isNewSessionObj != null) {
                prompt.append("IsNewSession: ").append(isNewSessionObj).append("\n");
            }
            Object isNewDeviceObj = metadata.get("isNewDevice");
            if (isNewDeviceObj != null) {
                prompt.append("IsNewDevice: ").append(isNewDeviceObj).append("\n");
            }
        }
    }

    /**
     * RAG 문서 메타데이터 추출
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

        Map<String, Object> metadata = doc.getMetadata();
        if (metadata != null) {
            // 1. 유사도 점수 (Vector Store에서 추가)
            Object scoreObj = metadata.get(VectorDocumentMetadata.SIMILARITY_SCORE);
            if (scoreObj == null) {
                scoreObj = metadata.get("score");
            }
            if (scoreObj instanceof Number) {
                meta.append("|sim=").append(String.format("%.2f", ((Number) scoreObj).doubleValue()));
            }

            // 2. 문서 타입
            Object typeObj = metadata.get("documentType");
            if (typeObj == null) {
                typeObj = metadata.get("type");
            }
            if (typeObj != null) {
                meta.append("|type=").append(typeObj.toString());
            }

            // 3. 저장된 중요 Metadata 출력 (LLM 분석에 필수)
            Object userId = metadata.get("userId");
            if (userId != null) {
                meta.append("|user=").append(userId);
            }

            Object riskScore = metadata.get("riskScore");
            if (riskScore instanceof Number) {
                meta.append("|risk=").append(String.format("%.2f", ((Number) riskScore).doubleValue()));
            }

            Object confidence = metadata.get("confidence");
            if (confidence instanceof Number) {
                meta.append("|conf=").append(String.format("%.2f", ((Number) confidence).doubleValue()));
            }

            Object sourceIp = metadata.get("sourceIp");
            if (sourceIp != null) {
                meta.append("|ip=").append(sourceIp);
            }

            Object timestamp = metadata.get("timestamp");
            if (timestamp != null) {
                meta.append("|time=").append(timestamp);
            }
        }

        meta.append("]");
        return meta.toString();
    }

    /**
     * Payload 요약 (Truncation 정책 적용)
     *
     * @param payload 원본 페이로드
     * @return 페이로드가 있으면 Optional.of(summary), 없으면 Optional.empty()
     */
    private Optional<String> summarizePayload(String payload) {
        if (payload == null || payload.isEmpty()) {
            return Optional.empty();
        }
        int maxPayload = tieredStrategyProperties.getTruncation().getLayer1().getPayload();
        if (payload.length() > maxPayload) {
            return Optional.of(payload.substring(0, maxPayload) + "... (truncated)");
        }
        return Optional.of(payload);
    }

    /**
     * 네트워크 정보 섹션 구성 (Zero Trust: 필수 필드 누락 시 경고)
     */
    private String buildNetworkSection(SecurityEvent event) {
        StringBuilder network = new StringBuilder();

        // IP (Zero Trust Critical) - IP 형식 검증 적용
        PromptTemplateUtils.appendIpWithValidation(network, event.getSourceIp());

        // SessionId (Zero Trust Critical) - sanitization 적용
        if (isValidData(event.getSessionId())) {
            String sanitizedSessionId = PromptTemplateUtils.sanitizeUserInput(event.getSessionId());
            network.append("SessionId: ").append(sanitizedSessionId).append("\n");
        } else {
            network.append("SessionId: NOT_PROVIDED [CRITICAL: Cannot verify session]\n");
        }

        // UserAgent (선택) - sanitization 적용
        if (isValidData(event.getUserAgent())) {
            String ua = event.getUserAgent();
            int maxUserAgent = tieredStrategyProperties.getTruncation().getLayer1().getUserAgent();
            String sanitizedUa = PromptTemplateUtils.sanitizeAndTruncate(ua, maxUserAgent);
            network.append("UserAgent: ").append(sanitizedUa).append("\n");
        }

        return network.toString().trim();
    }

    /**
     * 데이터가 유효한지 검사 (null, empty, "unknown" 제외)
     */
    private boolean isValidData(String value) {
        return PromptTemplateUtils.isValidData(value);
    }

    /**
     * AI Native v6.2: Baseline 상태 결정 (enum 기반)
     *
     * @param behaviorAnalysis 행동 분석 결과 (null 가능)
     * @param baselineContext baseline 컨텍스트 문자열 (null 가능)
     * @return 결정된 BaselineStatus
     */
    private BaselineStatus determineBaselineStatus(BehaviorAnalysis behaviorAnalysis, String baselineContext) {
        // 1. BehaviorAnalysis 자체가 null
        if (behaviorAnalysis == null) {
            return BaselineStatus.ANALYSIS_UNAVAILABLE;
        }

        // 2. 유효한 baseline 데이터
        if (isValidBaseline(baselineContext)) {
            return BaselineStatus.ESTABLISHED;
        }

        // 3. 상태 메시지로 시작하는 경우
        if (baselineContext != null && baselineContext.startsWith("[")) {
            if (baselineContext.startsWith("[SERVICE_UNAVAILABLE]")) {
                return BaselineStatus.SERVICE_UNAVAILABLE;
            }
            if (baselineContext.startsWith("[NO_USER_ID]")) {
                return BaselineStatus.MISSING_USER_ID;
            }
            if (baselineContext.startsWith("[NO_DATA]")) {
                return BaselineStatus.NOT_LOADED;
            }
            return BaselineStatus.NEW_USER;
        }

        // 4. CRITICAL 경고 또는 NO USER BASELINE 메시지
        if (baselineContext != null &&
            (baselineContext.contains("CRITICAL") || baselineContext.contains("NO USER BASELINE"))) {
            return BaselineStatus.NEW_USER;
        }

        // 5. Baseline이 존재하지만 로드되지 않음
        if (behaviorAnalysis.isBaselineEstablished()) {
            return BaselineStatus.NOT_LOADED;
        }

        // 6. 기본값: 신규 사용자
        return BaselineStatus.NEW_USER;
    }

    /**
     * Baseline 데이터가 유효한지 검사 (Zero Trust)
     */
    private boolean isValidBaseline(String baseline) {
        if (baseline == null || baseline.isEmpty()) {
            return false;
        }
        if (baseline.startsWith("[SERVICE_UNAVAILABLE]") ||
            baseline.startsWith("[NO_USER_ID]") ||
            baseline.startsWith("[NO_DATA]")) {
            return false;
        }
        if (baseline.contains("CRITICAL") || baseline.contains("NO USER BASELINE") ||
            baseline.contains("[NEW_USER]")) {
            return false;
        }
        return !baseline.equalsIgnoreCase("Not available")
            && !baseline.equalsIgnoreCase("none")
            && !baseline.equalsIgnoreCase("N/A");
    }

    /**
     * metadata에서 원시 메트릭을 프롬프트에 추가
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

    /**
     * 통합 SessionContext - AI Native v6.6
     *
     * Layer1과 Layer2에서 동일하게 사용되는 세션 컨텍스트입니다.
     * AI Native 원칙: 기본값 "unknown" 제거 - 값이 없으면 null 반환
     */
    public static class SessionContext {
        private String sessionId;
        private String userId;
        private String authMethod;
        private List<String> recentActions;

        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getAuthMethod() { return authMethod; }
        public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

        public List<String> getRecentActions() { return recentActions != null ? recentActions : List.of(); }
        public void setRecentActions(List<String> recentActions) { this.recentActions = recentActions; }
    }

    /**
     * 통합 BehaviorAnalysis - AI Native v6.6
     *
     * Layer1과 Layer2에서 동일하게 사용되는 행동 분석 결과입니다.
     * Layer2의 확장 필드를 모두 포함합니다:
     * - Zero Trust 신호: isNewUser, isNewSession, isNewDevice
     * - Baseline 성숙도: baselineConfidence
     * - 세션 하이재킹 탐지: previousUserAgentOS, currentUserAgentOS
     *
     * AI Native 원칙: 플랫폼은 raw 데이터만 제공, LLM이 판단
     */
    public static class BehaviorAnalysis {
        private List<String> similarEvents;
        private String baselineContext;
        private boolean baselineEstablished;

        // Zero Trust 신호 필드
        private Boolean isNewUser;
        private Boolean isNewSession;
        private Boolean isNewDevice;

        // Baseline 성숙도 (학습 횟수 기반)
        private Double baselineConfidence;

        // 세션 하이재킹 탐지용 OS 정보
        private String previousUserAgentOS;
        private String currentUserAgentOS;

        public List<String> getSimilarEvents() { return similarEvents != null ? similarEvents : List.of(); }
        public void setSimilarEvents(List<String> events) { this.similarEvents = events; }

        public String getBaselineContext() { return baselineContext; }
        public void setBaselineContext(String baselineContext) { this.baselineContext = baselineContext; }

        public boolean isBaselineEstablished() { return baselineEstablished; }
        public void setBaselineEstablished(boolean baselineEstablished) { this.baselineEstablished = baselineEstablished; }

        // Zero Trust 신호 getter/setter
        public Boolean getIsNewUser() { return isNewUser; }
        public void setIsNewUser(Boolean isNewUser) { this.isNewUser = isNewUser; }

        public Boolean getIsNewSession() { return isNewSession; }
        public void setIsNewSession(Boolean isNewSession) { this.isNewSession = isNewSession; }

        public Boolean getIsNewDevice() { return isNewDevice; }
        public void setIsNewDevice(Boolean isNewDevice) { this.isNewDevice = isNewDevice; }

        // Baseline 성숙도 getter/setter
        public Double getBaselineConfidence() { return baselineConfidence; }
        public void setBaselineConfidence(Double baselineConfidence) { this.baselineConfidence = baselineConfidence; }

        // 세션 하이재킹 탐지용 OS getter/setter
        public String getPreviousUserAgentOS() { return previousUserAgentOS; }
        public void setPreviousUserAgentOS(String previousUserAgentOS) { this.previousUserAgentOS = previousUserAgentOS; }

        public String getCurrentUserAgentOS() { return currentUserAgentOS; }
        public void setCurrentUserAgentOS(String currentUserAgentOS) { this.currentUserAgentOS = currentUserAgentOS; }
    }
}
