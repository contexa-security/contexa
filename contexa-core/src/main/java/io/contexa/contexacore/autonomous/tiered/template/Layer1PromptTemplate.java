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

        // AI Native v6.0: httpMethod Dead Code 제거
        // - 선언 후 프롬프트에서 미사용 (Phase 2 Dead Code 제거)
        // Phase 4: getDecodedPayload() 사용 (Base64/URL 인코딩 자동 디코딩)
        Optional<String> decodedPayload = eventEnricher.getDecodedPayload(event);

        // AI Native v4.1.0: Severity 변수 제거 - LLM이 원시 데이터로 직접 판단
        // AI Native v6.0: Optional 패턴으로 변경 - 마법 문자열 "empty" 제거
        Optional<String> payloadSummary = summarizePayload(decodedPayload.orElse(null));

        String networkSection = buildNetworkSection(event);
        // Phase 22: buildDataQualitySection() 사용 - 누락 필드 명시적 표시
        // AI Native v6.0: baseline 포함 새 메서드 사용 (@Deprecated 메서드 대체)
        // AI Native v6.0 NULL 안전성: behaviorAnalysis null 체크
        String baselineContextForQuality = (behaviorAnalysis != null) ? behaviorAnalysis.getBaselineContext() : null;
        String dataQualitySection = PromptTemplateUtils.buildDataQualitySection(event, baselineContextForQuality);

        // Session Context 핵심만 (AI Native: null 값 처리)
        // AI Native v3.0: accessPattern 제거 - "AccessFrequency: N" 형식만 제공하여 혼란 유발
        // AI Native v4.0: sessionDuration 제거 - isNewSession + recentRequestCount로 대체 가능한 중복 데이터
        // AI Native v6.0: sessionSummary 제거 - userId가 EVENT 섹션에서 이미 출력되므로 중복
        // recentActions가 실제 행동 정보 제공
        // AI Native v6.0 NULL 안전성: sessionContext null 체크
        String userId = (sessionContext != null) ? sessionContext.getUserId() : null;

        // Behavior 핵심만 - Phase 9: deviationScore 제거 (AI Native 위반)
        // AI Native 원칙: 플랫폼은 raw 데이터만 제공, LLM이 직접 판단
        // AI Native v6.0: behaviorSummary 제거 - "Similar Events: N" 단순 개수는 무의미
        // similarEvents 상세 내용이 아래에서 직접 출력됨

        // AI Native v6.2: BaselineStatus enum 적용으로 로직 단순화
        // 기존 7가지 경우의 수를 명확한 enum으로 통합
        // STATUS 라벨과 IMPACT 메시지가 enum에서 제공됨
        String baselineContext = (behaviorAnalysis != null) ? behaviorAnalysis.getBaselineContext() : null;
        BaselineStatus baselineStatus = determineBaselineStatus(behaviorAnalysis, baselineContext);

        // Baseline 섹션 구성 - enum 기반
        StringBuilder baselineSectionBuilder = new StringBuilder();
        baselineSectionBuilder.append("=== BASELINE ===\n");
        baselineSectionBuilder.append("STATUS: ").append(baselineStatus.getStatusLabel()).append("\n");

        if (baselineStatus == BaselineStatus.ESTABLISHED && baselineContext != null) {
            // 유효한 baseline 데이터 - sanitization 적용
            String sanitizedBaseline = PromptTemplateUtils.sanitizeUserInput(baselineContext);
            baselineSectionBuilder.append(sanitizedBaseline).append("\n");
        } else if (baselineStatus == BaselineStatus.NEW_USER && baselineContext != null
                   && (baselineContext.contains("CRITICAL") || baselineContext.contains("NO USER BASELINE"))) {
            // 신규 사용자지만 Zero Trust 경고 메시지가 있는 경우 함께 출력
            String sanitizedBaseline = PromptTemplateUtils.sanitizeUserInput(baselineContext);
            baselineSectionBuilder.append(sanitizedBaseline).append("\n");
        } else {
            // 그 외 상태: IMPACT 메시지 출력
            baselineSectionBuilder.append("IMPACT: ").append(baselineStatus.getImpactDescription()).append("\n");
        }
        String baselineSection = baselineSectionBuilder.toString();

        // Related Documents - 설정에서 최대 개수 읽기, 각 문서 길이는 truncation 설정 사용
        // Phase 9: RAG 문서 메타데이터 포함 (유사도 점수, 문서 타입)
        // AI Native v6.1: 하드코딩 5 → 설정값 사용
        // AI Native v6.0 NULL 안전성: relatedDocuments null 체크
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

                // 문서 메타데이터 추출 (Truncation 정책 적용)
                // AI Native v6.0: Layer1 설정 사용 (Layer2 → Layer1 수정)
                String docMeta = buildDocumentMetadata(doc, i + 1);
                int maxLength = tieredStrategyProperties.getTruncation().getLayer1().getRagDocument();
                String truncatedContent = content.length() > maxLength
                    ? content.substring(0, maxLength) + "..."
                    : content;

                relatedContextBuilder.append(docMeta).append(" ").append(truncatedContent);
            }
        }
        // AI Native v6.0: 마법 문자열 "No related context found" 제거
        // boolean으로 데이터 존재 여부 판단, 문자열 비교 제거
        boolean hasRelatedDocs = relatedContextBuilder.length() > 0;
        String relatedContext = hasRelatedDocs ? relatedContextBuilder.toString() : null;

        // Phase 9: deviationSection 제거 (AI Native 위반)
        // LLM이 baselineSection의 raw 데이터를 직접 비교하여 판단
        // AI Native v3.3.0: 4개 Action (ALLOW/BLOCK/CHALLENGE/ESCALATE)
        // Phase 5: metadata에서 추출한 풍부한 컨텍스트 정보 제공
        StringBuilder prompt = new StringBuilder();
        prompt.append("Contextual security analysis. Analyze with session/behavior patterns and user baseline.\n\n");

        // 1. 이벤트 기본 정보 (AI Native v4.1.0: Severity 제거, 원시 데이터 제공)
        // AI Native v6.0: 필수 필드 추가 - eventId, timestamp, description
        prompt.append("=== EVENT ===\n");
        // EventId (이벤트 추적용)
        if (isValidData(event.getEventId())) {
            prompt.append("EventId: ").append(PromptTemplateUtils.sanitizeUserInput(event.getEventId())).append("\n");
        }
        // Timestamp (시간 패턴 분석용)
        if (event.getTimestamp() != null) {
            prompt.append("Timestamp: ").append(event.getTimestamp()).append("\n");
        }
        // AI Native v6.0: userId sanitization 적용 (프롬프트 인젝션 방어)
        if (userId != null) {
            prompt.append("User: ").append(PromptTemplateUtils.sanitizeUserInput(userId)).append("\n");
        }
        // Description (컨텍스트 이해용)
        // AI Native v6.1: 하드코딩 200 → 설정값 사용
        if (isValidData(event.getDescription())) {
            int maxDescLen = tieredStrategyProperties.getLayer1().getPrompt().getMaxDescriptionLength();
            String desc = PromptTemplateUtils.sanitizeAndTruncate(event.getDescription(), maxDescLen);
            prompt.append("Description: ").append(desc).append("\n");
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
        // AI Native v6.0: Optional 패턴 - 마법 문자열 비교 제거
        if (payloadSummary.isPresent()) {
            prompt.append("\n=== PAYLOAD ===\n");
            prompt.append(payloadSummary.get()).append("\n");
        }

        // 4. 세션 컨텍스트 (Priority 1: authMethod, recentActions 추가)
        // AI Native v6.0: sessionSummary 제거 - userId가 EVENT 섹션에서 이미 출력됨
        prompt.append("\n=== SESSION ===\n");
        // AI Native v6.0 NULL 안전성: sessionContext null 체크
        // - sessionContext가 null인 경우: 세션 정보 수집 실패 또는 시스템 오류
        // - 명확한 상태 메시지로 LLM에게 데이터 부재 전달
        if (sessionContext != null) {
            List<String> recentActions = sessionContext.getRecentActions();
            if (recentActions != null && !recentActions.isEmpty()) {
                // AI Native v6.1: 하드코딩 5 → 설정값 사용
                int maxRecentActions = tieredStrategyProperties.getLayer1().getPrompt().getMaxRecentActions();
                int maxActions = Math.min(maxRecentActions, recentActions.size());
                List<String> subList = recentActions.subList(
                    Math.max(0, recentActions.size() - maxActions), recentActions.size());
                // 각 액션을 sanitize 후 결합
                String actionsStr = subList.stream()
                    .map(PromptTemplateUtils::sanitizeUserInput)
                    .collect(java.util.stream.Collectors.joining(", "));
                prompt.append("RecentActions: [").append(actionsStr).append("]\n");
            }
            // AI Native v6.0 Critical: authMethod 출력 추가
            // - 인증 방식(PASSWORD, MFA, SSO 등)은 LLM 신뢰도 판단의 핵심
            // - Zero Trust 원칙: 인증 강도에 따라 위험 평가 차등 적용
            // AI Native v6.1: sanitization 적용 (프롬프트 인젝션 방어)
            String authMethod = sessionContext.getAuthMethod();
            if (authMethod != null && !authMethod.isEmpty()) {
                String sanitizedAuthMethod = PromptTemplateUtils.sanitizeUserInput(authMethod);
                prompt.append("AuthMethod: ").append(sanitizedAuthMethod).append("\n");
            }
            // AI Native v6.0: Zero Trust Critical - isNewUser, isNewSession, isNewDevice 추가
            // 신규 사용자/세션/디바이스 여부는 LLM 위험 판단의 핵심 신호
            // 키: ZeroTrustEventListener.java:645-651에서 "isNewUser", "isNewSession", "isNewDevice"로 저장
            Map<String, Object> sessionMetadataObj = event.getMetadata();
            if (sessionMetadataObj instanceof Map) {
                Map<String, Object> sessionMetadata;
                sessionMetadata = sessionMetadataObj;
                // isNewUser: 신규 사용자 여부 (Baseline 없음 = 행동 패턴 비교 불가)
                Object isNewUserObj = sessionMetadata.get("isNewUser");
                if (isNewUserObj != null) {
                    prompt.append("IsNewUser: ").append(isNewUserObj).append("\n");
                }
                // isNewSession: 신규 세션 여부 (세션 하이재킹 탐지 핵심)
                Object isNewSessionObj = sessionMetadata.get("isNewSession");
                if (isNewSessionObj != null) {
                    prompt.append("IsNewSession: ").append(isNewSessionObj).append("\n");
                }
                // isNewDevice: 신규 디바이스 여부 (계정 탈취 탐지 핵심)
                Object isNewDeviceObj = sessionMetadata.get("isNewDevice");
                if (isNewDeviceObj != null) {
                    prompt.append("IsNewDevice: ").append(isNewDeviceObj).append("\n");
                }
            }
        } else {
            prompt.append("[NO_DATA] Session context unavailable\n");
        }

        // 7. 행동 분석 (Priority 1: similarEvents 상세 내용 추가)
        // AI Native v6.0: behaviorSummary 제거 - 단순 개수는 무의미, 상세 내용만 출력
        prompt.append("\n=== BEHAVIOR ===\n");
        // AI Native v6.0 NULL 안전성: behaviorAnalysis null 체크
        // - behaviorAnalysis가 null인 경우: 행동 분석 시스템 오류 또는 초기화 실패
        // - 명확한 상태 메시지로 LLM에게 데이터 부재 전달
        if (behaviorAnalysis != null) {
            // similarEvents 상세 내용 (Priority 1 Critical)
            // AI Native v6.1: 하드코딩 3 → 설정값 사용
            // AI Native v6.0: sanitization 적용 (프롬프트 인젝션 방어)
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
                // AI Native v6.0: similarEvents 없을 때 명시적 상태 메시지
                prompt.append("[NO_DATA] No similar events found\n");
            }
        } else {
            prompt.append("[NO_DATA] Behavior analysis unavailable\n");
        }

        // 8. 관련 문서 (RAG) - 항상 출력 (Zero Trust)
        // AI Native v6.0: boolean 패턴 - 마법 문자열 비교 제거
        prompt.append("\n=== RELATED CONTEXT ===\n");
        if (hasRelatedDocs) {
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

        // 12. 응답 형식 (AI Native v6.0 - 풀네임 사용으로 LLM 혼란 방지)
        // AI Native v6.0: A/B/C/E 약어 → ALLOW/BLOCK/CHALLENGE/ESCALATE 풀네임으로 통일
        // - 파싱 로직 단순화
        // - LLM 혼동 방지
        // - Layer1/Layer2 응답 형식 일관성 확보
        prompt.append("""

            === ACTIONS ===
            ALLOW: Permit the request
            BLOCK: Deny the request
            CHALLENGE: Request additional verification (MFA)
            ESCALATE: Forward to Layer 2 expert analysis

            === RESPONSE FORMAT ===
            {"riskScore":<0-1>,"confidence":<0-1>,"action":"ALLOW|BLOCK|CHALLENGE|ESCALATE","reason":"<reason>"}

            riskScore: [REQUIRED] Your risk assessment (0=safe, 1=critical threat) - MUST be a number
            confidence: [REQUIRED] Your confidence level (0=uncertain, 1=certain) - MUST be a number
            action: [REQUIRED] Your action decision - MUST be one of: ALLOW, BLOCK, CHALLENGE, ESCALATE (NEVER null)
            reason: Brief reasoning (max 30 tokens)

            CRITICAL: You MUST always provide riskScore, confidence, and action. Never omit any required field.
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

            // 2. 문서 타입 (저장 시 "documentType" 키 사용)
            // AI Native v6.0: 키 불일치 수정 - documentType을 우선 검색
            Object typeObj = metadata.get("documentType");
            if (typeObj == null) {
                typeObj = metadata.get("type");
            }
            if (typeObj != null) {
                meta.append("|type=").append(typeObj.toString());
            }

            // 3. 저장된 중요 Metadata 출력 (LLM 분석에 필수)
            // AI Native v6.0: 저장된 userId, riskScore, sourceIp, timestamp를 출력
            // 이 정보가 있어야 LLM이 과거 이벤트 컨텍스트를 이해할 수 있음
            Object userId = metadata.get("userId");
            if (userId != null) {
                meta.append("|user=").append(userId);
            }

            Object riskScore = metadata.get("riskScore");
            if (riskScore instanceof Number) {
                meta.append("|risk=").append(String.format("%.2f", ((Number) riskScore).doubleValue()));
            }

            // AI Native v6.0: confidence 출력 추가
            // - 과거 분석의 신뢰도를 LLM이 참조하여 유사 상황 판단에 활용
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
     * SQLi, XSS, Webshell 등 분석을 위해 페이로드 확장
     *
     * AI Native v6.0: Optional<String> 반환으로 변경
     * - 마법 문자열 "empty" 제거
     * - null/empty는 Optional.empty() 반환
     * - 호출부에서 isPresent()로 체크
     *
     * @param payload 원본 페이로드
     * @return 페이로드가 있으면 Optional.of(summary), 없으면 Optional.empty()
     */
    private Optional<String> summarizePayload(String payload) {
        if (payload == null || payload.isEmpty()) {
            return Optional.empty();
        }
        // AI Native v6.0: Layer1 설정 사용 (Layer2 → Layer1 수정)
        int maxPayload = tieredStrategyProperties.getTruncation().getLayer1().getPayload();
        if (payload.length() > maxPayload) {
            return Optional.of(payload.substring(0, maxPayload) + "... (truncated)");
        }
        return Optional.of(payload);
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

        // IP (Zero Trust Critical) - AI Native v6.0: IP 형식 검증 적용
        // appendIpWithValidation(): 유효한 IP, 잘못된 형식, 값 없음을 명시적으로 구분
        PromptTemplateUtils.appendIpWithValidation(network, event.getSourceIp());

        // SessionId (Zero Trust Critical) - AI Native v6.0: sanitization 적용
        if (isValidData(event.getSessionId())) {
            String sanitizedSessionId = PromptTemplateUtils.sanitizeUserInput(event.getSessionId());
            network.append("SessionId: ").append(sanitizedSessionId).append("\n");
        } else {
            network.append("SessionId: NOT_PROVIDED [CRITICAL: Cannot verify session]\n");
        }

        // UserAgent (선택) - AI Native v6.0: sanitization 적용
        if (isValidData(event.getUserAgent())) {
            String ua = event.getUserAgent();
            int maxUserAgent = tieredStrategyProperties.getTruncation().getLayer1().getUserAgent();
            // 프롬프트 인젝션 방어: sanitizeAndTruncate() 사용
            String sanitizedUa = PromptTemplateUtils.sanitizeAndTruncate(ua, maxUserAgent);
            network.append("UserAgent: ").append(sanitizedUa).append("\n");
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
     * AI Native v6.2: Baseline 상태 결정 (enum 기반)
     *
     * 기존 복잡한 조건문 로직을 명확한 enum 반환으로 단순화.
     * 상호 배타적인 상태를 보장하여 프롬프트 출력의 일관성 확보.
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

        // 3. 상태 메시지로 시작하는 경우 (SERVICE_UNAVAILABLE, NO_USER_ID, NO_DATA)
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
            // 기타 상태 메시지는 NEW_USER로 처리
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
        // AI Native v6.0: CRITICAL 경고나 NO USER BASELINE 메시지는 유효한 baseline이 아님
        // 이 메시지들은 별도의 조건문에서 처리되어 프롬프트에 출력됨
        if (baseline.contains("CRITICAL") || baseline.contains("NO USER BASELINE") ||
            baseline.contains("[NEW_USER]")) {
            return false;
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
        // AI Native v6.0: sessionDuration 제거 - Dead Code (프롬프트에서 미사용)
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

        // AI Native v6.0: getSessionDuration(), setSessionDuration() 제거 - Dead Code
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