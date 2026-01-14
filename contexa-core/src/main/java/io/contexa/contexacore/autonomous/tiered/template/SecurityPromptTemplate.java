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

        // AI Native v6.5: learningMaturity 프롬프트 출력 제거
        // - LLM 분석에 불필요한 메타데이터
        // - 핵심 비교 데이터(IP, 시간, 경로, UA)만 제공

        if (baselineStatus == BaselineStatus.ESTABLISHED) {
            baselineSectionBuilder.append("STATUS: Available\n");

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
        // AI Native v7.1: userId 재검증으로 다른 사용자 문서 필터링 (계정 격리)
        StringBuilder relatedContextBuilder = new StringBuilder();
        int maxRagDocs = tieredStrategyProperties.getLayer1().getPrompt().getMaxRagDocuments();
        int maxDocs = (relatedDocuments != null) ? Math.min(maxRagDocs, relatedDocuments.size()) : 0;
        int addedDocs = 0;
        int filteredDocs = 0;
        for (int i = 0; i < maxDocs && addedDocs < maxRagDocs; i++) {
            Document doc = relatedDocuments.get(i);

            // AI Native v7.1: userId 재검증 - 다른 사용자의 문서는 제외
            // 계정별 데이터 격리를 프롬프트 단계에서도 강제
            Map<String, Object> docMetadata = doc.getMetadata();
            if (userId != null) {
                Object docUserId = docMetadata.get("userId");
                if (docUserId != null && !userId.equals(docUserId.toString())) {
                    filteredDocs++;
                    log.debug("[SecurityPromptTemplate] 다른 사용자 문서 제외: docUser={}, currentUser={}",
                        docUserId, userId);
                    continue;  // 다른 사용자의 문서 제외
                }
            }

            String content = doc.getText();
            if (content != null && !content.isBlank()) {
                if (addedDocs > 0) {
                    relatedContextBuilder.append("\n");
                }

                String docMeta = buildDocumentMetadata(doc, addedDocs + 1);
                int maxLength = tieredStrategyProperties.getTruncation().getLayer1().getRagDocument();
                String truncatedContent = content.length() > maxLength
                    ? content.substring(0, maxLength) + "..."
                    : content;

                relatedContextBuilder.append(docMeta).append(" ").append(truncatedContent);
                addedDocs++;
            }
        }
        if (filteredDocs > 0) {
            log.info("[SecurityPromptTemplate][AI Native v7.1] userId 필터링: {}개 문서 제외, {}개 포함",
                filteredDocs, addedDocs);
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
        // AI Native v6.5: Description 필드 제거
        // - "Authorization decision: ALLOWED" 같은 무의미한 값이 LLM 분석을 방해
        // - LLM에 필요한 데이터만 제공하여 분석 품질 향상

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
            // AI Native v6.6: SESSION 의미화 - LLM에 유용한 컨텍스트 제공
            Integer sessionAge = sessionContext.getSessionAgeMinutes();
            if (sessionAge != null) {
                prompt.append("SessionAge: ").append(sessionAge).append(" minutes\n");
            }
            Integer requestCount = sessionContext.getRequestCount();
            if (requestCount != null && requestCount > 0) {
                prompt.append("RequestCount: ").append(requestCount).append("\n");
            }

            // AI Native v6.6: RecentActions 출력 제거
            // - "Authorization decision: ALLOWED" 같은 무의미한 Spring Security 메시지
            // - LLM 분석에 도움이 되지 않음, 토큰만 낭비

            // AI Native v6.0 Critical: authMethod 출력 추가
            String authMethod = sessionContext.getAuthMethod();
            if (authMethod != null && !authMethod.isEmpty()) {
                String sanitizedAuthMethod = PromptTemplateUtils.sanitizeUserInput(authMethod);
                prompt.append("AuthMethod: ").append(sanitizedAuthMethod).append("\n");
            }
            // Zero Trust 신호 출력 (isNewUser, isNewSession, isNewDevice)
            // AI Native v7.0: LLM 분석 시점 기준 - Baseline 없으면 모두 true
            appendZeroTrustSignals(prompt, event, behaviorAnalysis, baselineStatus);
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
        // AI Native v7.1: JSON 전용 응답 강제 + ALLOW 판정 기준 명확화
        // 영구 CHALLENGE 루프 방지: UA PARTIAL은 ALLOW 가능 명시
        prompt.append("""

            === RESPONSE INSTRUCTIONS ===
            IMPORTANT: Respond with ONLY a single JSON object. No explanation, no markdown, no text before or after.

            ACTIONS:
            - ALLOW: Permit when baseline ESTABLISHED and core patterns match:
              Required: IP: MATCH
              Required: Hour: MATCH (or within +-2 hours of normal range)
              Optional: UA: MATCH or PARTIAL is acceptable
              IMPORTANT (AI Native v7.3 - OS Change Detection):
              - UA PARTIAL (same browser, same OS, different version) is NORMAL due to auto-updates.
                If IP: MATCH and Hour: MATCH and UA: PARTIAL, ALLOW is acceptable.
              - UA MISMATCH (different OS like Windows to Android) is SUSPICIOUS.
                OS change indicates possible session hijacking or account takeover.
                If UA: MISMATCH even with IP/Hour match, CHALLENGE is recommended.

            - BLOCK: Deny (strong malicious evidence, clear threat indicators)

            - CHALLENGE: Request MFA when:
              1. New user without baseline
              2. IP: MISMATCH (different network)
              3. UA: MISMATCH (OS/device change even with IP/Hour match)
              4. Hour: outside normal range AND other suspicious indicators

            - ESCALATE: Forward to Layer 2 when:
              1. Complex/ambiguous requiring expert review
              2. Situation matches logical criteria but feels contextually suspicious
              3. Implies a pattern not covered by above rules
              Note: Use ESCALATE when rules say ALLOW but something feels wrong

            EXAMPLE RESPONSES (choose based on your analysis):

            1. ALLOW (IP and Hour match, UA version difference is normal):
            {"riskScore":0.2,"confidence":0.85,"confidenceReasoning":"IP and Hour match baseline, UA version difference is normal (browser auto-update)","action":"ALLOW","reasoning":"trusted user with consistent core patterns","mitre":null}

            2. CHALLENGE (new user without baseline):
            {"riskScore":0.6,"confidence":0.4,"confidenceReasoning":"no baseline, cannot verify identity","action":"CHALLENGE","reasoning":"require MFA to establish trust","mitre":null}

            3. CHALLENGE (IP mismatch):
            {"riskScore":0.65,"confidence":0.6,"confidenceReasoning":"IP does not match baseline, network location changed","action":"CHALLENGE","reasoning":"verify identity from new network","mitre":null}

            4. BLOCK (clear threat):
            {"riskScore":0.9,"confidence":0.85,"confidenceReasoning":"strong malicious indicators","action":"BLOCK","reasoning":"credential stuffing attempt detected","mitre":"T1078"}

            5. ESCALATE (rules match but contextually suspicious):
            {"riskScore":0.45,"confidence":0.4,"confidenceReasoning":"IP and Hour match but access pattern feels unusual - rapid sequential requests to sensitive endpoints","action":"ESCALATE","reasoning":"rules say ALLOW but behavior pattern warrants expert review","mitre":null}

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
     * AI Native v7.0: 각 신호를 독립적으로 판단
     *
     * 핵심 변경:
     * - IsNewUser: Baseline 존재 여부로 판단 (LLM 분석 시점 기준)
     * - IsNewSession: HCAD 시점 값 사용 (세션 기반, Redis 세션 키 존재 여부)
     * - IsNewDevice: HCAD 시점 값 사용 (디바이스 기반, Redis 디바이스 Set 존재 여부)
     *
     * 이유:
     * - IsNewUser: HCAD에서 false라도 Baseline 없으면 LLM 분석 시점에서 "새 사용자"
     * - IsNewSession: 세션 기반이라 HCAD 값 그대로 사용 가능
     * - IsNewDevice: 디바이스 기반이라 HCAD 값 그대로 사용 가능
     *
     * 예시:
     * - 새 사용자 + 같은 세션에서 여러 요청 → IsNewUser: true, IsNewSession: false
     * - 기존 사용자 + 새 디바이스 → IsNewUser: false, IsNewDevice: true
     */
    private void appendZeroTrustSignals(StringBuilder prompt, SecurityEvent event,
                                        BehaviorAnalysis behaviorAnalysis, BaselineStatus baselineStatus) {
        // AI Native v7.0: 각 신호 독립 판단

        // 1. IsNewUser: Baseline 존재 여부로 판단 (LLM 분석 시점 기준)
        // HCAD에서 false라도 Baseline 없으면 실질적으로 "새 사용자"
        boolean isNewUserForLlm = (baselineStatus != BaselineStatus.ESTABLISHED);
        prompt.append("IsNewUser: ").append(isNewUserForLlm);
        if (isNewUserForLlm) {
            prompt.append(" (no baseline established)");
        }
        prompt.append("\n");

        // 2. IsNewSession: HCAD 시점 값 사용 (세션 기반)
        Boolean isNewSession = getIsNewSession(behaviorAnalysis, event);
        if (isNewSession != null) {
            prompt.append("IsNewSession: ").append(isNewSession).append("\n");
        }

        // 3. IsNewDevice: HCAD 시점 값 사용 (디바이스 기반)
        Boolean isNewDevice = getIsNewDevice(behaviorAnalysis, event);
        if (isNewDevice != null) {
            prompt.append("IsNewDevice: ").append(isNewDevice).append("\n");
        }
    }

    /**
     * IsNewSession 값 추출 (BehaviorAnalysis 또는 metadata)
     */
    private Boolean getIsNewSession(BehaviorAnalysis behaviorAnalysis, SecurityEvent event) {
        if (behaviorAnalysis != null && behaviorAnalysis.getIsNewSession() != null) {
            return behaviorAnalysis.getIsNewSession();
        }

        Object metadataObj = event.getMetadata();
        if (metadataObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> metadata = (Map<String, Object>) metadataObj;
            Object value = metadata.get("isNewSession");
            if (value instanceof Boolean) {
                return (Boolean) value;
            }
        }
        return null;
    }

    /**
     * IsNewDevice 값 추출 (BehaviorAnalysis 또는 metadata)
     */
    private Boolean getIsNewDevice(BehaviorAnalysis behaviorAnalysis, SecurityEvent event) {
        if (behaviorAnalysis != null && behaviorAnalysis.getIsNewDevice() != null) {
            return behaviorAnalysis.getIsNewDevice();
        }

        Object metadataObj = event.getMetadata();
        if (metadataObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> metadata = (Map<String, Object>) metadataObj;
            Object value = metadata.get("isNewDevice");
            if (value instanceof Boolean) {
                return (Boolean) value;
            }
        }
        return null;
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

            // 3. 저장된 중요 Metadata 출력 (사실 데이터만)
            // AI Native v6.7: 순환 로직 방지 - LLM 결과(riskScore, confidence) 제거
            // LLM이 이전 자신의 분석 결과에 편향되는 것을 방지
            Object userId = metadata.get("userId");
            if (userId != null) {
                meta.append("|user=").append(userId);
            }

            // AI Native v7.0: action 출력 제거 (순환 로직 방지)
            // - 저장 단계에서 action 제거됨 (SecurityDecisionPostProcessor, Layer2ExpertStrategy)
            // - 기존 벡터 데이터에 action이 남아있어도 프롬프트에 출력하지 않음
            // - LLM이 이전 결정에 편향되지 않고 독립적으로 판단

            // AI Native v6.7: riskScore, confidence 제거 (순환 로직 방지)
            // 이전 LLM 결과가 다음 분석에 영향을 미치면 독립적 분석 불가

            Object sourceIp = metadata.get("sourceIp");
            if (sourceIp != null) {
                meta.append("|ip=").append(sourceIp);
            }

            // AI Native v6.7: hour 추가 (시간대 비교 용이)
            Object timestamp = metadata.get("timestamp");
            if (timestamp != null) {
                // 시간만 추출하여 표시 (전체 타임스탬프는 불필요하게 길음)
                String timeStr = timestamp.toString();
                if (timeStr.contains("T") && timeStr.length() > 13) {
                    meta.append("|hour=").append(timeStr.substring(11, 13));
                } else {
                    meta.append("|time=").append(timeStr);
                }
            }

            // AI Native v6.8: 실제 metadata 키 사용 (requestUri는 ZeroTrustEventListener에서 설정됨)
            Object requestUri = metadata.get("requestUri");
            if (requestUri != null) {
                meta.append("|path=").append(requestUri);
            }

            // AI Native v7.1: userAgentOS 출력 (디바이스 패턴 분석용)
            // LLM이 이전 요청의 디바이스 정보를 볼 수 있도록 함
            Object userAgentOS = metadata.get("userAgentOS");
            if (userAgentOS != null) {
                meta.append("|os=").append(userAgentOS);
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

        // AI Native v6.6: SESSION 의미화 - LLM에 유용한 컨텍스트 제공
        private Integer sessionAgeMinutes;    // 세션 시작 후 경과 시간 (분)
        private Integer requestCount;         // 현재 세션의 요청 횟수

        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getAuthMethod() { return authMethod; }
        public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

        public List<String> getRecentActions() { return recentActions != null ? recentActions : List.of(); }
        public void setRecentActions(List<String> recentActions) { this.recentActions = recentActions; }

        // AI Native v6.6: SESSION 의미화 getter/setter
        public Integer getSessionAgeMinutes() { return sessionAgeMinutes; }
        public void setSessionAgeMinutes(Integer sessionAgeMinutes) { this.sessionAgeMinutes = sessionAgeMinutes; }

        public Integer getRequestCount() { return requestCount; }
        public void setRequestCount(Integer requestCount) { this.requestCount = requestCount; }
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

        // AI Native v6.5: baselineConfidence 필드 제거
        // - LLM 분석에 불필요한 메타데이터
        // - 핵심 비교 데이터(IP, 시간, 경로, UA)만 제공

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

        // AI Native v6.5: baselineConfidence getter/setter 제거

        // 세션 하이재킹 탐지용 OS getter/setter
        public String getPreviousUserAgentOS() { return previousUserAgentOS; }
        public void setPreviousUserAgentOS(String previousUserAgentOS) { this.previousUserAgentOS = previousUserAgentOS; }

        public String getCurrentUserAgentOS() { return currentUserAgentOS; }
        public void setCurrentUserAgentOS(String currentUserAgentOS) { this.currentUserAgentOS = currentUserAgentOS; }
    }
}
