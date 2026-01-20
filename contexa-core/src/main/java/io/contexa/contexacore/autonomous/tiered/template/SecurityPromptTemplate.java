package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;


@Slf4j
public class SecurityPromptTemplate {

    private final SecurityEventEnricher eventEnricher;
    private final TieredStrategyProperties tieredStrategyProperties;
    // AI Native v11.5: Baseline + RAG 통합을 위한 서비스 주입
    private final BaselineLearningService baselineLearningService;

    @Autowired
    public SecurityPromptTemplate(
            @Autowired(required = false) SecurityEventEnricher eventEnricher,
            @Autowired(required = false) TieredStrategyProperties tieredStrategyProperties,
            @Autowired(required = false) BaselineLearningService baselineLearningService) {
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.tieredStrategyProperties = tieredStrategyProperties != null
            ? tieredStrategyProperties : new TieredStrategyProperties();
        this.baselineLearningService = baselineLearningService;
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

        // AI Native v11.5: BASELINE 섹션 단순화
        // - Known 데이터(IP, Hour, UA, Path)는 PRE-COMPUTED COMPARISON에 통합됨
        // - Baseline + RAG 데이터가 detectedXXXSet에 병합되어 단일 Known Set 구성
        // - BASELINE 섹션은 NEW_USER의 ZERO TRUST WARNING만 유지
        StringBuilder baselineSectionBuilder = new StringBuilder();

        if (baselineStatus == BaselineStatus.NEW_USER) {
            baselineSectionBuilder.append("=== BASELINE ===\n");
            baselineSectionBuilder.append("STATUS: ").append(baselineStatus.getStatusLabel()).append("\n");
            baselineSectionBuilder.append("IMPACT: ").append(baselineStatus.getImpactDescription()).append("\n");

            // AI Native v6.4: ZERO TRUST WARNING
            // 신규 사용자에게 ALLOW 부여 방지 - Zero Trust 핵심 원칙
            // Baseline 없음 = 정상 행동 패턴 검증 불가 = ALLOW 불가능
            baselineSectionBuilder.append("\nZERO TRUST WARNING:\n");
            baselineSectionBuilder.append("- This is a new user without established behavioral baseline.\n");
            baselineSectionBuilder.append("- Cannot verify if this is the legitimate user or an attacker.\n");
            baselineSectionBuilder.append("- confidence MUST be <= 0.5 due to insufficient historical data.\n");
            baselineSectionBuilder.append("- riskScore should be >= 0.5 for unverified users.\n");
        }

        String baselineSection = baselineSectionBuilder.toString();

        // Related Documents - 설정에서 최대 개수 읽기
        // AI Native v7.1: userId 재검증으로 다른 사용자 문서 필터링 (계정 격리)
        // AI Native v8.14: 5대 컨텍스트 요소 수집 (원시 데이터만, 해석 없음)
        // AI Native v11.2: UA Set 추가 - 모든 항목 동일하게 복수 값 수집
        StringBuilder relatedContextBuilder = new StringBuilder();
        Set<String> detectedOSSet = new HashSet<>();
        Set<String> detectedIPSet = new HashSet<>();
        Set<String> detectedHourSet = new HashSet<>();
        Set<String> detectedUASet = new HashSet<>();
        Set<String> detectedPathSet = new HashSet<>();
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

                // AI Native v8.14: 5대 컨텍스트 요소 수집 (원시 데이터만)
                // 1. OS 수집
                Object userAgentOS = docMetadata.get("userAgentOS");
                if (userAgentOS != null && !userAgentOS.toString().isEmpty()) {
                    detectedOSSet.add(userAgentOS.toString());
                }

                // 2. IP 수집 (loopback 정규화)
                Object sourceIp = docMetadata.get("sourceIp");
                if (sourceIp != null && !sourceIp.toString().isEmpty()) {
                    String ipStr = sourceIp.toString();
                    if (ipStr.contains("127.0.0.1") || ipStr.contains("0:0:0:0:0:0:0:1")) {
                        detectedIPSet.add("loopback");
                    } else {
                        detectedIPSet.add(ipStr);
                    }
                }

                // 3. Hour 수집
                Object hour = docMetadata.get("hour");
                if (hour != null) {
                    detectedHourSet.add(hour.toString());
                }

                // 4. UA 수집 (AI Native v11.2: RAG 문서에서 브라우저 정보 수집)
                Object userAgentBrowser = docMetadata.get("userAgentBrowser");
                if (userAgentBrowser != null && !userAgentBrowser.toString().isEmpty()) {
                    detectedUASet.add(userAgentBrowser.toString());
                }

                // 5. Path prefix 수집 (중복 방지를 위해 prefix만)
                Object requestPath = docMetadata.get("requestPath");
                if (requestPath != null && !requestPath.toString().isEmpty()) {
                    String pathStr = requestPath.toString();
                    // /api/security-test/xxx -> /api/security-test/*
                    int secondSlash = pathStr.indexOf('/', 1);
                    int thirdSlash = secondSlash > 0 ? pathStr.indexOf('/', secondSlash + 1) : -1;
                    if (thirdSlash > 0) {
                        detectedPathSet.add(pathStr.substring(0, thirdSlash) + "/*");
                    } else {
                        detectedPathSet.add(pathStr);
                    }
                }

                addedDocs++;
            }
        }

        // AI Native v11.5: Baseline 데이터를 detectedXXXSet에 병합
        // - RAG + Baseline 통합으로 단일 Known Set 구성
        // - 두 데이터 소스 간 충돌 방지 (BASELINE 섹션 별도 출력 제거)
        if (userId != null && baselineLearningService != null) {
            BaselineVector baseline = baselineLearningService.getBaseline(userId);
            if (baseline != null) {
                // IP 병합 (normalIpRanges)
                if (baseline.getNormalIpRanges() != null) {
                    for (String ip : baseline.getNormalIpRanges()) {
                        if (ip != null && !ip.isEmpty()) {
                            detectedIPSet.add(ip);
                        }
                    }
                }
                // Hour 병합 (normalAccessHours)
                if (baseline.getNormalAccessHours() != null) {
                    for (Integer hour : baseline.getNormalAccessHours()) {
                        if (hour != null) {
                            detectedHourSet.add(hour.toString());
                        }
                    }
                }
                // UA 병합 (normalUserAgents)
                if (baseline.getNormalUserAgents() != null) {
                    for (String ua : baseline.getNormalUserAgents()) {
                        if (ua != null && !ua.isEmpty()) {
                            detectedUASet.add(ua);
                        }
                    }
                }
                // Path 병합 (frequentPaths)
                if (baseline.getFrequentPaths() != null) {
                    for (String path : baseline.getFrequentPaths()) {
                        if (path != null && !path.isEmpty()) {
                            detectedPathSet.add(path);
                        }
                    }
                }
                // AI Native v11.6: OS 병합 (normalOperatingSystems)
                if (baseline.getNormalOperatingSystems() != null) {
                    for (String os : baseline.getNormalOperatingSystems()) {
                        if (os != null && !os.isEmpty()) {
                            detectedOSSet.add(os);
                        }
                    }
                }
                log.debug("[SecurityPromptTemplate][AI Native v11.6] Baseline 데이터 병합: userId={}, " +
                    "IPs={}, Hours={}, UAs={}, Paths={}, OSs={}",
                    userId,
                    baseline.getNormalIpRanges() != null ? baseline.getNormalIpRanges().length : 0,
                    baseline.getNormalAccessHours() != null ? baseline.getNormalAccessHours().length : 0,
                    baseline.getNormalUserAgents() != null ? baseline.getNormalUserAgents().length : 0,
                    baseline.getFrequentPaths() != null ? baseline.getFrequentPaths().length : 0,
                    baseline.getNormalOperatingSystems() != null ? baseline.getNormalOperatingSystems().length : 0);
            }
        }

        if (filteredDocs > 0) {
            log.info("[SecurityPromptTemplate][AI Native v7.1] userId 필터링: {}개 문서 제외, {}개 포함",
                filteredDocs, addedDocs);
        }
        boolean hasRelatedDocs = relatedContextBuilder.length() > 0;
        String relatedContext = hasRelatedDocs ? relatedContextBuilder.toString() : null;

        // 프롬프트 구성
        // AI Native v12.0: 시스템 프롬프트 간소화 (규칙 기반 지시 제거)
        // - CRITICAL INSTRUCTION 제거 (LLM 독립 판단 보장)
        // - PRE-COMPUTED COMPARISON 제거 → CURRENT REQUEST + KNOWN PATTERNS로 변경
        // - 플랫폼은 Raw 데이터만 제공, LLM이 직접 비교/판단
        StringBuilder prompt = new StringBuilder();
        prompt.append("""
            You are a Zero Trust security analyst AI.
            Analyze the security context and respond with ONLY a JSON object.
            No explanation, no markdown.

            """);

        // 1. 이벤트 기본 정보
        prompt.append("=== EVENT ===\n");
        if (isValidData(event.getEventId())) {
            prompt.append("EventId: ").append(PromptTemplateUtils.sanitizeUserInput(event.getEventId())).append("\n");
        }
        if (event.getTimestamp() != null) {
            prompt.append("Timestamp: ").append(event.getTimestamp()).append("\n");

            // AI Native v8.14.1: CurrentHour 추출 - getHour() 직접 사용 (문자열 파싱 버그 수정)
            prompt.append("CurrentHour: ").append(event.getTimestamp().getHour()).append("\n");
        }
        if (userId != null) {
            prompt.append("User: ").append(PromptTemplateUtils.sanitizeUserInput(userId)).append("\n");
        }

        // AI Native v8.14: HttpMethod 추출 (요청 유형 분석용)
        Map<String, Object> metadataObj = event.getMetadata();
        if (metadataObj instanceof Map) {
            Object httpMethod = metadataObj.get("httpMethod");
            if (httpMethod != null && !httpMethod.toString().isEmpty()) {
                prompt.append("HttpMethod: ").append(httpMethod).append("\n");
            }
            // AI Native: 원시 메트릭 제공 (Severity 대신 LLM이 직접 위험도 평가)
            appendMetadataIfPresent(prompt, metadataObj, "auth.failure_count", "FailureCount");
        }

        // AI Native v11.0: 현재 요청 Path 출력 (PRE-COMPUTED COMPARISON과 연계)
        String eventPath = extractRequestPath(event);
        if (eventPath != null && !eventPath.isEmpty()) {
            prompt.append("Path: ").append(PromptTemplateUtils.sanitizeUserInput(eventPath)).append("\n");
        }

        // AI Native v12.0: CURRENT REQUEST 섹션 (현재 요청의 Raw 데이터)
        // - PRE-COMPUTED COMPARISON 테이블 제거 (YES/NO 판단 제거)
        // - 플랫폼은 Raw 데이터만 제공, LLM이 직접 비교/판단
        String currentOS = extractOSFromUserAgent(event.getUserAgent());
        String currentIP = normalizeIP(event.getSourceIp());
        // AI Native v8.14.1: getHour() 직접 사용 (문자열 파싱 버그 수정)
        String currentHour = event.getTimestamp() != null
            ? String.valueOf(event.getTimestamp().getHour())
            : null;
        String currentUA = extractUASignature(event.getUserAgent());

        prompt.append("\n=== CURRENT REQUEST ===\n");
        prompt.append("OS: ").append(currentOS != null ? currentOS : "N/A").append("\n");
        prompt.append("IP: ").append(currentIP != null ? currentIP : "N/A").append("\n");
        prompt.append("Hour: ").append(currentHour != null ? currentHour : "N/A").append("\n");
        prompt.append("UA: ").append(currentUA != null ? currentUA : "N/A").append("\n");

        // AI Native v12.0: KNOWN PATTERNS 섹션 (Baseline + RAG 병합된 학습 패턴)
        // - LLM이 CURRENT REQUEST와 KNOWN PATTERNS를 직접 비교하여 판단
        String knownOSStr = !detectedOSSet.isEmpty() ? String.join(", ", detectedOSSet) : "N/A";
        String knownIPStr = !detectedIPSet.isEmpty() ? String.join(", ", normalizeIPSet(detectedIPSet)) : "N/A";
        String knownHourStr = !detectedHourSet.isEmpty() ? String.join(", ", detectedHourSet) : "N/A";
        String knownUAStr = !detectedUASet.isEmpty() ? String.join(", ", detectedUASet) : "N/A";
        String knownPathStr = !detectedPathSet.isEmpty() ? String.join(", ", detectedPathSet) : "N/A";

        prompt.append("\n=== KNOWN PATTERNS ===\n");
        prompt.append("OS: [").append(knownOSStr).append("]\n");
        prompt.append("IP: [").append(knownIPStr).append("]\n");
        prompt.append("Hour: [").append(knownHourStr).append("]\n");
        prompt.append("UA: [").append(knownUAStr).append("]\n");
        prompt.append("Path: [").append(knownPathStr).append("]\n");

        // AI Native v14.1: Zero Trust 평가 가이드 간소화 (30줄 → 8줄)
        // - LLM 혼란 방지: 너무 긴 지침은 LLM이 무시하거나 환각 유발
        // - 핵심만 전달: CURRENT vs KNOWN 비교 → mismatch 카운트 → 위험도 평가
        prompt.append("\n=== SIGNAL COMPARISON ===\n");
        prompt.append("For OS, IP, Hour, UA - check if CURRENT value exists in KNOWN list:\n");
        prompt.append("- IN list = MATCH (established pattern)\n");
        prompt.append("- NOT in list = MISMATCH (new/unusual)\n");
        prompt.append("Signal context (each mismatch is significant, not minor):\n");
        prompt.append("- IP mismatch: New network location (security-sensitive)\n");
        prompt.append("- OS mismatch: New device type (potential account compromise)\n");
        prompt.append("- Hour mismatch: Unusual access time (behavior anomaly)\n");
        prompt.append("- UA mismatch: New browser/client (credential sharing risk)\n");
        prompt.append("Risk assessment by mismatch count:\n");
        prompt.append("- 0 = All patterns match (low risk)\n");
        prompt.append("- 1 = Single deviation (evaluate context)\n");
        prompt.append("- 2+ = Multiple deviations (elevated risk)\n");

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
            // AI Native v9.0: 매직 스트링 제거 - DATA AVAILABILITY 섹션에서 상세 표시
            prompt.append("Session context not available (see DATA AVAILABILITY)\n");
        }

        // AI Native v6.6: 세션 디바이스 변경 감지 (중립적 정보 제공)
        // 판단은 LLM에게 위임 - 플랫폼은 데이터만 제공
        if (behaviorAnalysis != null) {
            String previousSessionOS = behaviorAnalysis.getPreviousUserAgentOS();
            String currentSessionOS = behaviorAnalysis.getCurrentUserAgentOS();

            if (previousSessionOS != null && currentSessionOS != null && !previousSessionOS.equals(currentSessionOS)) {
                prompt.append("\n=== SESSION DEVICE CHANGE ===\n");
                prompt.append("OBSERVATION: Same SessionId with different device fingerprint detected.\n");
                prompt.append("Previous OS: ").append(previousSessionOS).append("\n");
                prompt.append("Current OS: ").append(currentSessionOS).append("\n");
                prompt.append("OS Transition: ").append(previousSessionOS).append(" -> ").append(currentSessionOS).append("\n");
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
                // AI Native v9.0: 매직 스트링 제거 - DATA AVAILABILITY 섹션에서 상세 표시
                prompt.append("No similar events in history (see DATA AVAILABILITY)\n");
            }
        } else {
            // AI Native v9.0: 매직 스트링 제거 - DATA AVAILABILITY 섹션에서 상세 표시
            prompt.append("Behavior analysis not available (see DATA AVAILABILITY)\n");
        }

        // 6. 관련 문서 (RAG)
        // AI Native v12.0: RELATED CONTEXT 설명 간소화 (규칙 지시 제거)
        // - 개별 문서 비교 금지 지시 제거 (LLM 독립 판단 보장)
        // - 단순히 역사적 이벤트로 표현
        prompt.append("\n=== RELATED CONTEXT ===\n");
        prompt.append("Historical events for this user:\n\n");
        if (hasRelatedDocs) {
            String sanitizedContext = PromptTemplateUtils.sanitizeUserInput(relatedContext);
            prompt.append(sanitizedContext).append("\n");
        } else {
            // AI Native v9.0: 매직 스트링 제거 - DATA AVAILABILITY 섹션에서 상세 표시
            prompt.append("No related context found (see DATA AVAILABILITY)\n");
        }

        // AI Native v11.9: PRE-COMPUTED COMPARISON은 EVENT 다음에 출력됨 (상단 이동)

        // AI Native v9.8: 신규 사용자는 Baseline 없음을 명시 (사실 데이터)
        if (baselineStatus == BaselineStatus.NEW_USER) {
            prompt.append("\n").append(baselineSection);
        }

        // AI Native v12.0: DECISION 섹션 (판단 유도 제거)
        // - "If all factors show YES" 등 규칙 기반 가이드 제거
        // - LLM이 CURRENT REQUEST와 KNOWN PATTERNS를 직접 비교하여 독립적으로 판단
        // - 응답 형식만 제공
        prompt.append("""

            === DECISION ===

            RESPOND WITH JSON ONLY:
            {"riskScore":<0.0-1.0>,"confidence":<0.3-0.95>,"action":"<ACTION>","reasoning":"<analysis>","mitre":"<TAG|none>"}

            ACTIONS:
            - ALLOW: Consistent with known patterns (low risk)
            - CHALLENGE: Needs verification (moderate risk)
            - BLOCK: Unauthorized access indicators (high risk)
            - ESCALATE: Requires human review (critical risk)

            MITRE (if applicable): T1078, T1110, T1185

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
        // AI Native v9.1: IsNewDevice=true Zero Trust 경고 추가
        Boolean isNewDevice = getIsNewDevice(behaviorAnalysis, event);
        if (isNewDevice != null) {
            prompt.append("IsNewDevice: ").append(isNewDevice).append("\n");

            // Zero Trust: 새 디바이스 - 사실만 제공
            if (isNewDevice) {
                prompt.append("  -> First time seeing this device for this user\n");
            }
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

            // AI Native v8.5: hour 필드 직접 사용 (시간대 패턴 분석용)
            // - metadata에 hour 필드가 있으면 직접 사용 (더 정확)
            // - 없으면 timestamp 문자열에서 파싱 (하위 호환)
            Object hour = metadata.get("hour");
            if (hour != null) {
                meta.append("|hour=").append(hour);
            } else {
                Object timestamp = metadata.get("timestamp");
                if (timestamp != null) {
                    String timeStr = timestamp.toString();
                    if (timeStr.contains("T") && timeStr.length() > 13) {
                        meta.append("|hour=").append(timeStr.substring(11, 13));
                    }
                }
            }

            // AI Native v8.10: requestPath로 통일 (HCADContext 도메인 객체 기준)
            Object requestUri = metadata.get("requestPath");
            if (requestUri != null) {
                meta.append("|path=").append(requestUri);
            }

            // AI Native v9.0: userAgentOS 출력 제거 (OS 중복 방지)
            // - 현재 OS: NETWORK.CurrentOS에서 제공
            // - 과거 OS: CONTEXT SUMMARY.Known OS에서 집계
            // - RELATED CONTEXT에서 개별 os= 필드 제거로 LLM 혼란 방지
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

            // AI Native v8.14: CurrentOS 추출 (LLM OS 비교 용이)
            String currentOS = extractOSFromUserAgent(ua);
            if (currentOS != null) {
                network.append("CurrentOS: ").append(currentOS).append("\n");
            }

            // AI Native v10.1: CurrentUA 추출 (LLM UA 비교 용이)
            // [UA] Known과 동일한 형식으로 추출하여 직접 비교 가능하게
            String currentUA = extractUASignature(ua);
            network.append("CurrentUA: ").append(currentUA).append("\n");
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
     * AI Native v8.14: UserAgent에서 OS 추출 (단순 추출, 판단 없음)
     *
     * @param userAgent 원본 UserAgent 문자열
     * @return 추출된 OS 또는 null
     */
    private String extractOSFromUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return null;
        }

        // 모바일 OS 우선 검사
        if (userAgent.contains("Android")) {
            return "Android";
        }
        if (userAgent.contains("iPhone") || userAgent.contains("iPad") || userAgent.contains("iPod")) {
            return "iOS";
        }

        // 데스크톱 OS
        if (userAgent.contains("Windows")) {
            return "Windows";
        }
        if (userAgent.contains("Mac OS") || userAgent.contains("Macintosh")) {
            return "Mac";
        }
        if (userAgent.contains("Linux") && !userAgent.contains("Android")) {
            return "Linux";
        }
        if (userAgent.contains("CrOS")) {
            return "ChromeOS";
        }

        return null;
    }

    /**
     * AI Native v9.3: IP 주소 정규화
     * - loopback 주소들을 통일된 형태로 변환
     * - IPv6 loopback (::1, 0:0:0:0:0:0:0:1) -> "loopback"
     * - IPv4 loopback (127.0.0.1) -> "loopback"
     * - "loopback" 문자열 그대로 유지
     *
     * @param ip 원본 IP 주소
     * @return 정규화된 IP 주소
     */
    private String normalizeIP(String ip) {
        if (ip == null || ip.isEmpty()) {
            return ip;
        }

        String trimmed = ip.trim().toLowerCase();

        // loopback 주소 통일
        if (trimmed.equals("loopback") ||
            trimmed.equals("::1") ||
            trimmed.equals("0:0:0:0:0:0:0:1") ||
            trimmed.equals("127.0.0.1") ||
            trimmed.equals("localhost")) {
            return "loopback";
        }

        return ip;
    }

    /**
     * AI Native v9.3: IP Set 정규화
     * - Set 내의 모든 IP를 정규화하여 새 Set 반환
     *
     * @param ipSet 원본 IP Set
     * @return 정규화된 IP Set
     */
    private Set<String> normalizeIPSet(Set<String> ipSet) {
        if (ipSet == null || ipSet.isEmpty()) {
            return ipSet;
        }

        Set<String> normalized = new LinkedHashSet<>();
        for (String ip : ipSet) {
            normalized.add(normalizeIP(ip));
        }
        return normalized;
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
     * AI Native v10.3: UserAgent에서 브라우저/버전만 추출
     *
     * OS는 이미 [OS] Factor에서 별도로 비교하므로,
     * UA에서는 브라우저/버전만 추출하여 중복 비교 제거
     *
     * AI Native v10.3 변경:
     * - 변경 전: "Chrome/120/Windows" - OS 중복 + LLM 환각 유발
     * - 변경 후: "Chrome/120" - 브라우저/버전만 비교
     *
     * @param userAgent 원본 UserAgent 문자열
     * @return 브라우저/버전 (예: "Chrome/120")
     */
    private String extractUASignature(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Browser";
        }

        // 브라우저 및 버전 추출 (메이저 버전만)
        if (userAgent.contains("Chrome/") && !userAgent.contains("Edg/")) {
            return extractBrowserVersion(userAgent, "Chrome/");
        } else if (userAgent.contains("Edg/")) {
            String browser = extractBrowserVersion(userAgent, "Edg/");
            return browser.replace("Edg", "Edge");
        } else if (userAgent.contains("Firefox/")) {
            return extractBrowserVersion(userAgent, "Firefox/");
        } else if (userAgent.contains("Safari/") && !userAgent.contains("Chrome") && !userAgent.contains("Edg")) {
            String browser = extractBrowserVersion(userAgent, "Version/");
            return browser.replace("Version", "Safari");
        }

        return "Browser";
    }

    /**
     * AI Native v10.1: User-Agent에서 브라우저 버전 추출 (메이저 버전만)
     *
     * @param userAgent User-Agent 문자열
     * @param prefix 브라우저 prefix (예: "Chrome/")
     * @return 브라우저명/메이저버전 (예: "Chrome/120")
     */
    private String extractBrowserVersion(String userAgent, String prefix) {
        int idx = userAgent.indexOf(prefix);
        if (idx == -1) return "Browser";

        int start = idx + prefix.length();
        if (start >= userAgent.length()) return "Browser";

        int end = start;
        while (end < userAgent.length()) {
            char c = userAgent.charAt(end);
            if (c == '.' || c == ' ' || !Character.isDigit(c)) {
                break;
            }
            end++;
        }

        if (end == start) return "Browser";

        String version = userAgent.substring(start, end);
        String browserName = prefix.replace("/", "");
        return browserName + "/" + version;
    }

    /**
     * AI Native v11.0: 현재 요청의 Path 추출
     *
     * @param event 보안 이벤트
     * @return 요청 경로 또는 null
     */
    private String extractRequestPath(SecurityEvent event) {
        if (event == null) {
            return null;
        }

        // 1. metadata에서 requestPath 추출 (우선)
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null) {
            Object path = metadata.get("requestPath");
            if (path != null && !path.toString().isEmpty()) {
                return path.toString();
            }

            // requestUri도 확인
            Object uri = metadata.get("requestUri");
            if (uri != null && !uri.toString().isEmpty()) {
                return uri.toString();
            }
        }

        // 2. description에서 추출 시도
        // 예: "GET /test/security" -> "/test/security"
        String desc = event.getDescription();
        if (desc != null && desc.contains(" /")) {
            int pathStart = desc.indexOf(" /") + 1;
            int pathEnd = desc.indexOf(" ", pathStart);
            if (pathEnd == -1) pathEnd = desc.length();
            String path = desc.substring(pathStart, pathEnd);
            if (!path.isEmpty()) {
                return path;
            }
        }

        return null;
    }

    /**
     * AI Native v11.0: Path 패턴 매칭
     *
     * 현재 경로가 알려진 경로 패턴 집합에 포함되는지 확인
     * - 정확히 일치하거나
     * - prefix 패턴에 일치 (예: /api/security-test/* 패턴에 /api/security-test/resource 일치)
     *
     * @param currentPath 현재 요청 경로
     * @param knownPaths 알려진 경로 패턴 집합
     * @return 일치 여부
     */
    private boolean matchesPathPattern(String currentPath, Set<String> knownPaths) {
        if (currentPath == null || knownPaths == null || knownPaths.isEmpty()) {
            return false;
        }

        for (String knownPath : knownPaths) {
            // 정확히 일치
            if (currentPath.equals(knownPath)) {
                return true;
            }

            // 와일드카드 패턴 일치 (예: /api/security-test/*)
            if (knownPath.endsWith("/*")) {
                String prefix = knownPath.substring(0, knownPath.length() - 1); // "/*" 제거
                if (currentPath.startsWith(prefix)) {
                    return true;
                }
            }

            // prefix 일치 (현재 경로가 알려진 경로로 시작)
            if (currentPath.startsWith(knownPath) || knownPath.startsWith(currentPath)) {
                return true;
            }
        }

        return false;
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
