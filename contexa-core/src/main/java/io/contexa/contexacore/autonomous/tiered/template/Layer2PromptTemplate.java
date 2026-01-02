package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Map;
import java.util.Optional;

/**
 * Layer 3: 전문가 분석 프롬프트 템플릿 (최적화 버전)
 *
 * BeanOutputConverter 제거로 프롬프트 크기 대폭 감소:
 * - 변경 전: 3200+ 토큰 (JSON Schema 포함)
 * - 변경 후: 700 토큰 (78% 감소!)
 *
 * 예상 성능:
 * - Claude Sonnet: 5-10초 → 1-3초 (3-10배 개선!)
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
     * Layer3 프롬프트 생성 (기본 버전 - 하위 호환)
     * Phase 9: deviationAnalysis 파라미터 제거
     * AI Native v4.2.0: systemContext 파라미터 제거 (항상 null, 죽은 데이터)
     */
    public String buildPrompt(SecurityEvent event,
                               SecurityDecision layer1Decision,
                               SecurityDecision layer2Decision,
                               ThreatIntelligence threatIntel,
                               HistoricalContext historicalContext) {
        return buildPrompt(event, layer1Decision, layer2Decision, threatIntel,
                           historicalContext, null);
    }

    /**
     * Layer3 프롬프트 생성 (AI Native - Baseline 포함)
     *
     * 전문가 수준 분석을 위해 사용자 baseline 패턴과 편차 분석 결과를
     * 위협 인텔리전스, 과거 이력과 함께 종합적으로 제공
     *
     * @param event 보안 이벤트
     * @param layer1Decision Layer1 결정
     * @param layer2Decision Layer2 결정
     * @param threatIntel 위협 인텔리전스
     * @param historicalContext 과거 이력 컨텍스트
     * @param baselineContext 사용자 baseline 컨텍스트 (raw 데이터)
     * @return LLM 프롬프트 문자열
     *
     * Phase 9: deviationAnalysis 파라미터 제거 (AI Native 위반)
     * - analyzeDeviations() 제거로 불필요
     * - LLM이 baselineContext의 raw 데이터를 직접 비교하여 판단
     *
     * AI Native v4.2.0: systemContext 파라미터 제거
     * - 모든 필드가 항상 null (metadata에 설정 코드 없음)
     * - 프롬프트에서 사용되지 않음
     */
    public String buildPrompt(SecurityEvent event,
                               SecurityDecision layer1Decision,
                               SecurityDecision layer2Decision,
                               ThreatIntelligence threatIntel,
                               HistoricalContext historicalContext,
                               String baselineContext) {
        // Phase 4: getDecodedPayload() 사용 (Base64/URL 인코딩 자동 디코딩)
        Optional<String> decodedPayload = eventEnricher.getDecodedPayload(event);

        // AI Native v4.1.0: Severity 제거 - LLM이 원시 데이터로 직접 판단
        // AI Native: null인 경우 프롬프트에서 생략
        // AI Native v3.3.0: 프롬프트 인젝션 방어 적용
        String userId = PromptTemplateUtils.sanitizeUserInput(event.getUserId());
        String fullPayload = PromptTemplateUtils.sanitizeUserInput(decodedPayload.orElse("empty"));

        String networkSection = buildNetworkSection(event);
        // Phase 22: buildDataQualitySection() 사용 - 누락 필드 명시적 표시
        String dataQualitySection = PromptTemplateUtils.buildDataQualitySection(event);

        // Threat Intelligence 핵심 (AI Native: null 체크)
        StringBuilder threatBuilder = new StringBuilder();
        // AI Native: reputationScore 제거 - 항상 0.0 (설정 코드 없음, 죽은 데이터)
        // AI Native: iocMatches 제거 - 항상 빈 문자열 (죽은 데이터)

        // Truncation 정책 적용
        TieredStrategyProperties.Truncation.Layer3Truncation layer3Truncation =
            tieredStrategyProperties.getTruncation().getLayer3();

        String knownActors = threatIntel.getKnownActors();
        if (knownActors != null && !knownActors.isEmpty()) {
            threatBuilder.append(" | Actors: ").append(knownActors.substring(0, Math.min(200, knownActors.length())));
        }

        // relatedCampaigns 추가 (AI Native: null 체크)
        String campaigns = threatIntel.getRelatedCampaigns();
        if (campaigns != null && !campaigns.isEmpty()) {
            int maxCampaigns = layer3Truncation.getCampaigns();
            String campaignsSummary = campaigns.length() > maxCampaigns
                ? campaigns.substring(0, maxCampaigns - 3) + "..." : campaigns;
            threatBuilder.append("\nCampaigns: ").append(campaignsSummary);
        }
        String threatSummary = threatBuilder.toString();

        // Historical Context (AI Native: null 체크)
        StringBuilder historyBuilder = new StringBuilder();

        String previousAttacks = historicalContext.getPreviousAttacks();
        if (previousAttacks != null && !previousAttacks.isEmpty()) {
            historyBuilder.append("Previous: ").append(previousAttacks.substring(0, Math.min(30, previousAttacks.length())));
        }

        String similarIncidents = historicalContext.getSimilarIncidents();
        if (similarIncidents != null && !similarIncidents.isEmpty()) {
            if (historyBuilder.length() > 0) historyBuilder.append(" | ");
            historyBuilder.append("Similar: ").append(similarIncidents.substring(0, Math.min(30, similarIncidents.length())));
        }

        // AI Native: vulnerabilityHistory 제거 - 항상 빈 문자열 (죽은 데이터)
        String historySummary = historyBuilder.toString();

        // AI Native: SystemContext 제거 - asset.criticality, data.sensitivity,
        // compliance.requirements, security.posture 모두 설정 코드 없음 (항상 null, 죽은 데이터)

        // AI Native v4.0: Baseline 컨텍스트 섹션 (항상 출력 - Zero Trust)
        // STATUS 라벨 추가: 상태 메시지와 실제 데이터를 명확히 구분하여 LLM 오인 방지
        StringBuilder baselineSectionBuilder = new StringBuilder();
        baselineSectionBuilder.append("=== USER BEHAVIOR BASELINE ===\n");
        if (isValidBaseline(baselineContext)) {
            // 유효한 baseline 데이터 - sanitization 적용
            String sanitizedBaseline = PromptTemplateUtils.sanitizeUserInput(baselineContext);
            baselineSectionBuilder.append("STATUS: Available\n");
            baselineSectionBuilder.append(sanitizedBaseline);
        } else if (baselineContext != null && baselineContext.startsWith("[")) {
            // 상태 메시지 (SERVICE_UNAVAILABLE, NO_USER_ID, NO_DATA)
            baselineSectionBuilder.append("STATUS: ").append(baselineContext).append("\n");
            baselineSectionBuilder.append("IMPACT: Anomaly detection unavailable");
        } else {
            baselineSectionBuilder.append("STATUS: [NEW_USER] No baseline established for this user\n");
            baselineSectionBuilder.append("IMPACT: Cannot compare against historical patterns");
        }
        String baselineSection = baselineSectionBuilder.toString();

        // Phase 5: metadata에서 추출한 풍부한 컨텍스트 정보 제공
        // AI Native v3.3.0: 4개 Action (ALLOW/BLOCK/CHALLENGE/ESCALATE)
        StringBuilder prompt = new StringBuilder();
        prompt.append("Expert forensic security analysis with behavioral baseline comparison.\n\n");

        // 1. 이벤트 기본 정보 (AI Native: null 값 조건부 출력)
        prompt.append("=== EVENT ===\n");
        if (userId != null) {
            prompt.append("User: ").append(userId).append("\n");
        }

        // AI Native v4.1.0: 원시 메트릭 제공 (Severity 대신 LLM이 직접 위험도 평가)
        // AI Native v4.3.0: TrustScore 제거 - LLM은 riskScore만 반환하며
        // TrustScore(=1-riskScore)는 역관계로 혼란 유발. EMA 학습에서만 내부 사용.
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null) {
            appendMetadataIfPresent(prompt, metadata, "auth.failure_count", "FailureCount");
        }

        // 2. 네트워크 정보 (Zero Trust: 필수 출력)
        // IP, SessionId 누락 시 NOT_PROVIDED 표시하여 LLM에게 경고
        prompt.append("\n=== NETWORK ===\n");
        prompt.append(networkSection).append("\n");

        // 3. 페이로드 정보 (있는 경우만, Truncation 정책 적용)
        if (!"empty".equals(fullPayload)) {
            prompt.append("\n=== PAYLOAD ===\n");
            int maxPayload = layer3Truncation.getPayload();
            String payloadSummary = fullPayload.length() > maxPayload
                ? fullPayload.substring(0, maxPayload) + "..." : fullPayload;
            prompt.append(payloadSummary).append("\n");
        }

        // AI Native v4.0: Layer1/Layer2 분석 결과 - NaN 체크 추가 (LLM 혼란 방지)
        // NaN 검증: LLM이 "Risk=NaN"을 이해하지 못하므로 "[NOT_ANALYZED]" 라벨 사용
        prompt.append("\n=== PREVIOUS LAYER ANALYSIS ===\n");

        // Layer1 결과
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
        int maxReasoning = layer3Truncation.getReasoning();
        if (layer1Decision.getReasoning() != null && !layer1Decision.getReasoning().isEmpty()) {
            String reasoning = layer1Decision.getReasoning();
            if (reasoning.length() > maxReasoning) {
                reasoning = reasoning.substring(0, maxReasoning - 3) + "...";
            }
            prompt.append("L1 Reason: ").append(reasoning).append("\n");
        }

        // Layer2 결과
        double l2RiskScore = layer2Decision.getRiskScore();
        String l2RiskStr = Double.isNaN(l2RiskScore) ? "[NOT_ANALYZED]" : String.format("%.2f", l2RiskScore);
        prompt.append("Layer2: Risk=").append(l2RiskStr);
        if (layer2Decision.getAction() != null) {
            prompt.append(" | Action=").append(layer2Decision.getAction().toString());
        }
        // AI Native v3.0: Layer2 confidence 추가 - LLM이 Layer2 판단의 신뢰도를 참고하여 최종 판단
        Double l2Confidence = layer2Decision.getConfidence();
        if (l2Confidence != null && !l2Confidence.isNaN()) {
            prompt.append(" | Confidence=").append(String.format("%.2f", l2Confidence));
        }
        if (layer2Decision.getThreatCategory() != null) {
            prompt.append(" | Category=").append(layer2Decision.getThreatCategory());
        }
        prompt.append("\n");
        if (layer2Decision.getReasoning() != null && !layer2Decision.getReasoning().isEmpty()) {
            String reasoning = layer2Decision.getReasoning();
            if (reasoning.length() > maxReasoning) {
                reasoning = reasoning.substring(0, maxReasoning - 3) + "...";
            }
            prompt.append("L2 Reason: ").append(reasoning).append("\n");
        }

        // 6. 위협 인텔리전스
        prompt.append("\n=== THREAT INTELLIGENCE ===\n");
        prompt.append(threatSummary).append("\n");

        // 7. 과거 이력 - 항상 출력 (Zero Trust)
        prompt.append("\n=== HISTORICAL CONTEXT ===\n");
        if (!historySummary.isEmpty()) {
            prompt.append(historySummary).append("\n");
        } else {
            prompt.append("[NO_DATA] No historical context available for this event\n");
        }

        // AI Native: SYSTEM CONTEXT 섹션 제거 - 모든 필드가 항상 null (죽은 데이터)

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
            E (ESCALATE): Requires human security analyst review

            === RESPONSE FORMAT ===
            {"r":<0-1>,"c":<0-1>,"a":"A|B|C|E","d":"<reason>","m":"<MITRE>","rec":"<recommendation>","i":<boolean>}

            r: Your risk assessment (0=safe, 1=critical threat)
            c: Your confidence level (0=uncertain, 1=certain)
            a: Your action decision
            d: Detailed reasoning (max 50 tokens)
            m: MITRE ATT&CK technique if applicable (e.g., T1078, T1566)
            rec: Recommendation for SOC (max 20 tokens)
            i: Create security incident (true if B selected)
            """);

        return prompt.toString();
    }

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
            int maxUserAgent = tieredStrategyProperties.getTruncation().getLayer3().getUserAgent();
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

    /**
     * metadata에서 문자열 값 안전하게 추출 (AI Native)
     * PromptTemplateUtils로 위임
     */
    private String getStringFromMetadata(Map<String, Object> metadata, String key) {
        return PromptTemplateUtils.getStringFromMetadata(metadata, key);
    }

    /**
     * 클래스 풀네임에서 심플 클래스명 추출 (AI Native)
     * PromptTemplateUtils로 위임
     */
    private String extractSimpleClassName(String fullClassName) {
        return PromptTemplateUtils.extractSimpleClassName(fullClassName);
    }

    /**
     * 데이터 품질 점수 계산 (0-10)
     * LLM이 판단의 신뢰도를 조절하는 데 참고
     * PromptTemplateUtils로 위임
     */
    private int calculateDataQuality(SecurityEvent event) {
        return PromptTemplateUtils.calculateDataQuality(event);
    }

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
     * ThreatIntelligence - AI Native
     *
     * AI Native 원칙: 기본값 "none" 제거
     * - 값이 없으면 null 반환
     * - 호출부에서 null 체크 후 프롬프트 생략
     *
     * AI Native v4.2.0: Dead Code 제거
     * - iocMatches: 항상 빈 문자열 (Line 94 주석 참조)
     * - reputationScore: 항상 0.0 (Line 93 주석 참조)
     */
    public static class ThreatIntelligence {
        private String knownActors;
        private String relatedCampaigns;

        // AI Native: 기본값 없이 null 반환
        public String getKnownActors() { return knownActors; }
        public void setKnownActors(String knownActors) { this.knownActors = knownActors; }

        public String getRelatedCampaigns() { return relatedCampaigns; }
        public void setRelatedCampaigns(String relatedCampaigns) { this.relatedCampaigns = relatedCampaigns; }
    }

    /**
     * HistoricalContext - AI Native
     *
     * AI Native 원칙: 기본값 "none" 제거
     * - 값이 없으면 null 반환
     * - 호출부에서 null 체크 후 프롬프트 생략
     *
     * AI Native v4.2.0: Dead Code 제거
     * - vulnerabilityHistory: 항상 빈 리스트 (Line 129 주석 참조)
     */
    public static class HistoricalContext {
        private String similarIncidents;
        private String previousAttacks;

        // AI Native: 기본값 없이 null 반환
        public String getSimilarIncidents() { return similarIncidents; }
        public void setSimilarIncidents(String similarIncidents) { this.similarIncidents = similarIncidents; }

        public String getPreviousAttacks() { return previousAttacks; }
        public void setPreviousAttacks(String previousAttacks) { this.previousAttacks = previousAttacks; }
    }

    // AI Native v4.2.0: SystemContext 클래스 삭제
    // - asset.criticality, data.sensitivity, compliance.requirements, security.posture
    //   모두 metadata에 설정 코드 없음 (항상 null, 죽은 데이터)
    // - buildPrompt()에서 프롬프트에 포함되지 않음 (Line 247 주석 참조)
    // - LLM이 targetResource 경로를 보고 직접 판단
}