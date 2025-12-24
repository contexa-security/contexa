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
public class Layer3PromptTemplate {

    private final SecurityEventEnricher eventEnricher;
    private final TieredStrategyProperties tieredStrategyProperties;

    @Autowired
    public Layer3PromptTemplate(
            @Autowired(required = false) SecurityEventEnricher eventEnricher,
            @Autowired(required = false) TieredStrategyProperties tieredStrategyProperties) {
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
        this.tieredStrategyProperties = tieredStrategyProperties != null
            ? tieredStrategyProperties : new TieredStrategyProperties();
    }

    /**
     * Layer3 프롬프트 생성 (기본 버전 - 하위 호환)
     * Phase 9: deviationAnalysis 파라미터 제거
     */
    public String buildPrompt(SecurityEvent event,
                               SecurityDecision layer1Decision,
                               SecurityDecision layer2Decision,
                               ThreatIntelligence threatIntel,
                               HistoricalContext historicalContext,
                               SystemContext systemContext) {
        return buildPrompt(event, layer1Decision, layer2Decision, threatIntel,
                           historicalContext, systemContext, null);
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
     * @param systemContext 시스템 컨텍스트
     * @param baselineContext 사용자 baseline 컨텍스트 (raw 데이터)
     * @return LLM 프롬프트 문자열
     *
     * Phase 9: deviationAnalysis 파라미터 제거 (AI Native 위반)
     * - analyzeDeviations() 제거로 불필요
     * - LLM이 baselineContext의 raw 데이터를 직접 비교하여 판단
     */
    public String buildPrompt(SecurityEvent event,
                               SecurityDecision layer1Decision,
                               SecurityDecision layer2Decision,
                               ThreatIntelligence threatIntel,
                               HistoricalContext historicalContext,
                               SystemContext systemContext,
                               String baselineContext) {
        // Phase 4: getDecodedPayload() 사용 (Base64/URL 인코딩 자동 디코딩)
        Optional<String> decodedPayload = eventEnricher.getDecodedPayload(event);

        // AI Native: "UNKNOWN" 기본값 제거, null 그대로 처리
        String eventType = event.getEventType() != null ? event.getEventType().toString() : null;
        String severity = event.getSeverity() != null ? event.getSeverity().name() : "MEDIUM";
        // AI Native: null인 경우 프롬프트에서 생략
        String userId = event.getUserId();
        String fullPayload = decodedPayload.orElse("empty");

        // Phase 5: metadata에서 authz 정보 추출 (Layer1 패턴 적용)
        String authzSection = buildAuthzSection(event);
        String networkSection = buildNetworkSection(event);
        // Phase 22: buildDataQualitySection() 사용 - 누락 필드 명시적 표시
        String dataQualitySection = PromptTemplateUtils.buildDataQualitySection(event);

        // Threat Intelligence 핵심 (AI Native: null 체크)
        StringBuilder threatBuilder = new StringBuilder();
        threatBuilder.append("Reputation: ").append(String.format("%.1f", threatIntel.getReputationScore()));

        // Truncation 정책 적용
        TieredStrategyProperties.Truncation.Layer3Truncation layer3Truncation =
            tieredStrategyProperties.getTruncation().getLayer3();

        String iocMatches = threatIntel.getIocMatches();
        if (iocMatches != null && !iocMatches.isEmpty()) {
            // SHA-256 해시(64자), URL 등 전체 IOC 데이터 유지
            int maxIoc = layer3Truncation.getIocMatches();
            threatBuilder.append(" | IOC: ").append(iocMatches.substring(0, Math.min(maxIoc, iocMatches.length())));
        }

        String knownActors = threatIntel.getKnownActors();
        if (knownActors != null && !knownActors.isEmpty()) {
            threatBuilder.append(" | Actors: ").append(knownActors.substring(0, Math.min(30, knownActors.length())));
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

        // vulnerabilityHistory 추가 (AI Native: null 체크, Truncation 정책 적용)
        String vulnHistory = historicalContext.getVulnerabilityHistory();
        if (vulnHistory != null && !vulnHistory.isEmpty()) {
            int maxVulnerabilities = layer3Truncation.getVulnerabilities();
            String vulnSummary = vulnHistory.length() > maxVulnerabilities
                ? vulnHistory.substring(0, maxVulnerabilities - 3) + "..." : vulnHistory;
            historyBuilder.append("\nVulnerabilities: ").append(vulnSummary);
        }
        String historySummary = historyBuilder.toString();

        // AI Native: System Context - metadata에 있는 실제 값만 포함 (기본값 제거)
        // 값이 없으면 해당 필드 생략, LLM이 targetResource 경로로 직접 판단
        StringBuilder systemBuilder = new StringBuilder();
        String assetCrit = systemContext.getAssetCriticality();
        String dataSens = systemContext.getDataSensitivity();
        String compliance = systemContext.getComplianceRequirements();
        String posture = systemContext.getSecurityPosture();

        // 실제 값이 있는 필드만 포함
        if (assetCrit != null && !assetCrit.isEmpty()) {
            systemBuilder.append("Asset: ").append(assetCrit);
        }
        if (dataSens != null && !dataSens.isEmpty()) {
            if (systemBuilder.length() > 0) systemBuilder.append(" | ");
            systemBuilder.append("Data: ").append(dataSens);
        }
        if (compliance != null && !compliance.isEmpty()) {
            if (systemBuilder.length() > 0) systemBuilder.append("\n");
            int maxCompliance = layer3Truncation.getCompliance();
            String compSummary = compliance.length() > maxCompliance
                ? compliance.substring(0, maxCompliance - 3) + "..." : compliance;
            systemBuilder.append("Compliance: ").append(compSummary);
        }
        if (posture != null && !posture.isEmpty()) {
            if (systemBuilder.length() > 0) systemBuilder.append(" | ");
            systemBuilder.append("Posture: ").append(posture);
        }
        String systemSummary = systemBuilder.toString();

        // AI Native (Phase 9): Baseline 컨텍스트 섹션
        // Phase 2-7: null -> N/A 명시적 표현
        String baselineSection = (baselineContext != null && !baselineContext.isEmpty())
            ? "=== USER BEHAVIOR BASELINE ===\n" + baselineContext
            : "=== USER BEHAVIOR BASELINE ===\nBaseline: N/A (Not available for expert analysis)";

        // Phase 5: metadata에서 추출한 풍부한 컨텍스트 정보 제공
        // AI Native v3.3.0: 4개 Action (ALLOW/BLOCK/CHALLENGE/ESCALATE)
        StringBuilder prompt = new StringBuilder();
        prompt.append("Expert forensic security analysis with behavioral baseline comparison.\n\n");

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

        // 2. 네트워크 정보 (Zero Trust: 필수 출력)
        // IP, SessionId 누락 시 NOT_PROVIDED 표시하여 LLM에게 경고
        prompt.append("\n=== NETWORK ===\n");
        prompt.append(networkSection).append("\n");

        // 3. Authorization 정보 (metadata에서 추출)
        if (!authzSection.isEmpty()) {
            prompt.append("\n=== AUTHORIZATION ===\n");
            prompt.append(authzSection).append("\n");
        }

        // 4. 페이로드 정보 (있는 경우만, Truncation 정책 적용)
        if (!"empty".equals(fullPayload)) {
            prompt.append("\n=== PAYLOAD ===\n");
            int maxPayload = layer3Truncation.getPayload();
            String payloadSummary = fullPayload.length() > maxPayload
                ? fullPayload.substring(0, maxPayload) + "..." : fullPayload;
            prompt.append(payloadSummary).append("\n");
        }

        // 5. Layer1/Layer2 분석 결과 (AI Native: null 값 조건부 출력, "?" 기본값 제거)
        prompt.append("\n=== PREVIOUS LAYER ANALYSIS ===\n");
        prompt.append("Layer1: Risk=").append(String.format("%.2f", layer1Decision.getRiskScore()));
        if (layer1Decision.getAction() != null) {
            prompt.append(" | Action=").append(layer1Decision.getAction().toString());
        }
        Double l1Confidence = layer1Decision.getConfidence();
        if (l1Confidence != null) {
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
        prompt.append("Layer2: Risk=").append(String.format("%.2f", layer2Decision.getRiskScore()));
        if (layer2Decision.getAction() != null) {
            prompt.append(" | Action=").append(layer2Decision.getAction().toString());
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

        // 7. 과거 이력 (AI Native: 빈 경우 생략)
        if (!historySummary.isEmpty()) {
            prompt.append("\n=== HISTORICAL CONTEXT ===\n");
            prompt.append(historySummary).append("\n");
        }

        // 8. 시스템 컨텍스트 (AI Native: 실제 metadata 값이 있을 때만 포함)
        if (!systemSummary.isEmpty()) {
            prompt.append("\n=== SYSTEM CONTEXT ===\n");
            prompt.append(systemSummary).append("\n");
        }

        // 9. 사용자 Baseline
        prompt.append("\n").append(baselineSection).append("\n");

        // 11. 데이터 품질 평가 (AI Native: 누락 필드 명시)
        // buildDataQualitySection()이 누락 필드 목록과 CRITICAL 경고 포함
        prompt.append("\n=== DATA QUALITY ===\n");
        prompt.append(dataQualitySection);

        // 12. 응답 형식 (AI Native v3.4.0 - 액션 우선 원칙)
        prompt.append("""

            === RESPONSE FORMAT ===
            {"r":<0-1>,"c":<0-1>,"a":"A|B|C|E","d":"<reason>","m":"<MITRE>","rec":"<recommendation>"}
            a: YOUR FINAL DECISION (one of A/B/C/E) - Action is primary
            r: risk level supporting your action (0=safe, 1=attack) - for traceability
            c: your confidence in this decision (0-1)
            d: brief reason (max 30 tokens)
            m: MITRE ATT&CK technique if applicable (e.g., T1078, T1566)
            rec: specific recommendation for SOC (max 20 tokens)

            === ACTION GUIDE (Expert Level) ===
            A (ALLOW): Verified safe, no threat indicators -> r~0.0-0.2
            B (BLOCK): Confirmed attack (IOC match, MITRE confirmed, malware) -> r~0.9-1.0
            C (CHALLENGE): Strong suspicion, needs MFA/human verification -> r~0.6-0.9
            E (ESCALATE): HUMAN SOC ANALYST REQUIRED - Layer3 cannot decide -> any r, low c
               Use E when: conflicting evidence, APT-like patterns, or novel attack

            === AI NATIVE PRINCIPLE ===
            - This is the FINAL layer. YOU must make a decision.
            - E (ESCALATE) means "require human SOC analyst" - use only when truly uncertain.
            - For APT/zero-day patterns: prefer C (CHALLENGE) with detailed reasoning.
            - Action takes precedence over risk score if they conflict.
            - Always provide MITRE technique (m) if threat is detected.
            """);

        return prompt.toString();
    }

    /**
     * Phase 5: metadata에서 Authorization 정보 추출 (Layer1 패턴 적용)
     * PromptTemplateUtils로 위임
     */
    private String buildAuthzSection(SecurityEvent event) {
        return PromptTemplateUtils.buildAuthzSection(event);
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
            int maxUserAgent = tieredStrategyProperties.getTruncation().getLayer3().getUserAgent();
            if (ua.length() > maxUserAgent) {
                ua = ua.substring(0, maxUserAgent - 3) + "...";
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
            network.append("HttpMethod: ").append(httpMethod.get()).append("\n");
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
     * ThreatIntelligence - AI Native
     *
     * AI Native 원칙: 기본값 "none" 제거
     * - 값이 없으면 null 반환
     * - 호출부에서 null 체크 후 프롬프트 생략
     */
    public static class ThreatIntelligence {
        private String knownActors;
        private String relatedCampaigns;
        private String iocMatches;
        private double reputationScore;

        // AI Native: 기본값 없이 null 반환
        public String getKnownActors() { return knownActors; }
        public void setKnownActors(String knownActors) { this.knownActors = knownActors; }

        public String getRelatedCampaigns() { return relatedCampaigns; }
        public void setRelatedCampaigns(String relatedCampaigns) { this.relatedCampaigns = relatedCampaigns; }

        public String getIocMatches() { return iocMatches; }
        public void setIocMatches(String iocMatches) { this.iocMatches = iocMatches; }

        public double getReputationScore() { return reputationScore; }
        public void setReputationScore(double reputationScore) { this.reputationScore = reputationScore; }
    }

    /**
     * HistoricalContext - AI Native
     *
     * AI Native 원칙: 기본값 "none" 제거
     * - 값이 없으면 null 반환
     * - 호출부에서 null 체크 후 프롬프트 생략
     */
    public static class HistoricalContext {
        private String similarIncidents;
        private String previousAttacks;
        private String vulnerabilityHistory;

        // AI Native: 기본값 없이 null 반환
        public String getSimilarIncidents() { return similarIncidents; }
        public void setSimilarIncidents(String similarIncidents) { this.similarIncidents = similarIncidents; }

        public String getPreviousAttacks() { return previousAttacks; }
        public void setPreviousAttacks(String previousAttacks) { this.previousAttacks = previousAttacks; }

        public String getVulnerabilityHistory() { return vulnerabilityHistory; }
        public void setVulnerabilityHistory(String vulnerabilityHistory) { this.vulnerabilityHistory = vulnerabilityHistory; }
    }

    /**
     * AI Native: SystemContext - 기본값 제거
     *
     * 규칙 기반 기본값 완전 제거:
     * - null이면 null 반환 (기본값 MEDIUM/NORMAL 등 사용 금지)
     * - 프롬프트에서 null인 필드는 생략
     * - LLM이 targetResource 경로를 보고 직접 판단
     */
    public static class SystemContext {
        private String assetCriticality;
        private String dataSensitivity;
        private String complianceRequirements;
        private String securityPosture;

        // AI Native: 기본값 없이 null 반환
        public String getAssetCriticality() { return assetCriticality; }
        public void setAssetCriticality(String assetCriticality) { this.assetCriticality = assetCriticality; }

        public String getDataSensitivity() { return dataSensitivity; }
        public void setDataSensitivity(String dataSensitivity) { this.dataSensitivity = dataSensitivity; }

        public String getComplianceRequirements() { return complianceRequirements; }
        public void setComplianceRequirements(String complianceRequirements) { this.complianceRequirements = complianceRequirements; }

        public String getSecurityPosture() { return securityPosture; }
        public void setSecurityPosture(String securityPosture) { this.securityPosture = securityPosture; }
    }
}