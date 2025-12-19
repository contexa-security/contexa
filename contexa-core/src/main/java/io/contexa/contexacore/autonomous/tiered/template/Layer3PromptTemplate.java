package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

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

    @Autowired
    public Layer3PromptTemplate(@Autowired(required = false) SecurityEventEnricher eventEnricher) {
        this.eventEnricher = eventEnricher != null ? eventEnricher : new SecurityEventEnricher();
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
        Optional<String> targetResource = eventEnricher.getTargetResource(event);
        Optional<String> httpMethod = eventEnricher.getHttpMethod(event);
        Optional<Object> payload = eventEnricher.getRequestPayload(event);

        String eventType = event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN";
        String sourceIp = event.getSourceIp() != null ? event.getSourceIp() : "unknown";
        String userAgent = event.getUserAgent() != null ? event.getUserAgent() : "unknown";
        String target = targetResource.orElse("unknown");
        String method = httpMethod.orElse("unknown");
        String fullPayload = payload.map(Object::toString).orElse("empty");

        // Layer1/2 결과 극도로 축약
        String previousAnalysis = String.format("L1: Risk %.1f/%s | L2: Risk %.1f/%s",
            layer1Decision.getRiskScore(),
            layer1Decision.getAction() != null ? layer1Decision.getAction().toString() : "?",
            layer2Decision.getRiskScore(),
            layer2Decision.getThreatCategory() != null ? layer2Decision.getThreatCategory() : "?");

        // Threat Intelligence 핵심만
        String threatSummary = String.format("Reputation: %.1f | IOC: %s | Actors: %s",
            threatIntel.getReputationScore(),
            threatIntel.getIocMatches().isEmpty() || "none".equals(threatIntel.getIocMatches()) ? "none" :
                threatIntel.getIocMatches().substring(0, Math.min(30, threatIntel.getIocMatches().length())),
            threatIntel.getKnownActors().isEmpty() || "none".equals(threatIntel.getKnownActors()) ? "none" :
                threatIntel.getKnownActors().substring(0, Math.min(30, threatIntel.getKnownActors().length())));

        // Historical Context 핵심만
        String historySummary = String.format("Previous: %s | Similar: %s",
            historicalContext.getPreviousAttacks().isEmpty() || "none".equals(historicalContext.getPreviousAttacks()) ? "none" :
                historicalContext.getPreviousAttacks().substring(0, Math.min(30, historicalContext.getPreviousAttacks().length())),
            historicalContext.getSimilarIncidents().isEmpty() || "none".equals(historicalContext.getSimilarIncidents()) ? "none" :
                historicalContext.getSimilarIncidents().substring(0, Math.min(30, historicalContext.getSimilarIncidents().length())));

        // System Context 핵심만
        String systemSummary = String.format("Asset: %s | Data: %s",
            systemContext.getAssetCriticality(),
            systemContext.getDataSensitivity());

        // HCAD 위험도 분석 결과 추가
        String hcadSection = buildHCADSection(event);

        // AI Native (Phase 9): Baseline 컨텍스트 섹션
        // buildBaselinePromptContext()가 raw 데이터 제공 (Normal IPs, Current IP, Hours 등)
        // LLM이 직접 비교하여 ALLOW/BLOCK/ESCALATE 판단
        // deviationSection 제거됨 - analyzeDeviations() 제거로 불필요
        String baselineSection = (baselineContext != null && !baselineContext.isEmpty())
            ? "=== USER BEHAVIOR BASELINE ===\n" + baselineContext
            : "=== USER BEHAVIOR BASELINE ===\nBaseline: Not available for expert analysis";

        // Phase 9: deviationSection 제거, LLM이 baselineSection의 raw 데이터를 직접 비교
        return String.format("""
            Expert forensic security analysis. Deep threat analysis with behavioral baseline comparison.

            Event: %s | IP: %s | UA: %s | Target: %s | Method: %s
            Payload: %s
            Previous: %s
            Threat: %s
            History: %s
            System: %s
            %s

            %s

            USER-AGENT ANALYSIS (Expert-level):
            - Browser (Chrome/Firefox/Safari/Edge with version): Normal user traffic
            - curl/wget: Command-line automation - check for reconnaissance patterns
            - python-requests/httpx/aiohttp: Scripting tools - analyze request patterns for bot behavior
            - Headless browsers (HeadlessChrome, PhantomJS): Potential scraping or automation
            - Empty/Unknown/Malformed: Strong attack indicator, correlate with other threat signals

            SCORING GUIDELINES (Expert-level):
            1. ZERO TRUST: Unknown != Safe. Insufficient intelligence requires conservative assessment.
            2. BEHAVIORAL BASELINE ANALYSIS (CRITICAL):
               - Compare current request against user's established behavior patterns
               - Baseline raw data: Normal IPs vs Current IP, Normal Hours vs Current Hour
               - Compare paths, devices, user-agents against baseline
               - Deviation from baseline + threat intelligence = strong attack indicator
            3. BASELINE DEVIATION + THREAT CORRELATION:
               - Within baseline + no threat indicators = likely legitimate
               - Within baseline + threat indicators = possible insider threat
               - Outside baseline + no threat indicators = possible account takeover
               - Outside baseline + threat indicators = likely confirmed attack
            4. HCAD Risk Score: Integrate with baseline comparison and threat intelligence.
            5. Threat Intelligence:
               - Reputation score: Higher values indicate more trust
               - IOC matches: Consider matches as elevated risk signals
               - Known actors: Attribution context for threat assessment
            6. Historical Context:
               - Previous attacks: Prior incident history informs current risk
               - Similar incidents: Pattern matching for threat correlation
            7. System Context:
               - Asset criticality: Higher criticality warrants elevated concern
               - Data sensitivity: Sensitive data requires conservative assessment
            8. Risk Classification:
               - BENIGN: Within baseline + trusted patterns + no threat indicators
               - LOW_RISK: Within baseline + multiple trust signals
               - UNKNOWN: Insufficient baseline or intelligence
               - SUSPICIOUS: Outside baseline OR partial threat indicators
               - MALICIOUS: Outside baseline + confirmed attack patterns
               - CRITICAL_THREAT: APT/Ransomware indicators + behavioral anomaly

            Respond: riskScore(0.0-1.0), confidence(0.0-1.0), action(ALLOW/BLOCK/ESCALATE), reasoning(1 sentence).

            IMPORTANT:
            - riskScore: 0.0 (completely safe) to 1.0 (critical threat)
            - confidence: Express your certainty level in the assessment
            - Compare current request against baseline raw data (IPs, Hours, Paths)
            - Add reasoning: "[NEW_IP]" or "[ODD_HOUR]" when behavioral anomaly detected

            JSON format:
            {"riskScore": <number>, "confidence": <number>, "action": "ALLOW", "reasoning": "..."}
            """,
            eventType, sourceIp, userAgent, target, method,
            fullPayload.length() > 200 ? fullPayload.substring(0, 200) + "..." : fullPayload,
            previousAnalysis, threatSummary, historySummary, systemSummary, hcadSection,
            baselineSection);
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
            return "HCAD Analysis: Not available (requires LLM expert analysis)";
        }

        // AI Native: raw 데이터만 제공, 임계값 기반 assessment 제거
        // LLM이 riskScore를 해석하여 action(ALLOW/BLOCK/INVESTIGATE)을 결정
        return String.format("""
            HCAD Risk Analysis:
            - Risk Score: %.3f
            - Layer3 Expert: Determine action based on this score and threat intelligence""",
            riskScore
        );
    }

    public static class ThreatIntelligence {
        private String knownActors;
        private String relatedCampaigns;
        private String iocMatches;
        private double reputationScore;

        public String getKnownActors() { return knownActors != null ? knownActors : "none"; }
        public void setKnownActors(String knownActors) { this.knownActors = knownActors; }

        public String getRelatedCampaigns() { return relatedCampaigns != null ? relatedCampaigns : "none"; }
        public void setRelatedCampaigns(String relatedCampaigns) { this.relatedCampaigns = relatedCampaigns; }

        public String getIocMatches() { return iocMatches != null ? iocMatches : "none"; }
        public void setIocMatches(String iocMatches) { this.iocMatches = iocMatches; }

        public double getReputationScore() { return reputationScore; }
        public void setReputationScore(double reputationScore) { this.reputationScore = reputationScore; }
    }

    public static class HistoricalContext {
        private String similarIncidents;
        private String previousAttacks;
        private String vulnerabilityHistory;

        public String getSimilarIncidents() { return similarIncidents != null ? similarIncidents : "none"; }
        public void setSimilarIncidents(String similarIncidents) { this.similarIncidents = similarIncidents; }

        public String getPreviousAttacks() { return previousAttacks != null ? previousAttacks : "none"; }
        public void setPreviousAttacks(String previousAttacks) { this.previousAttacks = previousAttacks; }

        public String getVulnerabilityHistory() { return vulnerabilityHistory != null ? vulnerabilityHistory : "none"; }
        public void setVulnerabilityHistory(String vulnerabilityHistory) { this.vulnerabilityHistory = vulnerabilityHistory; }
    }

    public static class SystemContext {
        private String assetCriticality;
        private String dataSensitivity;
        private String complianceRequirements;
        private String securityPosture;

        public String getAssetCriticality() { return assetCriticality != null ? assetCriticality : "MEDIUM"; }
        public void setAssetCriticality(String assetCriticality) { this.assetCriticality = assetCriticality; }

        public String getDataSensitivity() { return dataSensitivity != null ? dataSensitivity : "MEDIUM"; }
        public void setDataSensitivity(String dataSensitivity) { this.dataSensitivity = dataSensitivity; }

        public String getComplianceRequirements() { return complianceRequirements != null ? complianceRequirements : "none"; }
        public void setComplianceRequirements(String complianceRequirements) { this.complianceRequirements = complianceRequirements; }

        public String getSecurityPosture() { return securityPosture != null ? securityPosture : "NORMAL"; }
        public void setSecurityPosture(String securityPosture) { this.securityPosture = securityPosture; }
    }
}