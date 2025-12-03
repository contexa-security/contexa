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

    public String buildPrompt(SecurityEvent event,
                               SecurityDecision layer1Decision,
                               SecurityDecision layer2Decision,
                               ThreatIntelligence threatIntel,
                               HistoricalContext historicalContext,
                               SystemContext systemContext) {
        Optional<String> targetResource = eventEnricher.getTargetResource(event);
        Optional<String> httpMethod = eventEnricher.getHttpMethod(event);
        Optional<Object> payload = eventEnricher.getRequestPayload(event);

        String eventType = event.getEventType() != null ? event.getEventType().toString() : "UNKNOWN";
        String sourceIp = event.getSourceIp() != null ? event.getSourceIp() : "unknown";
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

        return String.format("""
            Expert forensic security analysis. Deep threat analysis.

            Event: %s | IP: %s | Target: %s | Method: %s
            Payload: %s
            Previous: %s
            Threat: %s
            History: %s
            System: %s
            %s

            SCORING GUIDELINES (Expert-level):
            1. ZERO TRUST: Unknown != Safe. Insufficient intelligence requires conservative assessment.
            2. HCAD Risk Score: Provided as raw value. Integrate with other intelligence.
            3. Threat Intelligence:
               - Reputation score: Higher values indicate more trust
               - IOC matches: Consider matches as elevated risk signals
               - Known actors: Attribution context for threat assessment
            4. Historical Context:
               - Previous attacks: Prior incident history informs current risk
               - Similar incidents: Pattern matching for threat correlation
            5. System Context:
               - Asset criticality: Higher criticality warrants elevated concern
               - Data sensitivity: Sensitive data requires conservative assessment
            6. Risk Classification Principles:
               - BENIGN: Verified trusted with strong evidence
               - LOW_RISK: Multiple trust signals present
               - UNKNOWN: Insufficient intelligence for confident assessment
               - SUSPICIOUS: Partial threat indicators detected
               - MALICIOUS: Attack confirmed with evidence
               - CRITICAL_THREAT: APT/Ransomware indicators present

            Respond: riskScore(0.0-1.0), confidence(0.0-1.0), action(ALLOW/BLOCK/ESCALATE), reasoning(1 sentence).

            IMPORTANT:
            - riskScore: 0.0 (completely safe) to 1.0 (critical threat)
            - confidence: Express your certainty level in the assessment
            - Insufficient intelligence should be reflected in both riskScore and confidence
            - Add reasoning: "[DATA_MISSING: describe what]" when applicable

            JSON format:
            {"riskScore": <number>, "confidence": <number>, "action": "ALLOW", "reasoning": "..."}
            """,
            eventType, sourceIp, target, method,
            fullPayload.length() > 200 ? fullPayload.substring(0, 200) + "..." : fullPayload,
            previousAnalysis, threatSummary, historySummary, systemSummary, hcadSection);
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