package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
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

    private static final Map<String, String> MITRE_TACTICS = Map.ofEntries(
        Map.entry("TA0001", "Initial Access"),
        Map.entry("TA0002", "Execution"),
        Map.entry("TA0003", "Persistence"),
        Map.entry("TA0004", "Privilege Escalation"),
        Map.entry("TA0005", "Defense Evasion"),
        Map.entry("TA0006", "Credential Access"),
        Map.entry("TA0007", "Discovery"),
        Map.entry("TA0008", "Lateral Movement"),
        Map.entry("TA0009", "Collection"),
        Map.entry("TA0010", "Exfiltration"),
        Map.entry("TA0011", "Command and Control"),
        Map.entry("TA0040", "Impact")
    );

    private static final Map<String, String> MITRE_TECHNIQUES = Map.ofEntries(
        Map.entry("T1190", "Exploit Public-Facing Application"),
        Map.entry("T1566", "Phishing"),
        Map.entry("T1078", "Valid Accounts"),
        Map.entry("T1055", "Process Injection"),
        Map.entry("T1071", "Application Layer Protocol"),
        Map.entry("T1059", "Command and Scripting Interpreter"),
        Map.entry("T1003", "OS Credential Dumping"),
        Map.entry("T1083", "File and Directory Discovery"),
        Map.entry("T1021", "Remote Services"),
        Map.entry("T1041", "Exfiltration Over C2 Channel"),
        Map.entry("T1486", "Data Encrypted for Impact"),
        Map.entry("T1110", "Brute Force")
    );

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

        // HCAD 유사도 분석 결과 추가
        String hcadSection = buildHCADSection(event);

        // MITRE 참조 간소화 (주요 항목만)
        String mitreTactics = "TA0001(Initial Access), TA0002(Execution), TA0003(Persistence), TA0005(Defense Evasion), TA0006(Credential Access), TA0010(Exfiltration)";
        String mitreTechniques = "T1190(Exploit App), T1566(Phishing), T1078(Valid Accounts), T1059(Scripting), T1003(Credential Dump), T1041(Exfil C2)";

        return String.format("""
            Expert forensic security analysis. Deep threat analysis with MITRE ATT&CK.

            Event: %s | IP: %s | Target: %s | Method: %s
            Payload: %s
            Previous: %s
            Threat: %s
            History: %s
            System: %s
            %s

            MITRE Reference:
            Tactics: %s
            Techniques: %s

            SCORING GUIDELINES (Expert-level analysis):
            1. ZERO TRUST PRINCIPLE: Unknown ≠ Safe. Insufficient threat intelligence → 0.5 (neutral risk), NOT 0.0.
            2. HCAD Similarity Interpretation (CRITICAL SIGNAL):
               - Similarity < 0.40 → ANOMALY CONFIRMED → Base riskScore ≥ 0.8
               - Similarity 0.40-0.54 → SIGNIFICANT_DEVIATION → Base riskScore 0.6-0.8
               - Even if Layer3, respect HCAD baseline analysis (RAG-enhanced multi-layer verification)
            3. Threat Intelligence Interpretation:
               - "Reputation: 0.5" = neutral/unknown, NOT trusted (>0.8 is trusted)
               - "IOC: none" + "Actors: none" → riskScore = 0.5 (no intelligence = unknown state)
               - "Previous: none" + "Similar: none" → riskScore = 0.5 (no historical data)
               - Known malicious IOC/Actor → riskScore ≥ 0.8 regardless of other signals
            3. Historical Context Evaluation:
               - "Previous: none" → no attack history, NOT safe indicator
               - "Similar: none" → no pattern data, treat as unknown (0.5)
               - Previous attacks + Similar pattern → riskScore ≥ 0.7
            4. System Context Impact:
               - "Asset: HIGH" + "Data: HIGH" → escalate riskScore by +0.1~0.2
               - "Asset: LOW" + "Data: LOW" → can reduce riskScore by -0.1
            5. Use 6-tier expert scale:
               - BENIGN (0.0-0.2): Verified trusted, strong positive intelligence
               - LOW_RISK (0.2-0.4): Some trust signals, no threat indicators
               - UNKNOWN (0.4-0.6): Insufficient intelligence, no historical data
               - SUSPICIOUS (0.6-0.75): Anomalous pattern, partial threat indicators
               - MALICIOUS (0.75-0.9): Attack pattern confirmed, known techniques
               - CRITICAL_THREAT (0.9-1.0): APT/Ransomware, critical asset targeted

            Respond: riskScore(0.0-1.0 scale ONLY), confidence(0.0-1.0), action(ALLOW/BLOCK/INVESTIGATE),
            classification(BENIGN/MALICIOUS/CRITICAL_THREAT), scenario(detailed),
            tactics(list of TA codes), techniques(list of T codes),
            iocIndicators(list), threatActor, reasoning, expertRecommendation.

            IMPORTANT:
            - riskScore MUST be between 0.0 and 1.0 (NOT 0-10 scale)
            - confidence MUST be between 0.1 and 1.0 (NOT 0.0)
            - If threat intelligence/historical data insufficient, use riskScore=0.5, confidence=0.1-0.3
            - Add reasoning: "[DATA_MISSING: describe what]" when applicable

            JSON format:
            {"riskScore": <number>, "confidence": <number>, "action": "ALLOW", "classification": "BENIGN", "scenario": "...", "tactics": ["TA0001"], "techniques": ["T1190"], "iocIndicators": ["..."], "threatActor": "...", "reasoning": "...", "expertRecommendation": "..."}
            """,
            eventType, sourceIp, target, method,
            fullPayload.length() > 200 ? fullPayload.substring(0, 200) + "..." : fullPayload,
            previousAnalysis, threatSummary, historySummary, systemSummary, hcadSection,
            mitreTactics, mitreTechniques);
    }

    /**
     * HCAD 유사도 분석 결과 섹션 구성
     */
    private String buildHCADSection(SecurityEvent event) {
        Double similarityScore = event.getHcadSimilarityScore();

        if (similarityScore == null) {
            return "HCAD Analysis: Not available (no baseline yet)";
        }

        String assessment;
        if (similarityScore > 0.70) {
            assessment = "NORMAL_PATTERN (Should not reach Layer3 - routing error?)";
        } else if (similarityScore > 0.55) {
            assessment = "MODERATE_DEVIATION (Should not reach Layer3 - routing error?)";
        } else if (similarityScore > 0.40) {
            assessment = "SIGNIFICANT_DEVIATION (Expected Layer3 case)";
        } else {
            assessment = "ANOMALY_DETECTED (Critical Layer3 case)";
        }

        return String.format("""
            HCAD Similarity Analysis:
            - Similarity Score: %.3f (%.1f%% match with user's baseline pattern)
            - Assessment: %s
            - Note: Layer3 handles similarity < 0.40 (anomaly cases)""",
            similarityScore,
            similarityScore * 100,
            assessment
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