package io.contexa.contexaiam.aiam.labs.securityCopilot;

import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexaiam.aiam.protocol.request.SecurityCopilotRequest;
import io.contexa.contexaiam.aiam.protocol.response.SecurityCopilotResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Security Copilot 전용 벡터 저장소 서비스
 * 
 * SecurityCopilotLab을 위한 Spring AI 표준 준수 벡터 저장소 서비스입니다.
 * 보안 통합 분석, 위협 평가, 권고사항을 벡터화하여 저장하고 학습합니다.
 * 
 * @since 1.0.0
 */
@Slf4j
public class SecurityCopilotVectorService extends AbstractVectorLabService {
    
    @Value("${spring.ai.security.threat-threshold:0.7}")
    private double threatThreshold;
    
    @Value("${spring.ai.security.anomaly-detection:true}")
    private boolean anomalyDetection;
    
    @Value("${spring.ai.security.threat-intelligence:true}")
    private boolean threatIntelligence;
    
    @Value("${spring.ai.security.incident-correlation:true}")
    private boolean incidentCorrelation;
    
    @Value("${spring.ai.security.predictive-analysis:true}")
    private boolean predictiveAnalysis;
    
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    
    // 보안 위협 유형 분류 패턴
    private static final Map<String, Pattern> THREAT_TYPE_PATTERNS = Map.of(
        "UNAUTHORIZED_ACCESS", Pattern.compile("unauthorized|illegal|forbidden|무단|불법", Pattern.CASE_INSENSITIVE),
        "DATA_BREACH", Pattern.compile("breach|leak|exposure|유출|노출", Pattern.CASE_INSENSITIVE),
        "PRIVILEGE_ESCALATION", Pattern.compile("escalation|elevation|privilege|권한.*상승", Pattern.CASE_INSENSITIVE),
        "INJECTION_ATTACK", Pattern.compile("injection|sql.*injection|xss|주입", Pattern.CASE_INSENSITIVE),
        "DENIAL_OF_SERVICE", Pattern.compile("dos|ddos|denial.*service|서비스.*거부", Pattern.CASE_INSENSITIVE),
        "MALWARE", Pattern.compile("malware|virus|trojan|ransomware|악성", Pattern.CASE_INSENSITIVE),
        "INSIDER_THREAT", Pattern.compile("insider|internal.*threat|내부.*위협", Pattern.CASE_INSENSITIVE),
        "CONFIGURATION_ERROR", Pattern.compile("misconfiguration|config.*error|설정.*오류", Pattern.CASE_INSENSITIVE)
    );
    
    // 보안 영역 분류 패턴
    private static final Map<String, Pattern> SECURITY_DOMAIN_PATTERNS = Map.of(
        "IDENTITY", Pattern.compile("identity|authentication|인증|신원", Pattern.CASE_INSENSITIVE),
        "ACCESS", Pattern.compile("access|authorization|permission|접근|권한", Pattern.CASE_INSENSITIVE),
        "NETWORK", Pattern.compile("network|firewall|vpn|네트워크|방화벽", Pattern.CASE_INSENSITIVE),
        "APPLICATION", Pattern.compile("application|app|software|애플리케이션|소프트웨어", Pattern.CASE_INSENSITIVE),
        "DATA", Pattern.compile("data|database|storage|데이터|저장소", Pattern.CASE_INSENSITIVE),
        "ENDPOINT", Pattern.compile("endpoint|device|workstation|엔드포인트|장치", Pattern.CASE_INSENSITIVE),
        "CLOUD", Pattern.compile("cloud|saas|paas|iaas|클라우드", Pattern.CASE_INSENSITIVE),
        "COMPLIANCE", Pattern.compile("compliance|regulation|audit|준수|규정", Pattern.CASE_INSENSITIVE)
    );
    
    // 공격 단계 (MITRE ATT&CK 기반)
    private static final Map<String, Pattern> ATTACK_STAGE_PATTERNS = Map.of(
        "RECONNAISSANCE", Pattern.compile("recon|scanning|discovery|정찰|스캔", Pattern.CASE_INSENSITIVE),
        "INITIAL_ACCESS", Pattern.compile("initial.*access|entry.*point|초기.*접근", Pattern.CASE_INSENSITIVE),
        "EXECUTION", Pattern.compile("execution|run|launch|실행", Pattern.CASE_INSENSITIVE),
        "PERSISTENCE", Pattern.compile("persistence|backdoor|maintain|지속성|백도어", Pattern.CASE_INSENSITIVE),
        "PRIVILEGE_ESCALATION", Pattern.compile("privilege.*escalation|elevation|권한.*상승", Pattern.CASE_INSENSITIVE),
        "DEFENSE_EVASION", Pattern.compile("evasion|bypass|avoid|회피|우회", Pattern.CASE_INSENSITIVE),
        "LATERAL_MOVEMENT", Pattern.compile("lateral|spread|propagate|측면.*이동|전파", Pattern.CASE_INSENSITIVE),
        "EXFILTRATION", Pattern.compile("exfiltration|steal|extract|유출|탈취", Pattern.CASE_INSENSITIVE)
    );
    
    @Autowired
    public SecurityCopilotVectorService(StandardVectorStoreService standardVectorStoreService,
                                       @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        super(standardVectorStoreService, vectorStoreMetrics);
    }
    
    @Override
    protected String getLabName() {
        return "SecurityCopilot";
    }
    
    @Override
    protected String getDocumentType() {
        return "security_copilot";
    }
    
    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        Map<String, Object> metadata = new HashMap<>(document.getMetadata());
        
        try {
            // 1. 위협 유형 분류
            Set<String> threatTypes = classifyThreatTypes(document.getText());
            metadata.put("threatTypes", new ArrayList<>(threatTypes));
            metadata.put("threatTypeCount", threatTypes.size());
            
            // 2. 보안 영역 분석
            Set<String> securityDomains = analyzeSecurityDomains(document.getText());
            metadata.put("securityDomains", new ArrayList<>(securityDomains));
            metadata.put("crossDomainThreat", securityDomains.size() > 1);
            
            // 3. 공격 단계 식별
            Set<String> attackStages = identifyAttackStages(document.getText());
            metadata.put("attackStages", new ArrayList<>(attackStages));
            metadata.put("multiStageAttack", attackStages.size() > 1);
            
            // 4. 위협 심각도 평가
            ThreatSeverity severity = evaluateThreatSeverity(metadata);
            metadata.put("threatSeverity", severity.getLevel());
            metadata.put("threatScore", severity.getScore());
            metadata.put("severityFactors", severity.getFactors());
            
            // 5. 영향 분석
            ImpactAnalysis impact = analyzeImpact(document.getText(), metadata);
            metadata.put("impactScope", impact.getScope());
            metadata.put("impactLevel", impact.getLevel());
            metadata.put("affectedAssets", impact.getAffectedAssets());
            
            // 6. 이상 징후 감지
            if (anomalyDetection) {
                AnomalyIndicators anomalies = detectAnomalies(document.getText(), metadata);
                metadata.put("anomalyScore", anomalies.getScore());
                metadata.put("anomalyIndicators", anomalies.getIndicators());
                metadata.put("isAnomaly", anomalies.getScore() > 0.7);
            }
            
            // 7. 위협 인텔리전스 상관관계
            if (threatIntelligence) {
                Map<String, Object> threatIntel = correlateThreatIntelligence(metadata);
                metadata.put("threatIntelligence", threatIntel);
            }
            
            // 8. 인시던트 상관관계 분석
            if (incidentCorrelation) {
                Map<String, Object> correlations = analyzeIncidentCorrelations(metadata);
                metadata.put("incidentCorrelations", correlations);
            }
            
            // 9. 예측 분석
            if (predictiveAnalysis) {
                PredictiveInsights predictions = generatePredictiveInsights(metadata);
                metadata.put("predictedThreats", predictions.getThreats());
                metadata.put("riskTrend", predictions.getTrend());
                metadata.put("mitigationUrgency", predictions.getUrgency());
            }
            
            // 10. 보안 시그니처 생성
            String securitySignature = generateSecuritySignature(metadata);
            metadata.put("securitySignature", securitySignature);
            
            // 11. 권고사항 우선순위
            List<String> prioritizedRecommendations = prioritizeRecommendations(metadata);
            metadata.put("prioritizedRecommendations", prioritizedRecommendations);
            
            // 12. 메타데이터 버전 정보
            metadata.put("enrichmentVersion", "2.0");
            metadata.put("enrichedByService", "SecurityCopilotVectorService");
            metadata.put("analysisTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            
            return new Document(document.getText(), metadata);
            
        } catch (Exception e) {
            log.error("[SecurityCopilotVectorService] 메타데이터 강화 실패", e);
            metadata.put("enrichmentError", e.getMessage());
            return new Document(document.getText(), metadata);
        }
    }
    
    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();
        
        // 필수 필드 검증
        if (!metadata.containsKey("userId") && 
            !metadata.containsKey("analysisType") && 
            !metadata.containsKey("organizationId")) {
            throw new IllegalArgumentException(
                "Security Copilot 문서는 userId, analysisType, organizationId 중 최소 하나는 포함해야 합니다");
        }
        
        // 분석 내용 검증
        String text = document.getText();
        if (text == null || text.trim().length() < 10) {
            throw new IllegalArgumentException("보안 분석 내용이 너무 짧습니다 (최소 10자 필요)");
        }
        
        // 분석 길이 제한
        if (text.length() > 10000) {
            throw new IllegalArgumentException("보안 분석 내용이 너무 깁니다 (최대 10000자)");
        }
    }
    
    @Override
    protected void postProcessDocument(Document document, OperationType operationType) {
        try {
            Map<String, Object> metadata = document.getMetadata();
            
            if (operationType == OperationType.STORE) {
                // 고위험 위협 감지 시 알림
                Double threatScore = (Double) metadata.get("threatScore");
                if (threatScore != null && threatScore >= threatThreshold) {
                    log.warn("[SecurityCopilotVectorService] 고위험 위협 감지: 점수={}, 유형={}", 
                            threatScore, metadata.get("threatTypes"));
                    
                    metadata.put("requiresImmediateAction", true);
                    metadata.put("threatAlertTriggered", true);
                    metadata.put("alertTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
                    
                    // 인시던트 응답 프로세스 트리거
                    triggerIncidentResponse(metadata);
                }
                
                // 이상 징후 알림
                if (Boolean.TRUE.equals(metadata.get("isAnomaly"))) {
                    log.warn("[SecurityCopilotVectorService] 이상 징후 감지: {}", 
                            metadata.get("anomalyIndicators"));
                    metadata.put("anomalyAlertTriggered", true);
                }
                
                // 다단계 공격 감지 알림
                if (Boolean.TRUE.equals(metadata.get("multiStageAttack"))) {
                    log.warn("[SecurityCopilotVectorService] 다단계 공격 패턴 감지: {}", 
                            metadata.get("attackStages"));
                    metadata.put("advancedThreatDetected", true);
                }
            }
            
        } catch (Exception e) {
            log.error("[SecurityCopilotVectorService] 후처리 실패", e);
        }
    }
    
    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        filters.put("documentType", getDocumentType());
        
        if (anomalyDetection) {
            filters.put("includeAnomalyDetection", true);
        }
        if (threatIntelligence) {
            filters.put("includeThreatIntelligence", true);
        }
        if (incidentCorrelation) {
            filters.put("includeIncidentCorrelation", true);
        }
        if (predictiveAnalysis) {
            filters.put("includePredictiveAnalysis", true);
        }
        
        return filters;
    }
    
    /**
     * 보안 분석 요청을 벡터 저장소에 저장
     * 
     * @param request Security Copilot 요청
     */
    public void storeSecurityAnalysisRequest(SecurityCopilotRequest request) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", request.getUserId());
            metadata.put("analysisType", request.getAnalysisType());
            metadata.put("organizationId", request.getOrganizationId());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "security_copilot_request");
            metadata.put("requestId", UUID.randomUUID().toString());
            
            // 분석 옵션
            metadata.put("enableThreatHunting", request.isEnableThreatHunting());
            metadata.put("enableComplianceCheck", request.isEnableComplianceCheck());
            metadata.put("enableVulnerabilityAssessment", request.isEnableVulnerabilityAssessment());
            
            String requestText = String.format(
                "보안 통합 분석 요청: 사용자=%s, 유형=%s, 조직=%s, 위협사냥=%s, 규정준수=%s, 취약점평가=%s",
                request.getUserId(),
                request.getAnalysisType(),
                request.getOrganizationId(),
                request.isEnableThreatHunting(),
                request.isEnableComplianceCheck(),
                request.isEnableVulnerabilityAssessment()
            );
            
            Document requestDoc = new Document(requestText, metadata);
            storeDocument(requestDoc);
            
            log.debug("[SecurityCopilotVectorService] 보안 분석 요청 저장 완료: 사용자={}", request.getUserId());
            
        } catch (Exception e) {
            log.error("[SecurityCopilotVectorService] 보안 분석 요청 저장 실패", e);
            throw new VectorStoreException("보안 분석 요청 저장 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 보안 분석 결과를 벡터 저장소에 저장
     * 
     * @param request 원본 요청
     * @param response 분석 결과
     */
    public void storeSecurityAnalysisResult(SecurityCopilotRequest request, SecurityCopilotResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", request.getUserId());
            metadata.put("analysisType", request.getAnalysisType());
            metadata.put("organizationId", request.getOrganizationId());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "security_copilot_result");
            metadata.put("analysisId", response.getAnalysisId());
            
            // 분석 결과 정보
            metadata.put("overallSecurityScore", response.getOverallSecurityScore());
            metadata.put("criticalFindingsCount", response.getCriticalFindings() != null ? response.getCriticalFindings().size() : 0);
            metadata.put("recommendationsCount", response.getRecommendations() != null ? response.getRecommendations().size() : 0);
            metadata.put("complianceStatus", response.getComplianceStatus());
            
            // 위협 분석 결과
            if (response.getThreatAnalysis() != null) {
                metadata.put("identifiedThreats", response.getThreatAnalysis().getIdentifiedThreats());
                metadata.put("threatLevel", response.getThreatAnalysis().getThreatLevel());
                metadata.put("attackVectors", response.getThreatAnalysis().getAttackVectors());
            }
            
            // 취약점 평가 결과
            if (response.getVulnerabilityAssessment() != null) {
                metadata.put("vulnerabilityCount", response.getVulnerabilityAssessment().getVulnerabilities().size());
                metadata.put("criticalVulnerabilities", response.getVulnerabilityAssessment().getCriticalCount());
                metadata.put("patchableVulnerabilities", response.getVulnerabilityAssessment().getPatchableCount());
            }
            
            String resultText = String.format(
                "보안 통합 분석 결과: 점수=%.1f, 위협수준=%s, 중요발견사항=%d개, 권고사항=%d개, 준수상태=%s",
                response.getOverallSecurityScore(),
                response.getThreatAnalysis() != null ? response.getThreatAnalysis().getThreatLevel() : "UNKNOWN",
                response.getCriticalFindings() != null ? response.getCriticalFindings().size() : 0,
                response.getRecommendations() != null ? response.getRecommendations().size() : 0,
                response.getComplianceStatus()
            );
            
            Document resultDoc = new Document(resultText, metadata);
            storeDocument(resultDoc);
            
            // 각 Lab 결과 별도 저장
            storeIndividualLabResults(response, metadata);
            
            log.debug("[SecurityCopilotVectorService] 보안 분석 결과 저장 완료: 분석ID={}", response.getAnalysisId());
            
        } catch (Exception e) {
            log.error("[SecurityCopilotVectorService] 보안 분석 결과 저장 실패", e);
            throw new VectorStoreException("보안 분석 결과 저장 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 개별 Lab 결과를 별도로 저장
     */
    private void storeIndividualLabResults(SecurityCopilotResponse response, Map<String, Object> baseMetadata) {
        // 각 Lab 결과를 개별적으로 저장하여 상세 분석 가능하도록 함
        if (response.getIndividualResults() != null) {
            response.getIndividualResults().forEach((labName, result) -> {
                try {
                    Map<String, Object> labMetadata = new HashMap<>(baseMetadata);
                    labMetadata.put("labName", labName);
                    labMetadata.put("labResult", result);
                    labMetadata.put("documentType", "security_copilot_lab_result");
                    
                    String labResultText = String.format(
                        "Lab 분석 결과 [%s]: %s",
                        labName,
                        result.toString().substring(0, Math.min(200, result.toString().length()))
                    );
                    
                    Document labDoc = new Document(labResultText, labMetadata);
                    storeDocument(labDoc);
                    
                } catch (Exception e) {
                    log.error("Lab 결과 저장 실패: {}", labName, e);
                }
            });
        }
    }
    
    /**
     * 위협 유형 분류
     */
    private Set<String> classifyThreatTypes(String content) {
        Set<String> threatTypes = new HashSet<>();
        
        if (content == null) return threatTypes;
        
        for (Map.Entry<String, Pattern> entry : THREAT_TYPE_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                threatTypes.add(entry.getKey());
            }
        }
        
        if (threatTypes.isEmpty()) {
            threatTypes.add("UNCLASSIFIED");
        }
        
        return threatTypes;
    }
    
    /**
     * 보안 영역 분석
     */
    private Set<String> analyzeSecurityDomains(String content) {
        Set<String> domains = new HashSet<>();
        
        if (content == null) return domains;
        
        for (Map.Entry<String, Pattern> entry : SECURITY_DOMAIN_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                domains.add(entry.getKey());
            }
        }
        
        if (domains.isEmpty()) {
            domains.add("GENERAL");
        }
        
        return domains;
    }
    
    /**
     * 공격 단계 식별
     */
    private Set<String> identifyAttackStages(String content) {
        Set<String> stages = new HashSet<>();
        
        if (content == null) return stages;
        
        for (Map.Entry<String, Pattern> entry : ATTACK_STAGE_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                stages.add(entry.getKey());
            }
        }
        
        return stages;
    }
    
    /**
     * 위협 심각도 평가
     */
    private ThreatSeverity evaluateThreatSeverity(Map<String, Object> metadata) {
        ThreatSeverity severity = new ThreatSeverity();
        double score = 0.0;
        List<String> factors = new ArrayList<>();
        
        // 위협 유형 수에 따른 점수
        List<String> threatTypes = (List<String>) metadata.get("threatTypes");
        if (threatTypes != null) {
            score += threatTypes.size() * 15.0;
            if (threatTypes.size() > 2) {
                factors.add("다중 위협 유형");
            }
        }
        
        // 다단계 공격 여부
        if (Boolean.TRUE.equals(metadata.get("multiStageAttack"))) {
            score += 25.0;
            factors.add("다단계 공격");
        }
        
        // 교차 도메인 위협
        if (Boolean.TRUE.equals(metadata.get("crossDomainThreat"))) {
            score += 20.0;
            factors.add("교차 도메인 위협");
        }
        
        // 공격 단계 수
        List<String> attackStages = (List<String>) metadata.get("attackStages");
        if (attackStages != null && attackStages.size() > 3) {
            score += 20.0;
            factors.add("고급 공격 패턴");
        }
        
        // 특정 위협 유형 가중치
        if (threatTypes != null) {
            if (threatTypes.contains("DATA_BREACH")) {
                score += 15.0;
                factors.add("데이터 유출 위험");
            }
            if (threatTypes.contains("PRIVILEGE_ESCALATION")) {
                score += 15.0;
                factors.add("권한 상승 위험");
            }
            if (threatTypes.contains("INSIDER_THREAT")) {
                score += 10.0;
                factors.add("내부자 위협");
            }
        }
        
        severity.setScore(Math.min(score, 100.0));
        severity.setFactors(factors);
        
        if (score >= 80) severity.setLevel("CRITICAL");
        else if (score >= 60) severity.setLevel("HIGH");
        else if (score >= 40) severity.setLevel("MEDIUM");
        else if (score >= 20) severity.setLevel("LOW");
        else severity.setLevel("INFO");
        
        return severity;
    }
    
    /**
     * 영향 분석
     */
    private ImpactAnalysis analyzeImpact(String content, Map<String, Object> metadata) {
        ImpactAnalysis impact = new ImpactAnalysis();
        
        // 영향 범위 결정
        List<String> domains = (List<String>) metadata.get("securityDomains");
        if (domains != null && domains.size() > 3) {
            impact.setScope("ENTERPRISE");
        } else if (domains != null && domains.size() > 1) {
            impact.setScope("DEPARTMENT");
        } else {
            impact.setScope("LOCAL");
        }
        
        // 영향 수준
        String threatLevel = (String) metadata.get("threatSeverity");
        if ("CRITICAL".equals(threatLevel)) {
            impact.setLevel("SEVERE");
        } else if ("HIGH".equals(threatLevel)) {
            impact.setLevel("MAJOR");
        } else if ("MEDIUM".equals(threatLevel)) {
            impact.setLevel("MODERATE");
        } else {
            impact.setLevel("MINOR");
        }
        
        // 영향받는 자산 식별
        List<String> affectedAssets = new ArrayList<>();
        if (content.contains("database") || content.contains("데이터베이스")) {
            affectedAssets.add("DATABASE");
        }
        if (content.contains("server") || content.contains("서버")) {
            affectedAssets.add("SERVER");
        }
        if (content.contains("network") || content.contains("네트워크")) {
            affectedAssets.add("NETWORK");
        }
        if (content.contains("application") || content.contains("애플리케이션")) {
            affectedAssets.add("APPLICATION");
        }
        
        impact.setAffectedAssets(affectedAssets);
        
        return impact;
    }
    
    /**
     * 이상 징후 감지
     */
    private AnomalyIndicators detectAnomalies(String content, Map<String, Object> metadata) {
        AnomalyIndicators anomalies = new AnomalyIndicators();
        double score = 0.0;
        List<String> indicators = new ArrayList<>();
        
        // 비정상 패턴 감지
        if (content.contains("unusual") || content.contains("비정상") || content.contains("이상")) {
            score += 0.3;
            indicators.add("비정상 패턴 언급");
        }
        
        // 시간 기반 이상
        LocalDateTime now = LocalDateTime.now();
        if (now.getHour() < 6 || now.getHour() > 22) {
            score += 0.2;
            indicators.add("비정상 시간대 활동");
        }
        
        // 다중 위협 동시 발생
        List<String> threatTypes = (List<String>) metadata.get("threatTypes");
        if (threatTypes != null && threatTypes.size() > 3) {
            score += 0.3;
            indicators.add("다중 위협 동시 발생");
        }
        
        // 급격한 활동 증가
        if (content.contains("spike") || content.contains("surge") || content.contains("급증")) {
            score += 0.2;
            indicators.add("활동 급증");
        }
        
        anomalies.setScore(Math.min(score, 1.0));
        anomalies.setIndicators(indicators);
        
        return anomalies;
    }
    
    /**
     * 위협 인텔리전스 상관관계 분석
     */
    private Map<String, Object> correlateThreatIntelligence(Map<String, Object> metadata) {
        Map<String, Object> threatIntel = new HashMap<>();
        
        List<String> threatTypes = (List<String>) metadata.get("threatTypes");
        if (threatTypes != null) {
            // 알려진 위협 패턴과 매칭
            threatIntel.put("knownThreatPatterns", threatTypes.size());
            threatIntel.put("threatCategories", threatTypes);
            
            // IOC (Indicators of Compromise) 상관관계
            List<String> iocs = new ArrayList<>();
            if (threatTypes.contains("MALWARE")) {
                iocs.add("MALICIOUS_FILE_HASH");
            }
            if (threatTypes.contains("DATA_BREACH")) {
                iocs.add("SUSPICIOUS_DATA_TRANSFER");
            }
            threatIntel.put("relatedIOCs", iocs);
        }
        
        return threatIntel;
    }
    
    /**
     * 인시던트 상관관계 분석
     */
    private Map<String, Object> analyzeIncidentCorrelations(Map<String, Object> metadata) {
        Map<String, Object> correlations = new HashMap<>();
        
        // 관련 인시던트 패턴
        List<String> relatedPatterns = new ArrayList<>();
        
        List<String> attackStages = (List<String>) metadata.get("attackStages");
        if (attackStages != null && attackStages.contains("LATERAL_MOVEMENT")) {
            relatedPatterns.add("APT_CAMPAIGN");
        }
        
        if (Boolean.TRUE.equals(metadata.get("multiStageAttack"))) {
            relatedPatterns.add("COORDINATED_ATTACK");
        }
        
        correlations.put("relatedPatterns", relatedPatterns);
        correlations.put("correlationScore", relatedPatterns.size() * 0.3);
        
        return correlations;
    }
    
    /**
     * 예측 분석 인사이트 생성
     */
    private PredictiveInsights generatePredictiveInsights(Map<String, Object> metadata) {
        PredictiveInsights insights = new PredictiveInsights();
        
        // 예측된 위협
        List<String> predictedThreats = new ArrayList<>();
        
        List<String> attackStages = (List<String>) metadata.get("attackStages");
        if (attackStages != null) {
            if (attackStages.contains("RECONNAISSANCE")) {
                predictedThreats.add("INITIAL_ACCESS_ATTEMPT");
            }
            if (attackStages.contains("INITIAL_ACCESS")) {
                predictedThreats.add("PRIVILEGE_ESCALATION_ATTEMPT");
            }
            if (attackStages.contains("PERSISTENCE")) {
                predictedThreats.add("DATA_EXFILTRATION_RISK");
            }
        }
        
        insights.setThreats(predictedThreats);
        
        // 위험 추세
        Double threatScore = (Double) metadata.get("threatScore");
        if (threatScore != null) {
            if (threatScore > 70) {
                insights.setTrend("INCREASING");
                insights.setUrgency("IMMEDIATE");
            } else if (threatScore > 40) {
                insights.setTrend("STABLE");
                insights.setUrgency("HIGH");
            } else {
                insights.setTrend("DECREASING");
                insights.setUrgency("NORMAL");
            }
        }
        
        return insights;
    }
    
    /**
     * 보안 시그니처 생성
     */
    private String generateSecuritySignature(Map<String, Object> metadata) {
        StringBuilder signature = new StringBuilder();
        
        String severity = (String) metadata.get("threatSeverity");
        signature.append(severity != null ? severity : "UNKNOWN");
        
        Boolean multiStage = (Boolean) metadata.get("multiStageAttack");
        if (Boolean.TRUE.equals(multiStage)) {
            signature.append("-MULTISTAGE");
        }
        
        Boolean crossDomain = (Boolean) metadata.get("crossDomainThreat");
        if (Boolean.TRUE.equals(crossDomain)) {
            signature.append("-CROSSDOMAIN");
        }
        
        Boolean anomaly = (Boolean) metadata.get("isAnomaly");
        if (Boolean.TRUE.equals(anomaly)) {
            signature.append("-ANOMALY");
        }
        
        signature.append("-").append(System.currentTimeMillis() % 10000);
        
        return signature.toString();
    }
    
    /**
     * 권고사항 우선순위 지정
     */
    private List<String> prioritizeRecommendations(Map<String, Object> metadata) {
        List<String> recommendations = new ArrayList<>();
        
        String severity = (String) metadata.get("threatSeverity");
        if ("CRITICAL".equals(severity)) {
            recommendations.add("즉시 인시던트 대응팀 소집");
            recommendations.add("영향받은 시스템 격리");
            recommendations.add("포렌식 증거 수집");
        } else if ("HIGH".equals(severity)) {
            recommendations.add("보안 모니터링 강화");
            recommendations.add("취약점 패치 적용");
            recommendations.add("접근 권한 검토");
        } else {
            recommendations.add("정기 보안 점검 수행");
            recommendations.add("보안 정책 업데이트");
        }
        
        return recommendations;
    }
    
    /**
     * 인시던트 응답 프로세스 트리거
     */
    private void triggerIncidentResponse(Map<String, Object> metadata) {
        log.info("[SecurityCopilotVectorService] 인시던트 응답 프로세스 시작");
        // 실제 구현에서는 인시던트 응답 시스템과 통합
        metadata.put("incidentResponseTriggered", true);
        metadata.put("incidentId", UUID.randomUUID().toString());
    }
    
    // 내부 클래스들
    
    private static class ThreatSeverity {
        private String level;
        private double score;
        private List<String> factors;
        
        public String getLevel() { return level; }
        public void setLevel(String level) { this.level = level; }
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
        public List<String> getFactors() { return factors; }
        public void setFactors(List<String> factors) { this.factors = factors; }
    }
    
    private static class ImpactAnalysis {
        private String scope;
        private String level;
        private List<String> affectedAssets;
        
        public String getScope() { return scope; }
        public void setScope(String scope) { this.scope = scope; }
        public String getLevel() { return level; }
        public void setLevel(String level) { this.level = level; }
        public List<String> getAffectedAssets() { return affectedAssets; }
        public void setAffectedAssets(List<String> affectedAssets) { this.affectedAssets = affectedAssets; }
    }
    
    private static class AnomalyIndicators {
        private double score;
        private List<String> indicators;
        
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
        public List<String> getIndicators() { return indicators; }
        public void setIndicators(List<String> indicators) { this.indicators = indicators; }
    }
    
    private static class PredictiveInsights {
        private List<String> threats;
        private String trend;
        private String urgency;
        
        public List<String> getThreats() { return threats; }
        public void setThreats(List<String> threats) { this.threats = threats; }
        public String getTrend() { return trend; }
        public void setTrend(String trend) { this.trend = trend; }
        public String getUrgency() { return urgency; }
        public void setUrgency(String urgency) { this.urgency = urgency; }
    }
}