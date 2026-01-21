package io.contexa.contexacore.std.labs.risk;

import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.RiskAssessmentRequest;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;

@Slf4j
public class RiskAssessmentVectorService extends AbstractVectorLabService {
    
    @Value("${spring.ai.risk.zero-trust-threshold:0.8}")
    private double zeroTrustThreshold;
    
    @Value("${spring.ai.risk.continuous-validation:true}")
    private boolean continuousValidation;
    
    @Value("${spring.ai.risk.adaptive-risk-scoring:true}")
    private boolean adaptiveRiskScoring;
    
    @Value("${spring.ai.risk.context-aware-assessment:true}")
    private boolean contextAwareAssessment;
    
    @Value("${spring.ai.risk.predictive-risk-analysis:true}")
    private boolean predictiveRiskAnalysis;
    
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private static final Map<String, Pattern> ZERO_TRUST_PRINCIPLES = Map.of(
        "NEVER_TRUST", Pattern.compile("verify|validate|authenticate|검증|확인|인증", Pattern.CASE_INSENSITIVE),
        "ALWAYS_VERIFY", Pattern.compile("continuous|always|every|항상|지속적|매번", Pattern.CASE_INSENSITIVE),
        "LEAST_PRIVILEGE", Pattern.compile("minimal|least|restrict|최소|제한|최소권한", Pattern.CASE_INSENSITIVE),
        "ASSUME_BREACH", Pattern.compile("breach|compromise|attack|침해|공격|위협", Pattern.CASE_INSENSITIVE),
        "EXPLICIT_VERIFICATION", Pattern.compile("explicit|clear|specific|명시적|명확한|구체적", Pattern.CASE_INSENSITIVE),
        "MICROSEGMENTATION", Pattern.compile("segment|isolate|separate|분할|격리|분리", Pattern.CASE_INSENSITIVE),
        "CONTEXT_AWARE", Pattern.compile("context|situation|condition|상황|조건|맥락", Pattern.CASE_INSENSITIVE),
        "CONTINUOUS_MONITORING", Pattern.compile("monitor|watch|track|모니터링|감시|추적", Pattern.CASE_INSENSITIVE)
    );

    private static final Map<String, Pattern> RISK_CATEGORY_PATTERNS = Map.of(
        "IDENTITY_RISK", Pattern.compile("identity|credential|account|신원|자격증명|계정", Pattern.CASE_INSENSITIVE),
        "ACCESS_RISK", Pattern.compile("access|permission|authorization|접근|권한|인가", Pattern.CASE_INSENSITIVE),
        "DEVICE_RISK", Pattern.compile("device|endpoint|workstation|장치|단말|워크스테이션", Pattern.CASE_INSENSITIVE),
        "NETWORK_RISK", Pattern.compile("network|connection|traffic|네트워크|연결|트래픽", Pattern.CASE_INSENSITIVE),
        "APPLICATION_RISK", Pattern.compile("application|software|program|애플리케이션|소프트웨어|프로그램", Pattern.CASE_INSENSITIVE),
        "DATA_RISK", Pattern.compile("data|information|content|데이터|정보|콘텐츠", Pattern.CASE_INSENSITIVE),
        "BEHAVIOR_RISK", Pattern.compile("behavior|activity|action|행동|활동|행위", Pattern.CASE_INSENSITIVE),
        "COMPLIANCE_RISK", Pattern.compile("compliance|regulation|policy|준수|규정|정책", Pattern.CASE_INSENSITIVE)
    );

    private static final Map<String, Pattern> TRUST_FACTOR_PATTERNS = Map.of(
        "MFA_ENABLED", Pattern.compile("mfa|multi.*factor|2fa|다중.*인증|이중.*인증", Pattern.CASE_INSENSITIVE),
        "ENCRYPTION", Pattern.compile("encrypt|crypto|secure|암호화|보안", Pattern.CASE_INSENSITIVE),
        "CERTIFICATE", Pattern.compile("certificate|cert|pki|인증서", Pattern.CASE_INSENSITIVE),
        "MANAGED_DEVICE", Pattern.compile("managed|corporate|trusted.*device|관리.*장치|회사.*장치", Pattern.CASE_INSENSITIVE),
        "KNOWN_LOCATION", Pattern.compile("location|geo|office|위치|지역|사무실", Pattern.CASE_INSENSITIVE),
        "RECENT_AUTH", Pattern.compile("recent|fresh|just.*authenticated|최근.*인증|방금.*인증", Pattern.CASE_INSENSITIVE),
        "STRONG_PASSWORD", Pattern.compile("strong.*password|complex.*password|강력한.*비밀번호|복잡한.*비밀번호", Pattern.CASE_INSENSITIVE),
        "BIOMETRIC", Pattern.compile("biometric|fingerprint|face|생체인식|지문|얼굴", Pattern.CASE_INSENSITIVE)
    );
    
    @Autowired
    public RiskAssessmentVectorService(StandardVectorStoreService standardVectorStoreService,
                                      @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        super(standardVectorStoreService, vectorStoreMetrics);
    }
    
    @Override
    protected String getLabName() {
        return "RiskAssessment";
    }
    
    @Override
    protected String getDocumentType() {
        return VectorDocumentType.RISK_ASSESSMENT.getValue();
    }
    
    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        Map<String, Object> metadata = new HashMap<>(document.getMetadata());
        
        try {
            
            Map<String, Boolean> zeroTrustCompliance = analyzeZeroTrustCompliance(document.getText());
            metadata.put("zeroTrustCompliance", zeroTrustCompliance);
            metadata.put("zeroTrustScore", calculateZeroTrustScore(zeroTrustCompliance));

            Set<String> riskCategories = classifyRiskCategories(document.getText());
            metadata.put("riskCategories", new ArrayList<>(riskCategories));
            metadata.put("multiCategoryRisk", riskCategories.size() > 1);

            TrustFactorAnalysis trustFactors = analyzeTrustFactors(document.getText());
            metadata.put("trustFactors", trustFactors.getFactors());
            metadata.put("trustScore", trustFactors.getScore());
            metadata.put("trustLevel", trustFactors.getLevel());

            RiskScore riskScore = calculateRiskScore(metadata);
            metadata.put("riskScore", riskScore.getScore());
            metadata.put("riskLevel", riskScore.getLevel());
            metadata.put("riskFactors", riskScore.getFactors());

            if (contextAwareAssessment) {
                ContextualRisk contextualRisk = assessContextualRisk(document.getText(), metadata);
                metadata.put("contextualRiskScore", contextualRisk.getScore());
                metadata.put("contextualFactors", contextualRisk.getFactors());
                metadata.put("timeBasedRisk", contextualRisk.isTimeBasedRisk());
                metadata.put("locationBasedRisk", contextualRisk.isLocationBasedRisk());
            }

            if (adaptiveRiskScoring) {
                AdaptiveRiskScore adaptiveScore = calculateAdaptiveRiskScore(metadata);
                metadata.put("adaptiveRiskScore", adaptiveScore.getScore());
                metadata.put("adaptiveTrend", adaptiveScore.getTrend());
                metadata.put("adaptiveConfidence", adaptiveScore.getConfidence());
            }

            if (predictiveRiskAnalysis) {
                PredictiveRisk predictiveRisk = analyzePredictiveRisk(metadata);
                metadata.put("predictedRiskLevel", predictiveRisk.getPredictedLevel());
                metadata.put("riskProbability", predictiveRisk.getProbability());
                metadata.put("predictedThreats", predictiveRisk.getThreats());
            }

            if (continuousValidation) {
                ValidationRequirements validation = determineValidationRequirements(metadata);
                metadata.put("validationFrequency", validation.getFrequency());
                metadata.put("validationMethods", validation.getMethods());
                metadata.put("nextValidation", validation.getNextValidation());
            }

            List<String> mitigationRecommendations = generateMitigationRecommendations(metadata);
            metadata.put("mitigationRecommendations", mitigationRecommendations);
            metadata.put("mitigationPriority", determineMitigationPriority(metadata));

            String zeroTrustSignature = generateZeroTrustSignature(metadata);
            metadata.put("zeroTrustSignature", zeroTrustSignature);

            metadata.put("enrichmentVersion", "2.0");
            metadata.put("enrichedByService", "RiskAssessmentVectorService");
            metadata.put("assessmentTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            
            return new Document(document.getText(), metadata);
            
        } catch (Exception e) {
            log.error("[RiskAssessmentVectorService] 메타데이터 강화 실패", e);
            metadata.put("enrichmentError", e.getMessage());
            return new Document(document.getText(), metadata);
        }
    }
    
    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        if (!metadata.containsKey("userId") && 
            !metadata.containsKey("resourceId") && 
            !metadata.containsKey("assessmentType")) {
            throw new IllegalArgumentException(
                "Risk Assessment 문서는 userId, resourceId, assessmentType 중 최소 하나는 포함해야 합니다");
        }

        String text = document.getText();
        if (text == null || text.trim().length() < 10) {
            throw new IllegalArgumentException("위험 평가 내용이 너무 짧습니다 (최소 10자 필요)");
        }

        if (text.length() > 10000) {
            throw new IllegalArgumentException("위험 평가 내용이 너무 깁니다 (최대 10000자)");
        }
    }
    
    @Override
    protected void postProcessDocument(Document document, OperationType operationType) {
        try {
            Map<String, Object> metadata = document.getMetadata();
            
            if (operationType == OperationType.STORE) {
                
                Double zeroTrustScore = (Double) metadata.get("zeroTrustScore");
                if (zeroTrustScore != null && zeroTrustScore < zeroTrustThreshold) {
                    log.warn("[RiskAssessmentVectorService] Zero Trust 원칙 위반: 점수={}, 카테고리={}", 
                            zeroTrustScore, metadata.get("riskCategories"));
                    
                    metadata.put("zeroTrustViolation", true);
                    metadata.put("violationAlertTriggered", true);
                    metadata.put("alertTimestamp", LocalDateTime.now().format(ISO_FORMATTER));

                    triggerImmediateReassessment(metadata);
                }

                String riskLevel = (String) metadata.get("riskLevel");
                if ("CRITICAL".equals(riskLevel) || "HIGH".equals(riskLevel)) {
                    log.warn("[RiskAssessmentVectorService] 고위험 감지: 수준={}, 점수={}", 
                            riskLevel, metadata.get("riskScore"));
                    metadata.put("highRiskAlert", true);
                }

                String adaptiveTrend = (String) metadata.get("adaptiveTrend");
                if ("INCREASING".equals(adaptiveTrend)) {
                    log.warn("[RiskAssessmentVectorService] 위험 증가 추세 감지");
                    metadata.put("riskIncreasingAlert", true);
                }
            }
            
        } catch (Exception e) {
            log.error("[RiskAssessmentVectorService] 후처리 실패", e);
        }
    }
    
    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        filters.put("documentType", getDocumentType());
        
        if (continuousValidation) {
            filters.put("includeContinuousValidation", true);
        }
        if (adaptiveRiskScoring) {
            filters.put("includeAdaptiveScoring", true);
        }
        if (contextAwareAssessment) {
            filters.put("includeContextAware", true);
        }
        if (predictiveRiskAnalysis) {
            filters.put("includePredictiveAnalysis", true);
        }
        
        return filters;
    }

    public void storeRiskAssessmentRequest(RiskAssessmentRequest request) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", request.getUserId());
            metadata.put("resourceId", request.getResourceId());
            metadata.put("actionType", request.getActionType());
            metadata.put("organizationId", request.getContext().getOrganizationId());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "risk_assessment_request");
            metadata.put("requestId", UUID.randomUUID().toString());

            metadata.put("historyAnalysisEnabled", request.isEnableHistoryAnalysis());
            metadata.put("behaviorAnalysisEnabled", request.isEnableBehaviorAnalysis());
            metadata.put("maxHistoryRecords", request.getMaxHistoryRecords());
            
            String requestText = String.format(
                "위험 평가 요청: 사용자=%s, 리소스=%s, 액션=%s, 조직=%s, 이력분석=%s",
                request.getUserId(),
                request.getResourceId(),
                request.getActionType(),
                request.getContext().getOrganizationId(),
                request.isEnableHistoryAnalysis()
            );
            
            Document requestDoc = new Document(requestText, metadata);
            storeDocument(requestDoc);

        } catch (Exception e) {
            log.error("[RiskAssessmentVectorService] 위험 평가 요청 저장 실패", e);
            throw new VectorStoreException("위험 평가 요청 저장 실패: " + e.getMessage(), e);
        }
    }

    public void storeRiskAssessmentResult(RiskAssessmentRequest request, RiskAssessmentResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", request.getUserId());
            metadata.put("resourceId", request.getResourceId());
            metadata.put("actionType", request.getActionType());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "risk_assessment_result");
            metadata.put("assessmentId", response.getResponseId());

            metadata.put("trustScore", response.trustScore());
            metadata.put("riskScore", response.riskScore());
            metadata.put("riskTags", response.getAssessment() != null ? response.getAssessment().riskTags() : List.of());
            metadata.put("recommendation", response.recommendation());

            if (response.getAssessment() != null && response.getAssessment().riskTags() != null) {
                metadata.put("riskFactors", response.getAssessment().riskTags());
                metadata.put("riskFactorCount", response.getAssessment().riskTags().size());
            }

            boolean zeroTrustCompliant = response.trustScore() >= zeroTrustThreshold;
            metadata.put("zeroTrustCompliant", zeroTrustCompliant);
            
            String resultText = String.format(
                "Zero Trust 위험 평가 결과: 신뢰점수=%.1f, 위험점수=%.1f, ZT준수=%s, 권고=%s",
                response.trustScore(),
                response.riskScore(),
                zeroTrustCompliant ? "준수" : "위반",
                response.recommendation()
            );
            
            Document resultDoc = new Document(resultText, metadata);
            storeDocument(resultDoc);

            storeDetailedRiskFactors(response, metadata);

        } catch (Exception e) {
            log.error("[RiskAssessmentVectorService] 위험 평가 결과 저장 실패", e);
            throw new VectorStoreException("위험 평가 결과 저장 실패: " + e.getMessage(), e);
        }
    }

    private void storeDetailedRiskFactors(RiskAssessmentResponse response, Map<String, Object> baseMetadata) {
        if (response.getAssessment() != null && response.getAssessment().riskTags() != null) {
            response.getAssessment().riskTags().forEach(factor -> {
                try {
                    Map<String, Object> factorMetadata = new HashMap<>(baseMetadata);
                    factorMetadata.put("riskFactor", factor);
                    factorMetadata.put("documentType", "risk_factor_detail");
                    
                    String factorText = String.format(
                        "위험 요소: %s",
                        factor
                    );
                    
                    Document factorDoc = new Document(factorText, factorMetadata);
                    storeDocument(factorDoc);
                    
                } catch (Exception e) {
                    log.error("위험 요소 저장 실패: {}", factor, e);
                }
            });
        }
    }

    private Map<String, Boolean> analyzeZeroTrustCompliance(String content) {
        Map<String, Boolean> compliance = new HashMap<>();
        
        if (content == null) {
            ZERO_TRUST_PRINCIPLES.keySet().forEach(principle -> compliance.put(principle, false));
            return compliance;
        }
        
        for (Map.Entry<String, Pattern> entry : ZERO_TRUST_PRINCIPLES.entrySet()) {
            boolean compliant = entry.getValue().matcher(content).find();
            compliance.put(entry.getKey(), compliant);
        }
        
        return compliance;
    }

    private double calculateZeroTrustScore(Map<String, Boolean> compliance) {
        if (compliance.isEmpty()) return 0.0;
        
        long compliantCount = compliance.values().stream()
            .filter(Boolean::booleanValue)
            .count();
        
        return (double) compliantCount / compliance.size();
    }

    private Set<String> classifyRiskCategories(String content) {
        Set<String> categories = new HashSet<>();
        
        if (content == null) return categories;
        
        for (Map.Entry<String, Pattern> entry : RISK_CATEGORY_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                categories.add(entry.getKey());
            }
        }
        
        if (categories.isEmpty()) {
            categories.add("GENERAL_RISK");
        }
        
        return categories;
    }

    private TrustFactorAnalysis analyzeTrustFactors(String content) {
        TrustFactorAnalysis analysis = new TrustFactorAnalysis();
        List<String> factors = new ArrayList<>();
        double score = 0.0;
        
        if (content != null) {
            for (Map.Entry<String, Pattern> entry : TRUST_FACTOR_PATTERNS.entrySet()) {
                if (entry.getValue().matcher(content).find()) {
                    factors.add(entry.getKey());
                    score += 0.125; 
                }
            }
        }
        
        analysis.setFactors(factors);
        analysis.setScore(Math.min(score, 1.0));
        
        if (score >= 0.75) analysis.setLevel("HIGH");
        else if (score >= 0.5) analysis.setLevel("MEDIUM");
        else if (score >= 0.25) analysis.setLevel("LOW");
        else analysis.setLevel("NONE");
        
        return analysis;
    }

    private RiskScore calculateRiskScore(Map<String, Object> metadata) {
        RiskScore riskScore = new RiskScore();
        double score = 0.0;
        List<String> factors = new ArrayList<>();

        Double ztScore = (Double) metadata.get("zeroTrustScore");
        if (ztScore != null) {
            score += (1.0 - ztScore) * 30.0;
            if (ztScore < 0.5) {
                factors.add("Zero Trust 원칙 미준수");
            }
        }

        Double trustScore = (Double) metadata.get("trustScore");
        if (trustScore != null) {
            score += (1.0 - trustScore) * 25.0;
            if (trustScore < 0.5) {
                factors.add("낮은 신뢰도");
            }
        }

        if (Boolean.TRUE.equals(metadata.get("multiCategoryRisk"))) {
            score += 20.0;
            factors.add("다중 위험 카테고리");
        }

        List<String> categories = (List<String>) metadata.get("riskCategories");
        if (categories != null) {
            score += categories.size() * 5.0;
            if (categories.contains("IDENTITY_RISK")) {
                score += 10.0;
                factors.add("신원 위험");
            }
            if (categories.contains("DATA_RISK")) {
                score += 10.0;
                factors.add("데이터 위험");
            }
        }
        
        riskScore.setScore(Math.min(score, 100.0));
        riskScore.setFactors(factors);
        
        if (score >= 80) riskScore.setLevel("CRITICAL");
        else if (score >= 60) riskScore.setLevel("HIGH");
        else if (score >= 40) riskScore.setLevel("MEDIUM");
        else if (score >= 20) riskScore.setLevel("LOW");
        else riskScore.setLevel("MINIMAL");
        
        return riskScore;
    }

    private ContextualRisk assessContextualRisk(String content, Map<String, Object> metadata) {
        ContextualRisk contextualRisk = new ContextualRisk();
        double score = 0.0;
        List<String> factors = new ArrayList<>();

        LocalDateTime now = LocalDateTime.now();
        if (now.getHour() < 6 || now.getHour() > 22) {
            score += 0.2;
            factors.add("비정상 시간대");
            contextualRisk.setTimeBasedRisk(true);
        }

        if (now.getDayOfWeek().getValue() > 5) {
            score += 0.1;
            factors.add("주말 활동");
        }

        if (content != null && (content.contains("unknown location") || content.contains("알 수 없는 위치"))) {
            score += 0.3;
            factors.add("알 수 없는 위치");
            contextualRisk.setLocationBasedRisk(true);
        }

        if (content != null && (content.contains("sudden") || content.contains("급격") || content.contains("갑작"))) {
            score += 0.2;
            factors.add("급격한 변화");
        }

        if (content != null && (content.contains("unusual") || content.contains("anomaly") || content.contains("이상"))) {
            score += 0.2;
            factors.add("이상 패턴");
        }
        
        contextualRisk.setScore(Math.min(score, 1.0));
        contextualRisk.setFactors(factors);
        
        return contextualRisk;
    }

    private AdaptiveRiskScore calculateAdaptiveRiskScore(Map<String, Object> metadata) {
        AdaptiveRiskScore adaptiveScore = new AdaptiveRiskScore();
        
        Double currentRisk = (Double) metadata.get("riskScore");
        Double contextualRisk = (Double) metadata.get("contextualRiskScore");
        
        if (currentRisk != null && contextualRisk != null) {
            
            double adaptive = currentRisk * (1 + contextualRisk);
            adaptiveScore.setScore(Math.min(adaptive, 100.0));

            if (adaptive > currentRisk * 1.2) {
                adaptiveScore.setTrend("INCREASING");
            } else if (adaptive < currentRisk * 0.8) {
                adaptiveScore.setTrend("DECREASING");
            } else {
                adaptiveScore.setTrend("STABLE");
            }

            adaptiveScore.setConfidence(0.85); 
        } else {
            adaptiveScore.setScore(currentRisk != null ? currentRisk : 50.0);
            adaptiveScore.setTrend("UNKNOWN");
            adaptiveScore.setConfidence(0.5);
        }
        
        return adaptiveScore;
    }

    private PredictiveRisk analyzePredictiveRisk(Map<String, Object> metadata) {
        PredictiveRisk predictiveRisk = new PredictiveRisk();
        List<String> threats = new ArrayList<>();
        
        String riskLevel = (String) metadata.get("riskLevel");
        List<String> categories = (List<String>) metadata.get("riskCategories");

        if ("HIGH".equals(riskLevel) || "CRITICAL".equals(riskLevel)) {
            predictiveRisk.setPredictedLevel("CRITICAL");
            predictiveRisk.setProbability(0.8);
            threats.add("잠재적 보안 침해");
        } else if ("MEDIUM".equals(riskLevel)) {
            predictiveRisk.setPredictedLevel("HIGH");
            predictiveRisk.setProbability(0.6);
            threats.add("위험 상승 가능성");
        } else {
            predictiveRisk.setPredictedLevel("MEDIUM");
            predictiveRisk.setProbability(0.4);
        }

        if (categories != null) {
            if (categories.contains("IDENTITY_RISK")) {
                threats.add("계정 탈취 시도 가능");
            }
            if (categories.contains("DATA_RISK")) {
                threats.add("데이터 유출 위험");
            }
            if (categories.contains("BEHAVIOR_RISK")) {
                threats.add("이상 행동 패턴 진화");
            }
        }
        
        predictiveRisk.setThreats(threats);
        
        return predictiveRisk;
    }

    private ValidationRequirements determineValidationRequirements(Map<String, Object> metadata) {
        ValidationRequirements requirements = new ValidationRequirements();
        List<String> methods = new ArrayList<>();
        
        String riskLevel = (String) metadata.get("riskLevel");
        
        if ("CRITICAL".equals(riskLevel)) {
            requirements.setFrequency("CONTINUOUS");
            methods.add("MFA");
            methods.add("BIOMETRIC");
            methods.add("DEVICE_TRUST");
        } else if ("HIGH".equals(riskLevel)) {
            requirements.setFrequency("FREQUENT");
            methods.add("MFA");
            methods.add("CERTIFICATE");
        } else if ("MEDIUM".equals(riskLevel)) {
            requirements.setFrequency("PERIODIC");
            methods.add("PASSWORD");
            methods.add("DEVICE_CHECK");
        } else {
            requirements.setFrequency("STANDARD");
            methods.add("PASSWORD");
        }
        
        requirements.setMethods(methods);
        requirements.setNextValidation(calculateNextValidation(requirements.getFrequency()));
        
        return requirements;
    }

    private String calculateNextValidation(String frequency) {
        LocalDateTime next;
        
        switch (frequency) {
            case "CONTINUOUS":
                next = LocalDateTime.now().plusMinutes(5);
                break;
            case "FREQUENT":
                next = LocalDateTime.now().plusMinutes(30);
                break;
            case "PERIODIC":
                next = LocalDateTime.now().plusHours(2);
                break;
            default:
                next = LocalDateTime.now().plusHours(8);
        }
        
        return next.format(ISO_FORMATTER);
    }

    private List<String> generateMitigationRecommendations(Map<String, Object> metadata) {
        List<String> recommendations = new ArrayList<>();
        
        String riskLevel = (String) metadata.get("riskLevel");
        Double zeroTrustScore = (Double) metadata.get("zeroTrustScore");
        List<String> riskFactors = (List<String>) metadata.get("riskFactors");

        if ("CRITICAL".equals(riskLevel) || "HIGH".equals(riskLevel)) {
            recommendations.add("즉시 다중 인증(MFA) 활성화");
            recommendations.add("접근 권한 재검토 및 최소화");
            recommendations.add("실시간 모니터링 강화");
        }

        if (zeroTrustScore != null && zeroTrustScore < zeroTrustThreshold) {
            recommendations.add("Zero Trust 원칙 적용 강화");
            recommendations.add("마이크로세그멘테이션 구현");
            recommendations.add("지속적 검증 프로세스 도입");
        }

        if (riskFactors != null) {
            if (riskFactors.contains("낮은 신뢰도")) {
                recommendations.add("신뢰도 향상을 위한 추가 인증 수단 도입");
            }
            if (riskFactors.contains("신원 위험")) {
                recommendations.add("신원 확인 프로세스 강화");
            }
            if (riskFactors.contains("데이터 위험")) {
                recommendations.add("데이터 암호화 및 접근 제어 강화");
            }
        }
        
        return recommendations;
    }

    private String determineMitigationPriority(Map<String, Object> metadata) {
        String riskLevel = (String) metadata.get("riskLevel");
        String adaptiveTrend = (String) metadata.get("adaptiveTrend");
        
        if ("CRITICAL".equals(riskLevel)) {
            return "IMMEDIATE";
        } else if ("HIGH".equals(riskLevel) || "INCREASING".equals(adaptiveTrend)) {
            return "URGENT";
        } else if ("MEDIUM".equals(riskLevel)) {
            return "HIGH";
        } else {
            return "NORMAL";
        }
    }

    private String generateZeroTrustSignature(Map<String, Object> metadata) {
        StringBuilder signature = new StringBuilder("ZT");
        
        Double ztScore = (Double) metadata.get("zeroTrustScore");
        if (ztScore != null) {
            signature.append("-").append(String.format("%.0f", ztScore * 100));
        }
        
        String riskLevel = (String) metadata.get("riskLevel");
        if (riskLevel != null) {
            signature.append("-").append(riskLevel.substring(0, Math.min(3, riskLevel.length())));
        }
        
        Boolean continuous = (Boolean) metadata.get("continuousValidation");
        if (Boolean.TRUE.equals(continuous)) {
            signature.append("-CV");
        }
        
        Boolean adaptive = (Boolean) metadata.get("adaptiveRiskScoring");
        if (Boolean.TRUE.equals(adaptive)) {
            signature.append("-AR");
        }
        
        signature.append("-").append(System.currentTimeMillis() % 10000);
        
        return signature.toString();
    }

    private void triggerImmediateReassessment(Map<String, Object> metadata) {
                metadata.put("reassessmentTriggered", true);
        metadata.put("reassessmentId", UUID.randomUUID().toString());
        metadata.put("reassessmentReason", "Zero Trust 원칙 위반");
    }

    private static class TrustFactorAnalysis {
        private List<String> factors;
        private double score;
        private String level;
        
        public List<String> getFactors() { return factors; }
        public void setFactors(List<String> factors) { this.factors = factors; }
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
        public String getLevel() { return level; }
        public void setLevel(String level) { this.level = level; }
    }
    
    private static class RiskScore {
        private double score;
        private String level;
        private List<String> factors;
        
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
        public String getLevel() { return level; }
        public void setLevel(String level) { this.level = level; }
        public List<String> getFactors() { return factors; }
        public void setFactors(List<String> factors) { this.factors = factors; }
    }
    
    private static class ContextualRisk {
        private double score;
        private List<String> factors;
        private boolean timeBasedRisk;
        private boolean locationBasedRisk;
        
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
        public List<String> getFactors() { return factors; }
        public void setFactors(List<String> factors) { this.factors = factors; }
        public boolean isTimeBasedRisk() { return timeBasedRisk; }
        public void setTimeBasedRisk(boolean timeBasedRisk) { this.timeBasedRisk = timeBasedRisk; }
        public boolean isLocationBasedRisk() { return locationBasedRisk; }
        public void setLocationBasedRisk(boolean locationBasedRisk) { this.locationBasedRisk = locationBasedRisk; }
    }
    
    private static class AdaptiveRiskScore {
        private double score;
        private String trend;
        private double confidence;
        
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
        public String getTrend() { return trend; }
        public void setTrend(String trend) { this.trend = trend; }
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
    }
    
    private static class PredictiveRisk {
        private String predictedLevel;
        private double probability;
        private List<String> threats;
        
        public String getPredictedLevel() { return predictedLevel; }
        public void setPredictedLevel(String predictedLevel) { this.predictedLevel = predictedLevel; }
        public double getProbability() { return probability; }
        public void setProbability(double probability) { this.probability = probability; }
        public List<String> getThreats() { return threats; }
        public void setThreats(List<String> threats) { this.threats = threats; }
    }
    
    private static class ValidationRequirements {
        private String frequency;
        private List<String> methods;
        private String nextValidation;
        
        public String getFrequency() { return frequency; }
        public void setFrequency(String frequency) { this.frequency = frequency; }
        public List<String> getMethods() { return methods; }
        public void setMethods(List<String> methods) { this.methods = methods; }
        public String getNextValidation() { return nextValidation; }
        public void setNextValidation(String nextValidation) { this.nextValidation = nextValidation; }
    }

    public List<Document> findSimilarRiskPatterns(String userId, String resourceIdentifier, int topK) {
        try {
            Map<String, Object> filters = new HashMap<>();
            filters.put("documentType", "risk_assessment");
            filters.put("userId", userId);
            filters.put("resourceIdentifier", resourceIdentifier);
            filters.put("topK", topK);
            
            String query = String.format("위험 평가: 사용자=%s 리소스=%s", userId, resourceIdentifier);
            return searchSimilar(query, filters);
        } catch (Exception e) {
            log.error("위험 패턴 검색 실패", e);
            return List.of();
        }
    }

    public void storeRiskAssessment(RiskAssessmentContext context) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("documentType", "risk_assessment_context");
            metadata.put("userId", context.getUserId());
            metadata.put("resourceId", context.getResourceIdentifier());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            
            String text = String.format("위험 평가 컨텍스트: 사용자=%s, 리소스=%s", 
                context.getUserId(), context.getResourceIdentifier());
            Document doc = new Document(text, metadata);
            storeDocument(doc);
            
                    } catch (Exception e) {
            log.error("위험 평가 컨텍스트 저장 실패", e);
        }
    }

    public void storeRiskResult(String requestId, double riskScore, String result) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("documentType", "risk_assessment_result");
            metadata.put("requestId", requestId);
            metadata.put("riskScore", riskScore);
            metadata.put("assessmentType", "RISK_RESULT");  
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));

            Document doc = new Document(result, metadata);
            storeDocument(doc);
            
                    } catch (Exception e) {
            log.error("위험 평가 결과 저장 실패", e);
        }
    }
}