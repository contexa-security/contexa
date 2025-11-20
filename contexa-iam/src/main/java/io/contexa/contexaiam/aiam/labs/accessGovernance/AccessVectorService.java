package io.contexa.contexaiam.aiam.labs.accessGovernance;

import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexaiam.aiam.protocol.context.AccessGovernanceContext;
import io.contexa.contexaiam.aiam.protocol.response.AccessGovernanceResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;

/**
 * 접근 거버넌스 전용 벡터 저장소 서비스
 * 
 * AccessGovernanceLab을 위한 Spring AI 표준 준수 벡터 저장소 서비스입니다.
 * 권한 거버넌스 분석에 최적화된 메타데이터 강화 및 패턴 분석을 제공합니다.
 * 
 * @since 1.0.0
 */
@Slf4j
@Service
public class AccessVectorService extends AbstractVectorLabService {
    
    @Value("${spring.ai.access.governance-threshold:70.0}")
    private double governanceThreshold;
    
    @Value("${spring.ai.access.sod-violation-tracking:true}")
    private boolean sodViolationTracking;
    
    @Value("${spring.ai.access.dormant-permission-analysis:true}")
    private boolean dormantPermissionAnalysis;
    
    @Value("${spring.ai.access.excessive-permission-detection:true}")
    private boolean excessivePermissionDetection;
    
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    
    // 권한 관련 키워드 패턴
    private static final Map<String, Pattern> PERMISSION_PATTERNS = Map.of(
        "GRANT", Pattern.compile("grant|assign|give|허용|부여", Pattern.CASE_INSENSITIVE),
        "REVOKE", Pattern.compile("revoke|remove|delete|회수|삭제", Pattern.CASE_INSENSITIVE),
        "ADMIN", Pattern.compile("admin|administrator|super|관리자", Pattern.CASE_INSENSITIVE),
        "READ", Pattern.compile("read|view|select|조회|읽기", Pattern.CASE_INSENSITIVE),
        "WRITE", Pattern.compile("write|update|modify|쓰기|수정", Pattern.CASE_INSENSITIVE),
        "DELETE", Pattern.compile("delete|remove|drop|삭제", Pattern.CASE_INSENSITIVE),
        "EXECUTE", Pattern.compile("execute|run|call|실행", Pattern.CASE_INSENSITIVE),
        "CREATE", Pattern.compile("create|new|add|생성", Pattern.CASE_INSENSITIVE)
    );
    
    // 민감한 리소스 패턴
    private static final Set<Pattern> SENSITIVE_RESOURCE_PATTERNS = Set.of(
        Pattern.compile(".*admin.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*system.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*config.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*secret.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*financial.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*hr.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*payroll.*", Pattern.CASE_INSENSITIVE)
    );
    
    // SOD 위반 위험 조합
    private static final Set<Set<String>> SOD_RISK_COMBINATIONS = Set.of(
        Set.of("FINANCIAL_CREATE", "FINANCIAL_APPROVE"),
        Set.of("USER_CREATE", "USER_ADMIN"),
        Set.of("SYSTEM_CONFIG", "SYSTEM_AUDIT"),
        Set.of("DATA_CREATE", "DATA_DELETE")
    );
    
    @Autowired
    public AccessVectorService(StandardVectorStoreService standardVectorStoreService,
                              @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        super(standardVectorStoreService, vectorStoreMetrics);
    }
    
    @Override
    protected String getLabName() {
        return "AccessGovernance";
    }
    
    @Override
    protected String getDocumentType() {
        return "access_governance";
    }
    
    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        Map<String, Object> metadata = new HashMap<>(document.getMetadata());
        
        try {
            // 1. 권한 작업 타입 분류
            String permissionAction = classifyPermissionAction(document.getText());
            metadata.put("permissionAction", permissionAction);
            
            // 2. 리소스 민감도 분석
            String resourceSensitivity = analyzeResourceSensitivity(document.getText(), metadata);
            metadata.put("resourceSensitivity", resourceSensitivity);
            
            // 3. SOD (Segregation of Duties) 위반 위험 분석
            if (sodViolationTracking) {
                boolean sodRisk = analyzeSodViolationRisk(metadata);
                metadata.put("sodViolationRisk", sodRisk);
            }
            
            // 4. 권한 상속 경로 분석
            analyzePermissionInheritance(metadata);
            
            // 5. 업무 분리 원칙 준수 여부
            analyzeBusinessSeparation(metadata);
            
            // 6. 권한 사용 패턴 분석
            analyzePermissionUsagePattern(metadata);
            
            // 7. 거버넌스 위험 점수 계산
            double governanceRiskScore = calculateGovernanceRiskScore(metadata);
            metadata.put("governanceRiskScore", governanceRiskScore);
            
            // 8. 권한 거버넌스 시그니처 생성
            String governanceSignature = generateGovernanceSignature(metadata);
            metadata.put("governanceSignature", governanceSignature);
            
            // 9. 분석 결과 요약
            Map<String, Object> analysisSummary = generateAnalysisSummary(metadata);
            metadata.put("analysisSummary", analysisSummary);
            
            // 10. 메타데이터 버전 정보
            metadata.put("enrichmentVersion", "2.0");
            metadata.put("enrichedByService", "AccessVectorService");
            metadata.put("analysisTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            
            return new Document(document.getText(), metadata);
            
        } catch (Exception e) {
            log.error("[AccessVectorService] 메타데이터 강화 실패", e);
            metadata.put("enrichmentError", e.getMessage());
            return new Document(document.getText(), metadata);
        }
    }
    
    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();
        
        // 필수 필드 검증
        if (!metadata.containsKey("auditScope") && 
            !metadata.containsKey("analysisType") && 
            !metadata.containsKey("organizationId")) {
            throw new IllegalArgumentException(
                "접근 거버넌스 문서는 auditScope, analysisType, organizationId 중 최소 하나는 포함해야 합니다");
        }
        
        // 분석 타입 검증
        Object analysisType = metadata.get("analysisType");
        if (analysisType != null) {
            String typeStr = analysisType.toString();
            if (!isValidAnalysisType(typeStr)) {
                throw new IllegalArgumentException("유효하지 않은 분석 타입: " + typeStr);
            }
        }
        
        // 감사 범위 검증
        Object auditScope = metadata.get("auditScope");
        if (auditScope != null) {
            String scopeStr = auditScope.toString();
            if (!isValidAuditScope(scopeStr)) {
                throw new IllegalArgumentException("유효하지 않은 감사 범위: " + scopeStr);
            }
        }
    }
    
    @Override
    protected void postProcessDocument(Document document, OperationType operationType) {
        try {
            Map<String, Object> metadata = document.getMetadata();
            
            // 고위험 거버넌스 이슈 감지 시 알림
            if (operationType == OperationType.STORE) {
                Double governanceScore = (Double) metadata.get("governanceRiskScore");
                if (governanceScore != null && governanceScore >= governanceThreshold) {
                    log.warn("[AccessVectorService] 고위험 거버넌스 이슈 감지: 범위={}, 점수={}", 
                            metadata.get("auditScope"), governanceScore);
                    
                    metadata.put("requiresImmediateReview", true);
                    metadata.put("governanceAlertTriggered", true);
                    metadata.put("alertTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
                }
                
                // SOD 위반 위험 알림
                if (Boolean.TRUE.equals(metadata.get("sodViolationRisk"))) {
                    log.warn("[AccessVectorService] SOD 위반 위험 감지: {}", 
                            metadata.get("auditScope"));
                    metadata.put("sodViolationAlert", true);
                }
            }
            
        } catch (Exception e) {
            log.error("[AccessVectorService] 후처리 실패", e);
        }
    }
    
    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        
        // 거버넌스 특화 필터
        if (dormantPermissionAnalysis) {
            filters.put("includeDormantAnalysis", true);
        }
        if (excessivePermissionDetection) {
            filters.put("includeExcessiveDetection", true);
        }
        if (sodViolationTracking) {
            filters.put("includeSodTracking", true);
        }
        
        return filters;
    }
    
    /**
     * 분석 요청을 벡터 저장소에 저장
     * 
     * @param context 접근 거버넌스 컨텍스트
     */
    public void storeAnalysisRequest(AccessGovernanceContext context) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("auditScope", context.getAuditScope());
            metadata.put("analysisType", context.getAnalysisType());
            metadata.put("organizationId", context.getOrganizationId());
            metadata.put("priority", context.getPriority());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "access_governance_request");
            
            // 분석 옵션 정보
            metadata.put("enableDormantPermissionAnalysis", context.isEnableDormantPermissionAnalysis());
            metadata.put("enableExcessivePermissionDetection", context.isEnableExcessivePermissionDetection());
            metadata.put("enableSodViolationCheck", context.isEnableSodViolationCheck());
            
            // 요청 ID 생성
            String requestId = UUID.randomUUID().toString();
            metadata.put("requestId", requestId);
            
            String requestText = String.format(
                "접근 거버넌스 분석 요청: 범위=%s, 타입=%s, 우선순위=%s, 조직=%s",
                context.getAuditScope(),
                context.getAnalysisType(),
                context.getPriority(),
                context.getOrganizationId()
            );
            
            Document requestDoc = new Document(requestText, metadata);
            storeDocument(requestDoc);
            
            log.debug("[AccessVectorService] 분석 요청 저장 완료: 범위={}", context.getAuditScope());
            
        } catch (Exception e) {
            log.error("[AccessVectorService] 분석 요청 저장 실패", e);
            throw new VectorStoreException("분석 요청 저장 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 분석 결과를 벡터 저장소에 저장
     * 
     * @param context 접근 거버넌스 컨텍스트
     * @param response 분석 결과
     */
    public void storeAnalysisResult(AccessGovernanceContext context, AccessGovernanceResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("auditScope", context.getAuditScope());
            metadata.put("analysisType", context.getAnalysisType());
            metadata.put("reportId", response.getAnalysisId());
            metadata.put("organizationId", context.getOrganizationId());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "access_governance_result");
            
            // 거버넌스 결과 정보
            metadata.put("governanceScore", response.getOverallGovernanceScore());
            metadata.put("riskLevel", response.getRiskLevel());
            metadata.put("governanceStatus", response.getRiskLevel());
            
            // 발견사항 및 권고사항 수
            metadata.put("findingsCount", response.getFindings() != null ? response.getFindings().size() : 0);
            metadata.put("recommendationsCount", response.getRecommendations() != null ? response.getRecommendations().size() : 0);
            
            // 위험 분류
            if (response.getOverallGovernanceScore() >= governanceThreshold) {
                metadata.put("isHighRisk", true);
                metadata.put("requiresAction", true);
            } else {
                metadata.put("isHighRisk", false);
                metadata.put("requiresAction", false);
            }
            
            // 특정 위험 유형 분석
            analyzeSpecificRiskTypes(response, metadata);
            
            String resultText = String.format(
                "접근 거버넌스 분석 결과: 점수=%.1f (%s), 상태=%s, 발견사항=%d개, 권고사항=%d개",
                response.getOverallGovernanceScore(),
                response.getRiskLevel(),
                response.getRiskLevel(),
                response.getFindings() != null ? response.getFindings().size() : 0,
                response.getRecommendations() != null ? response.getRecommendations().size() : 0
            );
            
            Document resultDoc = new Document(resultText, metadata);
            storeDocument(resultDoc);
            
            log.debug("[AccessVectorService] 분석 결과 저장 완료: 보고서ID={}", response.getAnalysisId());
            
        } catch (Exception e) {
            log.error("[AccessVectorService] 분석 결과 저장 실패", e);
            throw new VectorStoreException("분석 결과 저장 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 피드백 정보를 벡터 저장소에 저장
     * 
     * @param reportId 보고서 ID
     * @param isCorrect 분석이 정확했는지 여부
     * @param feedback 피드백 내용
     */
    public void storeFeedback(String reportId, boolean isCorrect, String feedback) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("reportId", reportId);
            metadata.put("feedbackCorrect", isCorrect);
            metadata.put("feedbackText", feedback);
            metadata.put("feedbackTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "access_governance_feedback");
            metadata.put("feedbackType", isCorrect ? "POSITIVE" : "NEGATIVE");
            
            // 피드백 카테고리 분석
            String feedbackCategory = categorizeFeedback(feedback);
            metadata.put("feedbackCategory", feedbackCategory);
            
            String feedbackText = String.format(
                "접근 거버넌스 분석 %s에 대한 피드백: %s - %s",
                reportId,
                isCorrect ? "정확함" : "부정확함",
                feedback
            );
            
            Document feedbackDoc = new Document(feedbackText, metadata);
            storeDocument(feedbackDoc);
            
            log.info("📚 [AccessVectorService] 피드백 저장 완료: 보고서ID={}, 정확도={}", 
                    reportId, isCorrect);
            
        } catch (Exception e) {
            log.error("[AccessVectorService] 피드백 저장 실패", e);
            throw new VectorStoreException("피드백 저장 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 권한 작업 타입 분류
     */
    private String classifyPermissionAction(String content) {
        if (content == null) return "UNKNOWN";
        
        for (Map.Entry<String, Pattern> entry : PERMISSION_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                return entry.getKey();
            }
        }
        
        return "OTHER";
    }
    
    /**
     * 리소스 민감도 분석
     */
    private String analyzeResourceSensitivity(String content, Map<String, Object> metadata) {
        String resourceAccessed = (String) metadata.get("resourceAccessed");
        String combinedText = (content + " " + (resourceAccessed != null ? resourceAccessed : "")).toLowerCase();
        
        for (Pattern pattern : SENSITIVE_RESOURCE_PATTERNS) {
            if (pattern.matcher(combinedText).find()) {
                return "HIGH";
            }
        }
        
        // 중간 민감도 키워드
        if (combinedText.contains("user") || combinedText.contains("role") || 
            combinedText.contains("permission") || combinedText.contains("data")) {
            return "MEDIUM";
        }
        
        return "LOW";
    }
    
    /**
     * SOD 위반 위험 분석
     */
    private boolean analyzeSodViolationRisk(Map<String, Object> metadata) {
        // 실제 구현에서는 사용자의 현재 권한 목록을 조회하여 분석
        String permissionAction = (String) metadata.get("permissionAction");
        String resourceSensitivity = (String) metadata.get("resourceSensitivity");
        
        // 고민감도 리소스에 대한 생성/승인 권한 동시 보유 시 위험
        if ("HIGH".equals(resourceSensitivity) && 
            ("GRANT".equals(permissionAction) || "CREATE".equals(permissionAction))) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 권한 상속 경로 분석
     */
    private void analyzePermissionInheritance(Map<String, Object> metadata) {
        // 권한 상속 깊이 계산 (실제로는 역할 계층 구조에서 계산)
        int inheritanceDepth = calculateInheritanceDepth(metadata);
        metadata.put("inheritanceDepth", inheritanceDepth);
        
        // 상속 경로 복잡도
        if (inheritanceDepth > 3) {
            metadata.put("complexInheritance", true);
        } else {
            metadata.put("complexInheritance", false);
        }
    }
    
    /**
     * 업무 분리 원칙 분석
     */
    private void analyzeBusinessSeparation(Map<String, Object> metadata) {
        String permissionAction = (String) metadata.get("permissionAction");
        String resourceSensitivity = (String) metadata.get("resourceSensitivity");
        
        // 금융 관련 업무 분리 체크
        if ("HIGH".equals(resourceSensitivity)) {
            if ("GRANT".equals(permissionAction) || "EXECUTE".equals(permissionAction)) {
                metadata.put("requiresBusinessSeparation", true);
            }
        }
    }
    
    /**
     * 권한 사용 패턴 분석
     */
    private void analyzePermissionUsagePattern(Map<String, Object> metadata) {
        // 시간 기반 사용 패턴
        LocalDateTime now = LocalDateTime.now();
        boolean isBusinessHours = now.getHour() >= 9 && now.getHour() < 18 && 
                                 now.getDayOfWeek().getValue() <= 5;
        
        metadata.put("isBusinessHours", isBusinessHours);
        
        if (!isBusinessHours && "HIGH".equals(metadata.get("resourceSensitivity"))) {
            metadata.put("unusualAccessTime", true);
        }
    }
    
    /**
     * 거버넌스 위험 점수 계산
     */
    private double calculateGovernanceRiskScore(Map<String, Object> metadata) {
        double score = 0.0;
        
        // 리소스 민감도 (30%)
        String sensitivity = (String) metadata.get("resourceSensitivity");
        if ("HIGH".equals(sensitivity)) score += 30.0;
        else if ("MEDIUM".equals(sensitivity)) score += 15.0;
        
        // SOD 위반 위험 (25%)
        if (Boolean.TRUE.equals(metadata.get("sodViolationRisk"))) {
            score += 25.0;
        }
        
        // 복잡한 상속 구조 (20%)
        if (Boolean.TRUE.equals(metadata.get("complexInheritance"))) {
            score += 20.0;
        }
        
        // 비정상 접근 시간 (15%)
        if (Boolean.TRUE.equals(metadata.get("unusualAccessTime"))) {
            score += 15.0;
        }
        
        // 업무 분리 요구사항 (10%)
        if (Boolean.TRUE.equals(metadata.get("requiresBusinessSeparation"))) {
            score += 10.0;
        }
        
        return Math.min(score, 100.0);
    }
    
    /**
     * 거버넌스 시그니처 생성
     */
    private String generateGovernanceSignature(Map<String, Object> metadata) {
        StringBuilder signature = new StringBuilder();
        
        signature.append(metadata.getOrDefault("permissionAction", "UNKNOWN"));
        signature.append("-");
        signature.append(metadata.getOrDefault("resourceSensitivity", "UNKNOWN"));
        
        if (Boolean.TRUE.equals(metadata.get("sodViolationRisk"))) {
            signature.append("-SOD_RISK");
        }
        
        if (Boolean.TRUE.equals(metadata.get("complexInheritance"))) {
            signature.append("-COMPLEX");
        }
        
        if (Boolean.TRUE.equals(metadata.get("unusualAccessTime"))) {
            signature.append("-UNUSUAL");
        }
        
        return signature.toString();
    }
    
    /**
     * 분석 결과 요약 생성
     */
    private Map<String, Object> generateAnalysisSummary(Map<String, Object> metadata) {
        Map<String, Object> summary = new HashMap<>();
        
        // 위험 요소 수집
        List<String> riskFactors = new ArrayList<>();
        if (Boolean.TRUE.equals(metadata.get("sodViolationRisk"))) {
            riskFactors.add("SOD 위반 위험");
        }
        if (Boolean.TRUE.equals(metadata.get("complexInheritance"))) {
            riskFactors.add("복잡한 권한 상속");
        }
        if (Boolean.TRUE.equals(metadata.get("unusualAccessTime"))) {
            riskFactors.add("비정상 접근 시간");
        }
        
        summary.put("riskFactors", riskFactors);
        summary.put("riskFactorCount", riskFactors.size());
        
        // 권고사항 생성
        List<String> recommendations = generateRecommendations(metadata);
        summary.put("recommendations", recommendations);
        
        return summary;
    }
    
    /**
     * 권고사항 생성
     */
    private List<String> generateRecommendations(Map<String, Object> metadata) {
        List<String> recommendations = new ArrayList<>();
        
        if (Boolean.TRUE.equals(metadata.get("sodViolationRisk"))) {
            recommendations.add("업무 분리 원칙을 준수하여 권한을 재할당하세요");
        }
        
        if (Boolean.TRUE.equals(metadata.get("complexInheritance"))) {
            recommendations.add("권한 상속 구조를 단순화하세요");
        }
        
        if (Boolean.TRUE.equals(metadata.get("unusualAccessTime"))) {
            recommendations.add("비정상 시간대의 접근에 대한 모니터링을 강화하세요");
        }
        
        Double riskScore = (Double) metadata.get("governanceRiskScore");
        if (riskScore != null && riskScore >= governanceThreshold) {
            recommendations.add("즉시 관리자 검토가 필요합니다");
        }
        
        return recommendations;
    }
    
    /**
     * 특정 위험 유형 분석
     */
    private void analyzeSpecificRiskTypes(AccessGovernanceResponse response, Map<String, Object> metadata) {
        if (response.getFindings() != null) {
            long excessivePermissions = response.getFindings().stream()
                .filter(finding -> finding.getType().contains("EXCESSIVE"))
                .count();
            
            long dormantPermissions = response.getFindings().stream()
                .filter(finding -> finding.getType().contains("DORMANT"))
                .count();
            
            long sodViolations = response.getFindings().stream()
                .filter(finding -> finding.getType().contains("SOD"))
                .count();
            
            metadata.put("excessivePermissionsCount", excessivePermissions);
            metadata.put("dormantPermissionsCount", dormantPermissions);
            metadata.put("sodViolationsCount", sodViolations);
        }
    }
    
    /**
     * 피드백 카테고리 분석
     */
    private String categorizeFeedback(String feedback) {
        if (feedback == null) return "GENERAL";
        
        String lowerFeedback = feedback.toLowerCase();
        
        if (lowerFeedback.contains("false positive") || lowerFeedback.contains("오탐")) {
            return "FALSE_POSITIVE";
        } else if (lowerFeedback.contains("missing") || lowerFeedback.contains("누락")) {
            return "MISSING_DETECTION";
        } else if (lowerFeedback.contains("accuracy") || lowerFeedback.contains("정확도")) {
            return "ACCURACY";
        } else if (lowerFeedback.contains("performance") || lowerFeedback.contains("성능")) {
            return "PERFORMANCE";
        }
        
        return "GENERAL";
    }
    
    /**
     * 상속 깊이 계산
     */
    private int calculateInheritanceDepth(Map<String, Object> metadata) {
        // 실제로는 역할 계층 구조에서 계산
        // 여기서는 임시로 메타데이터 기반 추정
        String permissionAction = (String) metadata.get("permissionAction");
        if ("ADMIN".equals(permissionAction)) return 3;
        if ("EXECUTE".equals(permissionAction)) return 2;
        return 1;
    }
    
    /**
     * 유효한 분석 타입 검증
     */
    private boolean isValidAnalysisType(String analysisType) {
        Set<String> validTypes = Set.of(
            "DORMANT_PERMISSIONS", "EXCESSIVE_PERMISSIONS", "SOD_VIOLATIONS", 
            "PERMISSION_INHERITANCE", "ROLE_MINING", "ACCESS_REVIEW"
        );
        return validTypes.contains(analysisType);
    }
    
    /**
     * 유효한 감사 범위 검증
     */
    private boolean isValidAuditScope(String auditScope) {
        Set<String> validScopes = Set.of(
            "ORGANIZATION", "DEPARTMENT", "ROLE", "USER", "RESOURCE", "APPLICATION"
        );
        return validScopes.contains(auditScope);
    }
    
    /**
     * 거버넌스 컨텍스트를 벡터 저장소에 저장
     * AccessGovernanceContextRetriever와의 통합을 위한 메서드
     * 
     * @param context 거버넌스 컨텍스트
     */
    public void storeGovernanceContext(AccessGovernanceContext context) {
        storeAnalysisRequest(context); // 기존 storeAnalysisRequest 메서드 활용
    }
    
    /**
     * 유사한 거버넌스 문서 검색
     * AccessGovernanceContextRetriever와의 통합을 위한 메서드
     * 
     * @param query 검색 쿼리
     * @param topK 검색할 최대 문서 수
     * @return 유사한 거버넌스 문서 목록
     */
    public List<Document> findSimilarGovernanceDocuments(String query, int topK) {
        try {
            Map<String, Object> filters = new HashMap<>();
            filters.put("documentType", "access_governance");
            filters.put("topK", topK);
            
            return searchSimilar(query, filters);
        } catch (Exception e) {
            log.error("[AccessVectorService] 유사 거버넌스 문서 검색 실패", e);
            return List.of();
        }
    }
}