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

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;

@Slf4j
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

    private static final Set<Pattern> SENSITIVE_RESOURCE_PATTERNS = Set.of(
        Pattern.compile(".*admin.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*system.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*config.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*secret.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*financial.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*hr.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*payroll.*", Pattern.CASE_INSENSITIVE)
    );

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
            
            String permissionAction = classifyPermissionAction(document.getText());
            metadata.put("permissionAction", permissionAction);

            String resourceSensitivity = analyzeResourceSensitivity(document.getText(), metadata);
            metadata.put("resourceSensitivity", resourceSensitivity);

            if (sodViolationTracking) {
                boolean sodRisk = analyzeSodViolationRisk(metadata);
                metadata.put("sodViolationRisk", sodRisk);
            }

            analyzePermissionInheritance(metadata);

            analyzeBusinessSeparation(metadata);

            analyzePermissionUsagePattern(metadata);

            double governanceRiskScore = calculateGovernanceRiskScore(metadata);
            metadata.put("governanceRiskScore", governanceRiskScore);

            String governanceSignature = generateGovernanceSignature(metadata);
            metadata.put("governanceSignature", governanceSignature);

            Map<String, Object> analysisSummary = generateAnalysisSummary(metadata);
            metadata.put("analysisSummary", analysisSummary);

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

        if (!metadata.containsKey("auditScope") && 
            !metadata.containsKey("analysisType") && 
            !metadata.containsKey("organizationId")) {
            throw new IllegalArgumentException(
                "접근 거버넌스 문서는 auditScope, analysisType, organizationId 중 최소 하나는 포함해야 합니다");
        }

        Object analysisType = metadata.get("analysisType");
        if (analysisType != null) {
            String typeStr = analysisType.toString();
            if (!isValidAnalysisType(typeStr)) {
                throw new IllegalArgumentException("유효하지 않은 분석 타입: " + typeStr);
            }
        }

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

            if (operationType == OperationType.STORE) {
                Double governanceScore = (Double) metadata.get("governanceRiskScore");
                if (governanceScore != null && governanceScore >= governanceThreshold) {
                    log.warn("[AccessVectorService] 고위험 거버넌스 이슈 감지: 범위={}, 점수={}", 
                            metadata.get("auditScope"), governanceScore);
                    
                    metadata.put("requiresImmediateReview", true);
                    metadata.put("governanceAlertTriggered", true);
                    metadata.put("alertTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
                }

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

    public void storeAnalysisRequest(AccessGovernanceContext context) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("auditScope", context.getAuditScope());
            metadata.put("analysisType", context.getAnalysisType());
            metadata.put("organizationId", context.getOrganizationId());
            metadata.put("priority", context.getPriority());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "access_governance_request");

            metadata.put("enableDormantPermissionAnalysis", context.isEnableDormantPermissionAnalysis());
            metadata.put("enableExcessivePermissionDetection", context.isEnableExcessivePermissionDetection());
            metadata.put("enableSodViolationCheck", context.isEnableSodViolationCheck());

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

        } catch (Exception e) {
            log.error("[AccessVectorService] 분석 요청 저장 실패", e);
            throw new VectorStoreException("분석 요청 저장 실패: " + e.getMessage(), e);
        }
    }

    public void storeAnalysisResult(AccessGovernanceContext context, AccessGovernanceResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("auditScope", context.getAuditScope());
            metadata.put("analysisType", context.getAnalysisType());
            metadata.put("reportId", response.getAnalysisId());
            metadata.put("organizationId", context.getOrganizationId());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "access_governance_result");

            metadata.put("governanceScore", response.getOverallGovernanceScore());
            metadata.put("riskLevel", response.getRiskLevel());
            metadata.put("governanceStatus", response.getRiskLevel());

            metadata.put("findingsCount", response.getFindings() != null ? response.getFindings().size() : 0);
            metadata.put("recommendationsCount", response.getRecommendations() != null ? response.getRecommendations().size() : 0);

            if (response.getOverallGovernanceScore() >= governanceThreshold) {
                metadata.put("isHighRisk", true);
                metadata.put("requiresAction", true);
            } else {
                metadata.put("isHighRisk", false);
                metadata.put("requiresAction", false);
            }

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

        } catch (Exception e) {
            log.error("[AccessVectorService] 분석 결과 저장 실패", e);
            throw new VectorStoreException("분석 결과 저장 실패: " + e.getMessage(), e);
        }
    }

    public void storeFeedback(String reportId, boolean isCorrect, String feedback) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("reportId", reportId);
            metadata.put("feedbackCorrect", isCorrect);
            metadata.put("feedbackText", feedback);
            metadata.put("feedbackTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "access_governance_feedback");
            metadata.put("feedbackType", isCorrect ? "POSITIVE" : "NEGATIVE");

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

        } catch (Exception e) {
            log.error("[AccessVectorService] 피드백 저장 실패", e);
            throw new VectorStoreException("피드백 저장 실패: " + e.getMessage(), e);
        }
    }

    private String classifyPermissionAction(String content) {
        if (content == null) return "UNKNOWN";
        
        for (Map.Entry<String, Pattern> entry : PERMISSION_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                return entry.getKey();
            }
        }
        
        return "OTHER";
    }

    private String analyzeResourceSensitivity(String content, Map<String, Object> metadata) {
        String resourceAccessed = (String) metadata.get("resourceAccessed");
        String combinedText = (content + " " + (resourceAccessed != null ? resourceAccessed : "")).toLowerCase();
        
        for (Pattern pattern : SENSITIVE_RESOURCE_PATTERNS) {
            if (pattern.matcher(combinedText).find()) {
                return "HIGH";
            }
        }

        if (combinedText.contains("user") || combinedText.contains("role") || 
            combinedText.contains("permission") || combinedText.contains("data")) {
            return "MEDIUM";
        }
        
        return "LOW";
    }

    private boolean analyzeSodViolationRisk(Map<String, Object> metadata) {
        
        String permissionAction = (String) metadata.get("permissionAction");
        String resourceSensitivity = (String) metadata.get("resourceSensitivity");

        if ("HIGH".equals(resourceSensitivity) && 
            ("GRANT".equals(permissionAction) || "CREATE".equals(permissionAction))) {
            return true;
        }
        
        return false;
    }

    private void analyzePermissionInheritance(Map<String, Object> metadata) {
        
        int inheritanceDepth = calculateInheritanceDepth(metadata);
        metadata.put("inheritanceDepth", inheritanceDepth);

        if (inheritanceDepth > 3) {
            metadata.put("complexInheritance", true);
        } else {
            metadata.put("complexInheritance", false);
        }
    }

    private void analyzeBusinessSeparation(Map<String, Object> metadata) {
        String permissionAction = (String) metadata.get("permissionAction");
        String resourceSensitivity = (String) metadata.get("resourceSensitivity");

        if ("HIGH".equals(resourceSensitivity)) {
            if ("GRANT".equals(permissionAction) || "EXECUTE".equals(permissionAction)) {
                metadata.put("requiresBusinessSeparation", true);
            }
        }
    }

    private void analyzePermissionUsagePattern(Map<String, Object> metadata) {
        
        LocalDateTime now = LocalDateTime.now();
        boolean isBusinessHours = now.getHour() >= 9 && now.getHour() < 18 && 
                                 now.getDayOfWeek().getValue() <= 5;
        
        metadata.put("isBusinessHours", isBusinessHours);
        
        if (!isBusinessHours && "HIGH".equals(metadata.get("resourceSensitivity"))) {
            metadata.put("unusualAccessTime", true);
        }
    }

    private double calculateGovernanceRiskScore(Map<String, Object> metadata) {
        double score = 0.0;

        String sensitivity = (String) metadata.get("resourceSensitivity");
        if ("HIGH".equals(sensitivity)) score += 30.0;
        else if ("MEDIUM".equals(sensitivity)) score += 15.0;

        if (Boolean.TRUE.equals(metadata.get("sodViolationRisk"))) {
            score += 25.0;
        }

        if (Boolean.TRUE.equals(metadata.get("complexInheritance"))) {
            score += 20.0;
        }

        if (Boolean.TRUE.equals(metadata.get("unusualAccessTime"))) {
            score += 15.0;
        }

        if (Boolean.TRUE.equals(metadata.get("requiresBusinessSeparation"))) {
            score += 10.0;
        }
        
        return Math.min(score, 100.0);
    }

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

    private Map<String, Object> generateAnalysisSummary(Map<String, Object> metadata) {
        Map<String, Object> summary = new HashMap<>();

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

        List<String> recommendations = generateRecommendations(metadata);
        summary.put("recommendations", recommendations);
        
        return summary;
    }

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

    private int calculateInheritanceDepth(Map<String, Object> metadata) {

        String permissionAction = (String) metadata.get("permissionAction");
        if ("ADMIN".equals(permissionAction)) return 3;
        if ("EXECUTE".equals(permissionAction)) return 2;
        return 1;
    }

    private boolean isValidAnalysisType(String analysisType) {
        Set<String> validTypes = Set.of(
            "DORMANT_PERMISSIONS", "EXCESSIVE_PERMISSIONS", "SOD_VIOLATIONS", 
            "PERMISSION_INHERITANCE", "ROLE_MINING", "ACCESS_REVIEW"
        );
        return validTypes.contains(analysisType);
    }

    private boolean isValidAuditScope(String auditScope) {
        Set<String> validScopes = Set.of(
            "ORGANIZATION", "DEPARTMENT", "ROLE", "USER", "RESOURCE", "APPLICATION"
        );
        return validScopes.contains(auditScope);
    }

    public void storeGovernanceContext(AccessGovernanceContext context) {
        storeAnalysisRequest(context); 
    }

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