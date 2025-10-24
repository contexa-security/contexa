package io.contexa.contexaiam.aiam.protocol.response;

import io.contexa.contexacommon.domain.response.IAMResponse;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

/**
 * AI 보안 어드바이저 (Security Copilot) 응답 클래스
 * 
 * IAMResponse 상속으로 표준 응답 패턴 준수
 * 다중 Lab 협업 결과 통합
 * 포괄적 보안 분석 결과 제공
 * 클라이언트 접근 필드 추가: riskLevel, categoryScores, complianceInfo
 */
@Getter
@Setter
public class SecurityCopilotResponse extends IAMResponse {
    
    /**
     * 분석 ID
     */
    private String analysisId;
    
    /**
     * 원본 질의
     */
    private String originalQuery;
    
    /**
     * 권한 구조 분석 결과 (StudioQueryLab)
     */
    private Object structureAnalysis;
    
    /**
     * 위험도 분석 결과 (RiskAssessmentLab)
     */
    private Object riskAnalysis;
    
    /**
     * 조치 방안 (PolicyGenerationLab)
     */
    private Object actionPlan;
    
    /**
     * 전체 보안 점수 (0-100)
     */
    private double overallSecurityScore;
    
    /**
     * 위험 수준 (LOW, MEDIUM, HIGH, CRITICAL)
     */
    private String riskLevel;
    
    /**
     * 카테고리별 점수 (클라이언트 직접 접근용)
     */
    private Map<String, Double> categoryScores;
    
    /**
     * 컴플라이언스 데이터 (클라이언트 직접 접근용)
     */
    private Map<String, Object> complianceData;
    
    /**
     * 실행 시간 (밀리초)
     */
    private long executionTimeMs;
    
    /**
     * 에러 메시지들 (String → String 매핑으로 수정)
     */
    private Map<String, String> errors;
    
    /**
     * 분석 메타데이터
     */
    private Map<String, Object> metadata;
    
    /**
     * 중요 발견사항 리스트
     */
    private List<Object> criticalFindings;
    
    /**
     * 권고사항 리스트
     */
    private List<Object> recommendations;
    
    /**
     * 컴플라이언스 상태
     */
    private String complianceStatus;
    
    /**
     * 위협 분석 결과
     */
    private ThreatAnalysis threatAnalysis;
    
    /**
     * 취약점 평가 결과
     */
    private VulnerabilityAssessment vulnerabilityAssessment;
    
    /**
     * 개별 Lab 결과들
     */
    private Map<String, Object> individualResults;
    
    /**
     * 위협 분석 내부 클래스
     */
    @Getter
    @Setter
    public static class ThreatAnalysis {
        private List<String> identifiedThreats;
        private String threatLevel;
        private List<String> attackVectors;
    }
    
    /**
     * 취약점 평가 내부 클래스
     */
    @Getter
    @Setter
    public static class VulnerabilityAssessment {
        private List<Object> vulnerabilities;
        private int criticalCount;
        private int patchableCount;
        
        public List<Object> getVulnerabilities() {
            return vulnerabilities;
        }
        
        public int getCriticalCount() {
            return criticalCount;
        }
        
        public int getPatchableCount() {
            return patchableCount;
        }
    }
    
    /**
     * 연관성 분석 결과 (권한-정책-리스크 간의 관계)
     */
    private Map<String, Object> relationshipAnalysis;
    
    /**
     * 통합 시각화 데이터 (관계망 시각화)
     */
    private Map<String, Object> integratedVisualizationData;
    
    /**
     * 다각적 인사이트 (긍정, 부정, 위험, 예측)
     */
    private Map<String, Object> multiPerspectiveInsights;
    
    /**
     * 조치 우선순위 (AI 기반 우선순위 결정)
     */
    private List<Map<String, Object>> actionPriorities;
    
    /**
     * 예측적 보안 분석 (AI 기반 미래 위험 예측)
     */
    private Map<String, Object> predictiveAnalysis;
    
    /**
     * 분석 완료 시간
     */
    private java.time.LocalDateTime completedAt;
    
    /**
     * 권장사항 요약
     */
    private String recommendationSummary;
    
    // ==================== 생성자들 ====================
    
    public SecurityCopilotResponse() {
        super("default", ExecutionStatus.SUCCESS);
    }
    
    public SecurityCopilotResponse(String requestId, ExecutionStatus status) {
        super(requestId, status);
    }
    
    public SecurityCopilotResponse(String requestId, ExecutionStatus status, String recommendationSummary) {
        super(requestId, status);
        this.recommendationSummary = recommendationSummary;
    }
    
    // ==================== IAMResponse 구현 ====================
    
    @Override
    public Object getData() {
        // 권장사항 요약을 주요 데이터로 반환
        return recommendationSummary != null ? recommendationSummary : "보안 분석 완료";
    }
    
    @Override
    public String getResponseType() {
        return "SECURITY_COPILOT";
    }
    
    // ==================== 빌더 패턴 지원 ====================
    
    public static SecurityCopilotResponseBuilder builder() {
        return new SecurityCopilotResponseBuilder();
    }
    
    public SecurityCopilotResponseBuilder toBuilder() {
        return new SecurityCopilotResponseBuilder(this);
    }
    
    public static class SecurityCopilotResponseBuilder {
        private String requestId = "default";
        private ExecutionStatus status = ExecutionStatus.SUCCESS;
        private String analysisId;
        private String originalQuery;
        private Object structureAnalysis;
        private Object riskAnalysis;
        private Object actionPlan;
        private double overallSecurityScore;
        private String riskLevel;
        private Map<String, Double> categoryScores;
        private Map<String, Object> complianceData;
        private long executionTimeMs;
        private Map<String, String> errors;
        private Map<String, Object> metadata;
        private Map<String, Object> relationshipAnalysis;
        private Map<String, Object> integratedVisualizationData;
        private Map<String, Object> multiPerspectiveInsights;
        private List<Map<String, Object>> actionPriorities;
        private Map<String, Object> predictiveAnalysis;
        private java.time.LocalDateTime completedAt;
        private String recommendationSummary;
        
        public SecurityCopilotResponseBuilder() {
        }
        
        public SecurityCopilotResponseBuilder(SecurityCopilotResponse existing) {
            this.requestId = existing.getResponseId();
            this.status = existing.getStatus();
            this.analysisId = existing.analysisId;
            this.originalQuery = existing.originalQuery;
            this.structureAnalysis = existing.structureAnalysis;
            this.riskAnalysis = existing.riskAnalysis;
            this.actionPlan = existing.actionPlan;
            this.overallSecurityScore = existing.overallSecurityScore;
            this.riskLevel = existing.riskLevel;
            this.categoryScores = existing.categoryScores;
            this.complianceData = existing.complianceData;
            this.executionTimeMs = existing.executionTimeMs;
            this.errors = existing.errors;
            this.metadata = existing.metadata;
            this.relationshipAnalysis = existing.relationshipAnalysis;
            this.integratedVisualizationData = existing.integratedVisualizationData;
            this.multiPerspectiveInsights = existing.multiPerspectiveInsights;
            this.actionPriorities = existing.actionPriorities;
            this.predictiveAnalysis = existing.predictiveAnalysis;
            this.completedAt = existing.completedAt;
            this.recommendationSummary = existing.recommendationSummary;
        }
        
        public SecurityCopilotResponseBuilder analysisId(String analysisId) {
            this.analysisId = analysisId;
            return this;
        }
        
        public SecurityCopilotResponseBuilder recommendationSummary(String recommendationSummary) {
            this.recommendationSummary = recommendationSummary;
            return this;
        }
        
        public SecurityCopilotResponseBuilder overallSecurityScore(double overallSecurityScore) {
            this.overallSecurityScore = overallSecurityScore;
            return this;
        }
        
        public SecurityCopilotResponseBuilder riskLevel(String riskLevel) {
            this.riskLevel = riskLevel;
            return this;
        }
        
        public SecurityCopilotResponseBuilder categoryScores(Map<String, Double> categoryScores) {
            this.categoryScores = categoryScores;
            return this;
        }
        
        public SecurityCopilotResponseBuilder complianceData(Map<String, Object> complianceData) {
            this.complianceData = complianceData;
            return this;
        }

        public SecurityCopilotResponseBuilder originalQuery(String originalQuery) {
            this.originalQuery = originalQuery;
            return this;
        }

        public SecurityCopilotResponseBuilder status(String status) {
            // status를 ExecutionStatus로 변환
            if ("COMPLETED".equals(status)) {
                this.status = ExecutionStatus.SUCCESS;
            } else if ("FAILED".equals(status)) {
                this.status = ExecutionStatus.FAILURE;
            } else if ("PARTIAL".equals(status)) {
                this.status = ExecutionStatus.PARTIAL_SUCCESS;
            } else {
                this.status = ExecutionStatus.SUCCESS;
            }
            return this;
        }
        
        public SecurityCopilotResponseBuilder executionTimeMs(long executionTimeMs) {
            this.executionTimeMs = executionTimeMs;
            return this;
        }
        
        public SecurityCopilotResponseBuilder errors(Map<String, String> errors) {
            this.errors = errors;
            return this;
        }
        
        public SecurityCopilotResponseBuilder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }
        
        public SecurityCopilotResponseBuilder completedAt(java.time.LocalDateTime completedAt) {
            this.completedAt = completedAt;
            return this;
        }
        
        public SecurityCopilotResponseBuilder relationshipAnalysis(Map<String, Object> relationshipAnalysis) {
            this.relationshipAnalysis = relationshipAnalysis;
            return this;
        }
        
        public SecurityCopilotResponseBuilder integratedVisualizationData(Map<String, Object> integratedVisualizationData) {
            this.integratedVisualizationData = integratedVisualizationData;
            return this;
        }
        
        public SecurityCopilotResponseBuilder multiPerspectiveInsights(Map<String, Object> multiPerspectiveInsights) {
            this.multiPerspectiveInsights = multiPerspectiveInsights;
            return this;
        }
        
        public SecurityCopilotResponseBuilder actionPriorities(List<Map<String, Object>> actionPriorities) {
            this.actionPriorities = actionPriorities;
            return this;
        }
        
        public SecurityCopilotResponseBuilder predictiveAnalysis(Map<String, Object> predictiveAnalysis) {
            this.predictiveAnalysis = predictiveAnalysis;
            return this;
        }
        
        public SecurityCopilotResponse build() {
            SecurityCopilotResponse response = new SecurityCopilotResponse(this.requestId, this.status, this.recommendationSummary);
            response.analysisId = this.analysisId;
            response.originalQuery = this.originalQuery;
            response.structureAnalysis = this.structureAnalysis;
            response.riskAnalysis = this.riskAnalysis;
            response.actionPlan = this.actionPlan;
            response.overallSecurityScore = this.overallSecurityScore;
            response.riskLevel = this.riskLevel;
            response.categoryScores = this.categoryScores;
            response.complianceData = this.complianceData;
            response.executionTimeMs = this.executionTimeMs;
            response.errors = this.errors;
            response.metadata = this.metadata;
            response.relationshipAnalysis = this.relationshipAnalysis;
            response.integratedVisualizationData = this.integratedVisualizationData;
            response.multiPerspectiveInsights = this.multiPerspectiveInsights;
            response.actionPriorities = this.actionPriorities;
            response.predictiveAnalysis = this.predictiveAnalysis;
            response.completedAt = this.completedAt;
            return response;
        }
    }
    
    // ==================== 유틸리티 메서드들 ====================
    
    /**
     * 성공적으로 완료된 분석인지 확인
     */
    public boolean isSuccessful() {
        ExecutionStatus status = getStatus();
        return status == ExecutionStatus.SUCCESS || status == ExecutionStatus.PARTIAL_SUCCESS;
    }
    
    /**
     * 에러가 있는지 확인
     */
    public boolean hasErrors() {
        return errors != null && !errors.isEmpty();
    }
    
    /**
     * 보안 점수에 따른 위험 등급 반환 (기존 호환성 유지)
     */
    public String getRiskLevel() {
        // 필드가 이미 설정되어 있으면 그것을 반환
        if (riskLevel != null) {
            return riskLevel;
        }
        
        // 그렇지 않으면 점수로 계산
        if (overallSecurityScore >= 80) return "LOW";
        if (overallSecurityScore >= 60) return "MEDIUM";
        if (overallSecurityScore >= 40) return "HIGH";
        return "CRITICAL";
    }
    
    /**
     * 카테고리 점수 반환 (기존 호환성 유지)
     */
    public Map<String, Double> getCategoryScores() {
        // 필드가 이미 설정되어 있으면 그것을 반환
        if (categoryScores != null) {
            return categoryScores;
        }
        
        // 그렇지 않으면 metadata에서 찾기
        if (metadata != null && metadata.containsKey("categoryScores")) {
            @SuppressWarnings("unchecked")
            Map<String, Double> metadataScores = (Map<String, Double>) metadata.get("categoryScores");
            return metadataScores;
        }
        
        return new java.util.HashMap<>();
    }
    
    /**
     * 컴플라이언스 데이터 반환 (클라이언트 접근용)
     */
    public Map<String, Object> getComplianceData() {
        // 필드가 이미 설정되어 있으면 그것을 반환
        if (complianceData != null) {
            return complianceData;
        }
        
        // 그렇지 않으면 metadata에서 찾기
        if (metadata != null && metadata.containsKey("complianceStatus")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> metadataCompliance = (Map<String, Object>) metadata.get("complianceStatus");
            return metadataCompliance;
        }
        
        return new java.util.HashMap<>();
    }
} 