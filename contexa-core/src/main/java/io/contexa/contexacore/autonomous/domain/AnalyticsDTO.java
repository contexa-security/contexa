package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * 분석 통계 DTO
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnalyticsDTO {
    
    // 기간 정보
    private LocalDateTime startDate;
    private LocalDateTime endDate;
    private String period;
    
    // 제안 통계
    private int totalProposals;
    private int approvedProposals;
    private int rejectedProposals;
    private int pendingProposals;
    private int activatedProposals;
    
    // 승인율
    private double approvalRate;
    private double rejectionRate;
    private double autoApprovalRate;
    
    // 효과성
    private double averageExpectedImpact;
    private double averageActualImpact;
    private double impactAccuracy;
    
    // 처리 시간
    private double averageProcessingTimeHours;
    private double averageApprovalTimeHours;
    
    // 제안 유형별 통계
    private Map<String, Integer> proposalsByType;
    
    // 위험 수준별 통계
    private Map<String, Integer> proposalsByRiskLevel;
    
    // 일별 트렌드
    private List<DailyTrend> dailyTrends;
    
    // 최고 성과 제안
    private List<TopPerformer> topPerformers;
    
    /**
     * 일별 트렌드
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DailyTrend {
        private LocalDateTime date;
        private int proposals;
        private int approvals;
        private int rejections;
        private int activations;
    }
    
    /**
     * 최고 성과 제안
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TopPerformer {
        private Long proposalId;
        private String title;
        private double actualImpact;
        private double improvementRate;
        private LocalDateTime activatedAt;
    }
}