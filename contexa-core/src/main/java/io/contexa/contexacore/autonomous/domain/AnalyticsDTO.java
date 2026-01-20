package io.contexa.contexacore.autonomous.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnalyticsDTO {
    
    
    private LocalDateTime startDate;
    private LocalDateTime endDate;
    private String period;
    
    
    private int totalProposals;
    private int approvedProposals;
    private int rejectedProposals;
    private int pendingProposals;
    private int activatedProposals;
    
    
    private double approvalRate;
    private double rejectionRate;
    private double autoApprovalRate;
    
    
    private double averageExpectedImpact;
    private double averageActualImpact;
    private double impactAccuracy;
    
    
    private double averageProcessingTimeHours;
    private double averageApprovalTimeHours;
    
    
    private Map<String, Integer> proposalsByType;
    
    
    private Map<String, Integer> proposalsByRiskLevel;
    
    
    private List<DailyTrend> dailyTrends;
    
    
    private List<TopPerformer> topPerformers;
    
    
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