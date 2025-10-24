package io.contexa.contexacore.autonomous.monitor;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalType;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.RiskLevel;
import io.contexa.contexacore.autonomous.repository.PolicyEvolutionProposalRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 정책 제안 분석 시스템
 * 통계 생성, 트렌드 분석, 대시보드 데이터 제공
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PolicyProposalAnalytics {
    
    private final PolicyEvolutionProposalRepository proposalRepository;
    private final PolicyEffectivenessMonitor effectivenessMonitor;
    
    // 분석 데이터 캐시
    private final Map<String, AnalyticsSnapshot> analyticsCache = new ConcurrentHashMap<>();
    
    /**
     * 분석 스냅샷
     */
    public static class AnalyticsSnapshot {
        private LocalDateTime timestamp;
        private Map<String, Object> metrics;
        private Map<String, List<DataPoint>> trends;
        private Map<String, Object> insights;
        
        public AnalyticsSnapshot() {
            this.timestamp = LocalDateTime.now();
            this.metrics = new HashMap<>();
            this.trends = new HashMap<>();
            this.insights = new HashMap<>();
        }
        
        public void addMetric(String name, Object value) {
            metrics.put(name, value);
        }
        
        public void addTrend(String name, List<DataPoint> dataPoints) {
            trends.put(name, dataPoints);
        }
        
        public void addInsight(String category, Object insight) {
            insights.put(category, insight);
        }
        
        public Map<String, Object> getMetrics() { return metrics; }
        public Map<String, List<DataPoint>> getTrends() { return trends; }
        public Map<String, Object> getInsights() { return insights; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    /**
     * 데이터 포인트
     */
    public static class DataPoint {
        private LocalDateTime timestamp;
        private double value;
        private String label;
        
        public DataPoint(LocalDateTime timestamp, double value, String label) {
            this.timestamp = timestamp;
            this.value = value;
            this.label = label;
        }
        
        public LocalDateTime getTimestamp() { return timestamp; }
        public double getValue() { return value; }
        public String getLabel() { return label; }
    }
    
    /**
     * 대시보드 통계 생성
     */
    public DashboardStatistics generateDashboardStatistics() {
        DashboardStatistics stats = new DashboardStatistics();
        
        // 전체 제안 통계
        List<PolicyEvolutionProposal> allProposals = proposalRepository.findAll();
        stats.setTotalProposals(allProposals.size());
        
        // 상태별 통계
        Map<ProposalStatus, Long> statusCounts = allProposals.stream()
            .collect(Collectors.groupingBy(
                PolicyEvolutionProposal::getStatus,
                Collectors.counting()
            ));
        stats.setProposalsByStatus(statusCounts);
        
        // 타입별 통계
        Map<ProposalType, Long> typeCounts = allProposals.stream()
            .collect(Collectors.groupingBy(
                PolicyEvolutionProposal::getProposalType,
                Collectors.counting()
            ));
        stats.setProposalsByType(typeCounts);
        
        // 위험 레벨별 통계
        Map<RiskLevel, Long> riskCounts = allProposals.stream()
            .collect(Collectors.groupingBy(
                PolicyEvolutionProposal::getRiskLevel,
                Collectors.counting()
            ));
        stats.setProposalsByRiskLevel(riskCounts);
        
        // 승인율 계산
        long approvedCount = statusCounts.getOrDefault(ProposalStatus.APPROVED, 0L);
        long rejectedCount = statusCounts.getOrDefault(ProposalStatus.REJECTED, 0L);
        double approvalRate = (approvedCount + rejectedCount) > 0 ?
            (double) approvedCount / (approvedCount + rejectedCount) * 100 : 0;
        stats.setApprovalRate(approvalRate);
        
        // 평균 처리 시간 계산
        double avgProcessingTime = calculateAverageProcessingTime(allProposals);
        stats.setAverageProcessingTime(avgProcessingTime);
        
        // 활성 정책 수
        long activePolicies = allProposals.stream()
            .filter(p -> p.getStatus() == ProposalStatus.APPROVED)
            .filter(p -> p.getPolicyId() != null)
            .count();
        stats.setActivePolicies(activePolicies);
        
        // 이번 주 제안 수
        long weeklyProposals = allProposals.stream()
            .filter(p -> p.getCreatedAt().isAfter(LocalDateTime.now().minusWeeks(1)))
            .count();
        stats.setWeeklyProposals(weeklyProposals);
        
        // 이번 달 제안 수
        long monthlyProposals = allProposals.stream()
            .filter(p -> p.getCreatedAt().isAfter(LocalDateTime.now().minusMonths(1)))
            .count();
        stats.setMonthlyProposals(monthlyProposals);
        
        log.info("Dashboard statistics generated: {} total proposals, {:.2f}% approval rate",
            stats.getTotalProposals(), stats.getApprovalRate());
        
        return stats;
    }
    
    /**
     * 트렌드 분석
     */
    public TrendAnalysis analyzeTrends(int days) {
        TrendAnalysis analysis = new TrendAnalysis();
        LocalDateTime startDate = LocalDateTime.now().minusDays(days);
        
        List<PolicyEvolutionProposal> proposals = proposalRepository.findAll().stream()
            .filter(p -> p.getCreatedAt().isAfter(startDate))
            .collect(Collectors.toList());
        
        // 일별 제안 트렌드
        List<DataPoint> dailyProposals = generateDailyTrend(proposals, days);
        analysis.setDailyProposalTrend(dailyProposals);
        
        // 타입별 트렌드
        Map<ProposalType, List<DataPoint>> typesTrend = generateTypeTrends(proposals, days);
        analysis.setTypesTrend(typesTrend);
        
        // 위험 레벨 트렌드
        Map<RiskLevel, List<DataPoint>> riskTrend = generateRiskTrends(proposals, days);
        analysis.setRiskLevelTrend(riskTrend);
        
        // 승인율 트렌드
        List<DataPoint> approvalRateTrend = generateApprovalRateTrend(proposals, days);
        analysis.setApprovalRateTrend(approvalRateTrend);
        
        // 효과성 트렌드
        List<DataPoint> effectivenessTrend = generateEffectivenessTrend(proposals, days);
        analysis.setEffectivenessTrend(effectivenessTrend);
        
        // 트렌드 인사이트 생성
        TrendInsights insights = generateTrendInsights(analysis);
        analysis.setInsights(insights);
        
        log.info("Trend analysis completed for {} days period", days);
        
        return analysis;
    }
    
    /**
     * 일별 제안 트렌드 생성
     */
    private List<DataPoint> generateDailyTrend(List<PolicyEvolutionProposal> proposals, int days) {
        List<DataPoint> trend = new ArrayList<>();
        
        for (int i = days - 1; i >= 0; i--) {
            LocalDateTime date = LocalDateTime.now().minusDays(i).truncatedTo(ChronoUnit.DAYS);
            LocalDateTime nextDate = date.plusDays(1);
            
            long count = proposals.stream()
                .filter(p -> p.getCreatedAt().isAfter(date) && p.getCreatedAt().isBefore(nextDate))
                .count();
            
            trend.add(new DataPoint(date, count, date.toLocalDate().toString()));
        }
        
        return trend;
    }
    
    /**
     * 타입별 트렌드 생성
     */
    private Map<ProposalType, List<DataPoint>> generateTypeTrends(List<PolicyEvolutionProposal> proposals, int days) {
        Map<ProposalType, List<DataPoint>> trends = new HashMap<>();
        
        for (ProposalType type : ProposalType.values()) {
            List<DataPoint> typeTrend = new ArrayList<>();
            
            for (int i = days - 1; i >= 0; i--) {
                LocalDateTime date = LocalDateTime.now().minusDays(i).truncatedTo(ChronoUnit.DAYS);
                LocalDateTime nextDate = date.plusDays(1);
                
                long count = proposals.stream()
                    .filter(p -> p.getProposalType() == type)
                    .filter(p -> p.getCreatedAt().isAfter(date) && p.getCreatedAt().isBefore(nextDate))
                    .count();
                
                typeTrend.add(new DataPoint(date, count, date.toLocalDate().toString()));
            }
            
            trends.put(type, typeTrend);
        }
        
        return trends;
    }
    
    /**
     * 위험 레벨 트렌드 생성
     */
    private Map<RiskLevel, List<DataPoint>> generateRiskTrends(List<PolicyEvolutionProposal> proposals, int days) {
        Map<RiskLevel, List<DataPoint>> trends = new HashMap<>();
        
        for (RiskLevel risk : RiskLevel.values()) {
            List<DataPoint> riskTrend = new ArrayList<>();
            
            for (int i = days - 1; i >= 0; i--) {
                LocalDateTime date = LocalDateTime.now().minusDays(i).truncatedTo(ChronoUnit.DAYS);
                LocalDateTime nextDate = date.plusDays(1);
                
                long count = proposals.stream()
                    .filter(p -> p.getRiskLevel() == risk)
                    .filter(p -> p.getCreatedAt().isAfter(date) && p.getCreatedAt().isBefore(nextDate))
                    .count();
                
                riskTrend.add(new DataPoint(date, count, date.toLocalDate().toString()));
            }
            
            trends.put(risk, riskTrend);
        }
        
        return trends;
    }
    
    /**
     * 승인율 트렌드 생성
     */
    private List<DataPoint> generateApprovalRateTrend(List<PolicyEvolutionProposal> proposals, int days) {
        List<DataPoint> trend = new ArrayList<>();
        
        for (int i = days - 1; i >= 0; i--) {
            LocalDateTime date = LocalDateTime.now().minusDays(i).truncatedTo(ChronoUnit.DAYS);
            LocalDateTime nextDate = date.plusDays(1);
            
            List<PolicyEvolutionProposal> dayProposals = proposals.stream()
                .filter(p -> p.getCreatedAt().isAfter(date) && p.getCreatedAt().isBefore(nextDate))
                .collect(Collectors.toList());
            
            long approved = dayProposals.stream()
                .filter(p -> p.getStatus() == ProposalStatus.APPROVED)
                .count();
            
            long total = dayProposals.stream()
                .filter(p -> p.getStatus() == ProposalStatus.APPROVED || 
                           p.getStatus() == ProposalStatus.REJECTED)
                .count();
            
            double rate = total > 0 ? (double) approved / total * 100 : 0;
            
            trend.add(new DataPoint(date, rate, date.toLocalDate().toString()));
        }
        
        return trend;
    }
    
    /**
     * 효과성 트렌드 생성
     */
    private List<DataPoint> generateEffectivenessTrend(List<PolicyEvolutionProposal> proposals, int days) {
        List<DataPoint> trend = new ArrayList<>();
        
        for (int i = days - 1; i >= 0; i--) {
            LocalDateTime date = LocalDateTime.now().minusDays(i).truncatedTo(ChronoUnit.DAYS);
            LocalDateTime nextDate = date.plusDays(1);
            
            List<PolicyEvolutionProposal> dayProposals = proposals.stream()
                .filter(p -> p.getStatus() == ProposalStatus.APPROVED)
                .filter(p -> p.getCreatedAt().isAfter(date) && p.getCreatedAt().isBefore(nextDate))
                .collect(Collectors.toList());
            
            double avgEffectiveness = dayProposals.stream()
                .mapToDouble(p -> effectivenessMonitor.calculateActualImpact(p.getId()))
                .average()
                .orElse(0.0);
            
            trend.add(new DataPoint(date, avgEffectiveness, date.toLocalDate().toString()));
        }
        
        return trend;
    }
    
    /**
     * 트렌드 인사이트 생성
     */
    private TrendInsights generateTrendInsights(TrendAnalysis analysis) {
        TrendInsights insights = new TrendInsights();
        
        // 제안 증가/감소 트렌드
        List<DataPoint> dailyTrend = analysis.getDailyProposalTrend();
        if (!dailyTrend.isEmpty()) {
            double firstWeekAvg = dailyTrend.stream()
                .limit(7)
                .mapToDouble(DataPoint::getValue)
                .average()
                .orElse(0);
            
            double lastWeekAvg = dailyTrend.stream()
                .skip(Math.max(0, dailyTrend.size() - 7))
                .mapToDouble(DataPoint::getValue)
                .average()
                .orElse(0);
            
            double growthRate = firstWeekAvg > 0 ? 
                (lastWeekAvg - firstWeekAvg) / firstWeekAvg * 100 : 0;
            
            insights.setProposalGrowthRate(growthRate);
            
            if (growthRate > 20) {
                insights.addInsight("Significant increase in policy proposals detected");
            } else if (growthRate < -20) {
                insights.addInsight("Significant decrease in policy proposals detected");
            }
        }
        
        // 가장 활발한 정책 타입
        Map<ProposalType, Double> typeActivity = new HashMap<>();
        for (Map.Entry<ProposalType, List<DataPoint>> entry : analysis.getTypesTrend().entrySet()) {
            double total = entry.getValue().stream()
                .mapToDouble(DataPoint::getValue)
                .sum();
            typeActivity.put(entry.getKey(), total);
        }
        
        ProposalType mostActiveType = typeActivity.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse(null);
        
        if (mostActiveType != null) {
            insights.setMostActiveType(mostActiveType);
            insights.addInsight("Most active policy type: " + mostActiveType);
        }
        
        // 위험 레벨 분포 변화
        Map<RiskLevel, List<DataPoint>> riskTrends = analysis.getRiskLevelTrend();
        double highRiskIncrease = calculateTrendSlope(riskTrends.get(RiskLevel.HIGH));
        
        if (highRiskIncrease > 0.5) {
            insights.addInsight("Increasing trend in high-risk policy proposals");
            insights.setHighRiskAlert(true);
        }
        
        // 승인율 변화
        List<DataPoint> approvalTrend = analysis.getApprovalRateTrend();
        double approvalSlope = calculateTrendSlope(approvalTrend);
        
        if (approvalSlope < -0.5) {
            insights.addInsight("Declining approval rate trend detected");
            insights.setApprovalRateDeclining(true);
        }
        
        // 효과성 트렌드
        List<DataPoint> effectivenessTrend = analysis.getEffectivenessTrend();
        double avgEffectiveness = effectivenessTrend.stream()
            .mapToDouble(DataPoint::getValue)
            .average()
            .orElse(0);
        
        insights.setAverageEffectiveness(avgEffectiveness);
        
        if (avgEffectiveness < 50) {
            insights.addInsight("Policy effectiveness below optimal threshold");
        } else if (avgEffectiveness > 80) {
            insights.addInsight("Excellent policy effectiveness maintained");
        }
        
        return insights;
    }
    
    /**
     * 트렌드 기울기 계산 (선형 회귀)
     */
    private double calculateTrendSlope(List<DataPoint> trend) {
        if (trend == null || trend.size() < 2) {
            return 0;
        }
        
        int n = trend.size();
        double sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
        
        for (int i = 0; i < n; i++) {
            double x = i;
            double y = trend.get(i).getValue();
            
            sumX += x;
            sumY += y;
            sumXY += x * y;
            sumX2 += x * x;
        }
        
        double slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
        return slope;
    }
    
    /**
     * 평균 처리 시간 계산
     */
    private double calculateAverageProcessingTime(List<PolicyEvolutionProposal> proposals) {
        return proposals.stream()
            .filter(p -> p.getStatus() == ProposalStatus.APPROVED || 
                        p.getStatus() == ProposalStatus.REJECTED)
            .filter(p -> p.getApprovedAt() != null)
            .mapToDouble(p -> ChronoUnit.HOURS.between(p.getCreatedAt(), p.getApprovedAt()))
            .average()
            .orElse(0);
    }
    
    /**
     * 성능 메트릭 생성
     */
    public PerformanceMetrics generatePerformanceMetrics() {
        PerformanceMetrics metrics = new PerformanceMetrics();
        
        List<PolicyEvolutionProposal> approvedProposals = proposalRepository.findAll().stream()
            .filter(p -> p.getStatus() == ProposalStatus.APPROVED)
            .collect(Collectors.toList());
        
        // 평균 효과성
        double avgEffectiveness = approvedProposals.stream()
            .mapToDouble(p -> effectivenessMonitor.calculateActualImpact(p.getId()))
            .average()
            .orElse(0);
        metrics.setAverageEffectiveness(avgEffectiveness);
        
        // 최고/최저 성과 정책
        PolicyEvolutionProposal bestPerformer = approvedProposals.stream()
            .max(Comparator.comparingDouble(p -> effectivenessMonitor.calculateActualImpact(p.getId())))
            .orElse(null);
        
        PolicyEvolutionProposal worstPerformer = approvedProposals.stream()
            .min(Comparator.comparingDouble(p -> effectivenessMonitor.calculateActualImpact(p.getId())))
            .orElse(null);
        
        if (bestPerformer != null) {
            metrics.setBestPerformingPolicy(bestPerformer.getTitle());
            metrics.setBestPerformanceScore(effectivenessMonitor.calculateActualImpact(bestPerformer.getId()));
        }
        
        if (worstPerformer != null) {
            metrics.setWorstPerformingPolicy(worstPerformer.getTitle());
            metrics.setWorstPerformanceScore(effectivenessMonitor.calculateActualImpact(worstPerformer.getId()));
        }
        
        // 타입별 성과
        Map<ProposalType, Double> performanceByType = approvedProposals.stream()
            .collect(Collectors.groupingBy(
                PolicyEvolutionProposal::getProposalType,
                Collectors.averagingDouble(p -> effectivenessMonitor.calculateActualImpact(p.getId()))
            ));
        metrics.setPerformanceByType(performanceByType);
        
        // 위험 레벨별 성과
        Map<RiskLevel, Double> performanceByRisk = approvedProposals.stream()
            .collect(Collectors.groupingBy(
                PolicyEvolutionProposal::getRiskLevel,
                Collectors.averagingDouble(p -> effectivenessMonitor.calculateActualImpact(p.getId()))
            ));
        metrics.setPerformanceByRisk(performanceByRisk);
        
        log.info("Performance metrics generated: avg effectiveness {:.2f}%", avgEffectiveness);
        
        return metrics;
    }
    
    /**
     * 대시보드 통계 클래스
     */
    public static class DashboardStatistics {
        private long totalProposals;
        private Map<ProposalStatus, Long> proposalsByStatus;
        private Map<ProposalType, Long> proposalsByType;
        private Map<RiskLevel, Long> proposalsByRiskLevel;
        private double approvalRate;
        private double averageProcessingTime;
        private long activePolicies;
        private long weeklyProposals;
        private long monthlyProposals;
        
        // Getters and Setters
        public long getTotalProposals() { return totalProposals; }
        public void setTotalProposals(long totalProposals) { this.totalProposals = totalProposals; }
        
        public Map<ProposalStatus, Long> getProposalsByStatus() { return proposalsByStatus; }
        public void setProposalsByStatus(Map<ProposalStatus, Long> proposalsByStatus) { 
            this.proposalsByStatus = proposalsByStatus; 
        }
        
        public Map<ProposalType, Long> getProposalsByType() { return proposalsByType; }
        public void setProposalsByType(Map<ProposalType, Long> proposalsByType) { 
            this.proposalsByType = proposalsByType; 
        }
        
        public Map<RiskLevel, Long> getProposalsByRiskLevel() { return proposalsByRiskLevel; }
        public void setProposalsByRiskLevel(Map<RiskLevel, Long> proposalsByRiskLevel) { 
            this.proposalsByRiskLevel = proposalsByRiskLevel; 
        }
        
        public double getApprovalRate() { return approvalRate; }
        public void setApprovalRate(double approvalRate) { this.approvalRate = approvalRate; }
        
        public double getAverageProcessingTime() { return averageProcessingTime; }
        public void setAverageProcessingTime(double averageProcessingTime) { 
            this.averageProcessingTime = averageProcessingTime; 
        }
        
        public long getActivePolicies() { return activePolicies; }
        public void setActivePolicies(long activePolicies) { this.activePolicies = activePolicies; }
        
        public long getWeeklyProposals() { return weeklyProposals; }
        public void setWeeklyProposals(long weeklyProposals) { this.weeklyProposals = weeklyProposals; }
        
        public long getMonthlyProposals() { return monthlyProposals; }
        public void setMonthlyProposals(long monthlyProposals) { this.monthlyProposals = monthlyProposals; }
    }
    
    /**
     * 트렌드 분석 클래스
     */
    public static class TrendAnalysis {
        private List<DataPoint> dailyProposalTrend;
        private Map<ProposalType, List<DataPoint>> typesTrend;
        private Map<RiskLevel, List<DataPoint>> riskLevelTrend;
        private List<DataPoint> approvalRateTrend;
        private List<DataPoint> effectivenessTrend;
        private TrendInsights insights;
        
        // Getters and Setters
        public List<DataPoint> getDailyProposalTrend() { return dailyProposalTrend; }
        public void setDailyProposalTrend(List<DataPoint> dailyProposalTrend) { 
            this.dailyProposalTrend = dailyProposalTrend; 
        }
        
        public Map<ProposalType, List<DataPoint>> getTypesTrend() { return typesTrend; }
        public void setTypesTrend(Map<ProposalType, List<DataPoint>> typesTrend) { 
            this.typesTrend = typesTrend; 
        }
        
        public Map<RiskLevel, List<DataPoint>> getRiskLevelTrend() { return riskLevelTrend; }
        public void setRiskLevelTrend(Map<RiskLevel, List<DataPoint>> riskLevelTrend) { 
            this.riskLevelTrend = riskLevelTrend; 
        }
        
        public List<DataPoint> getApprovalRateTrend() { return approvalRateTrend; }
        public void setApprovalRateTrend(List<DataPoint> approvalRateTrend) { 
            this.approvalRateTrend = approvalRateTrend; 
        }
        
        public List<DataPoint> getEffectivenessTrend() { return effectivenessTrend; }
        public void setEffectivenessTrend(List<DataPoint> effectivenessTrend) { 
            this.effectivenessTrend = effectivenessTrend; 
        }
        
        public TrendInsights getInsights() { return insights; }
        public void setInsights(TrendInsights insights) { this.insights = insights; }
    }
    
    /**
     * 트렌드 인사이트 클래스
     */
    public static class TrendInsights {
        private double proposalGrowthRate;
        private ProposalType mostActiveType;
        private boolean highRiskAlert;
        private boolean approvalRateDeclining;
        private double averageEffectiveness;
        private List<String> insights = new ArrayList<>();
        
        public void addInsight(String insight) {
            insights.add(insight);
        }
        
        // Getters and Setters
        public double getProposalGrowthRate() { return proposalGrowthRate; }
        public void setProposalGrowthRate(double proposalGrowthRate) { 
            this.proposalGrowthRate = proposalGrowthRate; 
        }
        
        public ProposalType getMostActiveType() { return mostActiveType; }
        public void setMostActiveType(ProposalType mostActiveType) { 
            this.mostActiveType = mostActiveType; 
        }
        
        public boolean isHighRiskAlert() { return highRiskAlert; }
        public void setHighRiskAlert(boolean highRiskAlert) { this.highRiskAlert = highRiskAlert; }
        
        public boolean isApprovalRateDeclining() { return approvalRateDeclining; }
        public void setApprovalRateDeclining(boolean approvalRateDeclining) { 
            this.approvalRateDeclining = approvalRateDeclining; 
        }
        
        public double getAverageEffectiveness() { return averageEffectiveness; }
        public void setAverageEffectiveness(double averageEffectiveness) { 
            this.averageEffectiveness = averageEffectiveness; 
        }
        
        public List<String> getInsights() { return insights; }
    }
    
    /**
     * 성능 메트릭 클래스
     */
    public static class PerformanceMetrics {
        private double averageEffectiveness;
        private String bestPerformingPolicy;
        private double bestPerformanceScore;
        private String worstPerformingPolicy;
        private double worstPerformanceScore;
        private Map<ProposalType, Double> performanceByType;
        private Map<RiskLevel, Double> performanceByRisk;
        
        // Getters and Setters
        public double getAverageEffectiveness() { return averageEffectiveness; }
        public void setAverageEffectiveness(double averageEffectiveness) { 
            this.averageEffectiveness = averageEffectiveness; 
        }
        
        public String getBestPerformingPolicy() { return bestPerformingPolicy; }
        public void setBestPerformingPolicy(String bestPerformingPolicy) { 
            this.bestPerformingPolicy = bestPerformingPolicy; 
        }
        
        public double getBestPerformanceScore() { return bestPerformanceScore; }
        public void setBestPerformanceScore(double bestPerformanceScore) { 
            this.bestPerformanceScore = bestPerformanceScore; 
        }
        
        public String getWorstPerformingPolicy() { return worstPerformingPolicy; }
        public void setWorstPerformingPolicy(String worstPerformingPolicy) { 
            this.worstPerformingPolicy = worstPerformingPolicy; 
        }
        
        public double getWorstPerformanceScore() { return worstPerformanceScore; }
        public void setWorstPerformanceScore(double worstPerformanceScore) { 
            this.worstPerformanceScore = worstPerformanceScore; 
        }
        
        public Map<ProposalType, Double> getPerformanceByType() { return performanceByType; }
        public void setPerformanceByType(Map<ProposalType, Double> performanceByType) { 
            this.performanceByType = performanceByType; 
        }
        
        public Map<RiskLevel, Double> getPerformanceByRisk() { return performanceByRisk; }
        public void setPerformanceByRisk(Map<RiskLevel, Double> performanceByRisk) { 
            this.performanceByRisk = performanceByRisk; 
        }
    }
    
    /**
     * 주기적 분석 업데이트 (매시간)
     */
//    @Scheduled(fixedDelay = 3600000) // 1시간마다
    public void updateAnalytics() {
        log.info("Updating analytics cache...");
        
        AnalyticsSnapshot snapshot = new AnalyticsSnapshot();
        
        // 대시보드 통계 업데이트
        DashboardStatistics stats = generateDashboardStatistics();
        snapshot.addMetric("dashboardStats", stats);
        
        // 7일 트렌드 업데이트
        TrendAnalysis weeklyTrend = analyzeTrends(7);
        snapshot.addTrend("weekly", weeklyTrend.getDailyProposalTrend());
        
        // 30일 트렌드 업데이트
        TrendAnalysis monthlyTrend = analyzeTrends(30);
        snapshot.addTrend("monthly", monthlyTrend.getDailyProposalTrend());
        
        // 성능 메트릭 업데이트
        PerformanceMetrics performance = generatePerformanceMetrics();
        snapshot.addMetric("performance", performance);
        
        // 인사이트 업데이트
        snapshot.addInsight("weekly", weeklyTrend.getInsights());
        snapshot.addInsight("monthly", monthlyTrend.getInsights());
        
        // 캐시 저장
        analyticsCache.put("latest", snapshot);
        
        log.info("Analytics cache updated successfully");
    }
    
    /**
     * 캐시된 분석 데이터 조회
     */
    public AnalyticsSnapshot getCachedAnalytics() {
        AnalyticsSnapshot cached = analyticsCache.get("latest");
        
        if (cached == null || cached.getTimestamp().isBefore(LocalDateTime.now().minusHours(1))) {
            // 캐시가 없거나 오래된 경우 새로 생성
            updateAnalytics();
            cached = analyticsCache.get("latest");
        }
        
        return cached;
    }
}