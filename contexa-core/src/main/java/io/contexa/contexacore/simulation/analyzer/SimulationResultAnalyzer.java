package io.contexa.contexacore.simulation.analyzer;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.tracker.DataBreachTracker;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 시뮬레이션 결과 분석기
 *
 * 무방비 모드와 방어 모드의 시뮬레이션 결과를 비교 분석하여
 * 자율보안체제의 효과성을 평가합니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SimulationResultAnalyzer {

    private final DataBreachTracker dataBreachTracker;

    /**
     * 캠페인 결과 분석
     *
     * @param campaignId 캠페인 ID
     * @param unprotectedResults 무방비 모드 결과
     * @param protectedResults 방어 모드 결과
     * @return 분석 결과
     */
    public AnalysisReport analyzeCampaign(String campaignId,
                                         List<AttackResult> unprotectedResults,
                                         List<AttackResult> protectedResults) {

        log.info("Analyzing campaign: {} - Unprotected: {}, Protected: {}",
                campaignId, unprotectedResults.size(), protectedResults.size());

        AnalysisReport report = new AnalysisReport();
        report.setCampaignId(campaignId);
        report.setAnalysisTime(LocalDateTime.now());

        // 기본 통계
        report.setTotalAttacks(Math.max(unprotectedResults.size(), protectedResults.size()));

        // 무방비 모드 분석
        UnprotectedModeAnalysis unprotectedAnalysis = analyzeUnprotectedMode(unprotectedResults);
        report.setUnprotectedAnalysis(unprotectedAnalysis);

        // 방어 모드 분석
        ProtectedModeAnalysis protectedAnalysis = analyzeProtectedMode(protectedResults);
        report.setProtectedAnalysis(protectedAnalysis);

        // 보안 효과성 계산
        SecurityEffectiveness effectiveness = calculateEffectiveness(
            unprotectedAnalysis, protectedAnalysis);
        report.setEffectiveness(effectiveness);

        // 공격 유형별 분석
        Map<String, AttackTypeAnalysis> byType = analyzeByAttackType(
            unprotectedResults, protectedResults);
        report.setAttackTypeAnalysis(byType);

        // 데이터 유출 분석
        DataBreachAnalysis breachAnalysis = analyzeDataBreaches(campaignId);
        report.setDataBreachAnalysis(breachAnalysis);

        // 위험 평가
        report.setRiskAssessment(assessRisk(report));

        // 권장사항 생성
        report.setRecommendations(generateRecommendations(report));

        return report;
    }

    /**
     * 무방비 모드 결과 분석
     */
    private UnprotectedModeAnalysis analyzeUnprotectedMode(List<AttackResult> results) {
        UnprotectedModeAnalysis analysis = new UnprotectedModeAnalysis();

        if (results.isEmpty()) {
            return analysis;
        }

        // 전체 개수 설정
        analysis.setTotalCount(results.size());

        // 성공률 계산
        long successCount = results.stream()
            .filter(AttackResult::isAttackSuccessful)
            .count();
        analysis.setSuccessCount((int) successCount);
        analysis.setSuccessRate(successCount * 100.0 / results.size());

        // 데이터 유출 통계
        long breachCount = results.stream()
            .filter(AttackResult::isDataBreached)
            .count();
        analysis.setDataBreachCount((int) breachCount);

        long totalBreachedRecords = results.stream()
            .mapToLong(AttackResult::getBreachedRecordCount)
            .sum();
        analysis.setTotalBreachedRecords((int) totalBreachedRecords);

        // 평균 공격 시간
        double avgDuration = results.stream()
            .mapToLong(AttackResult::getDuration)
            .average()
            .orElse(0);
        analysis.setAverageDuration(avgDuration);

        // 위험도별 분포
        Map<String, Long> riskDistribution = results.stream()
            .collect(Collectors.groupingBy(
                r -> r.getRiskLevel() != null ? r.getRiskLevel() : "UNKNOWN",
                Collectors.counting()
            ));
        analysis.setRiskDistribution(riskDistribution);

        return analysis;
    }

    /**
     * 방어 모드 결과 분석
     */
    private ProtectedModeAnalysis analyzeProtectedMode(List<AttackResult> results) {
        ProtectedModeAnalysis analysis = new ProtectedModeAnalysis();

        if (results.isEmpty()) {
            return analysis;
        }

        // 전체 개수 설정
        analysis.setTotalCount(results.size());

        // 차단률 계산
        long blockedCount = results.stream()
            .filter(r -> !r.isAttackSuccessful())
            .count();
        analysis.setBlockedCount((int) blockedCount);
        analysis.setBlockRate(blockedCount * 100.0 / results.size());

        // 탐지 통계
        long detectedCount = results.stream()
            .filter(AttackResult::isDetected)
            .count();
        analysis.setDetectedCount((int) detectedCount);
        analysis.setDetectionRate(detectedCount * 100.0 / results.size());

        // 평균 탐지 시간
        double avgDetectionTime = results.stream()
            .filter(AttackResult::isDetected)
            .mapToLong(AttackResult::getDetectionTimeMs)
            .average()
            .orElse(0);
        analysis.setAverageDetectionTimeMs(avgDetectionTime);

        // 데이터 유출 카운트
        long dataBreachCount = results.stream()
            .filter(AttackResult::isDataBreached)
            .count();
        analysis.setDataBreachCount((int) dataBreachCount);

        // 보안 이벤트 생성 수
        analysis.setSecurityEventsGenerated(results.size());

        // 자동 대응 통계
        long autoResponseCount = results.stream()
            .filter(r -> r.getDetails().containsKey("autoResponse"))
            .count();
        analysis.setAutoResponseCount((int) autoResponseCount);

        return analysis;
    }

    /**
     * 보안 효과성 계산
     */
    private SecurityEffectiveness calculateEffectiveness(
            UnprotectedModeAnalysis unprotected,
            ProtectedModeAnalysis protected_) {

        SecurityEffectiveness effectiveness = new SecurityEffectiveness();

        // 공격 방어율 (무방비 대비 얼마나 차단했는지)
        double preventionRate = 0;
        if (unprotected.getSuccessCount() > 0) {
            preventionRate = protected_.getBlockedCount() * 100.0 / unprotected.getSuccessCount();
        }
        effectiveness.setAttackPreventionRate(Math.min(preventionRate, 100));

        // 데이터 보호율
        double dataProtectionRate = 0;
        if (unprotected.getTotalBreachedRecords() > 0) {
            int protectedBreaches = unprotected.getTotalBreachedRecords() -
                                   protected_.getBlockedCount();
            dataProtectionRate = (1 - (double)Math.max(0, protectedBreaches) /
                                 unprotected.getTotalBreachedRecords()) * 100;
        }
        effectiveness.setDataProtectionRate(Math.min(dataProtectionRate, 100));

        // 탐지 효율성
        effectiveness.setDetectionEfficiency(protected_.getDetectionRate());

        // 응답 시간 효율성 (빠를수록 좋음)
        double responseEfficiency = 100;
        if (protected_.getAverageDetectionTimeMs() > 0) {
            // 1초 이내 탐지를 100%로 기준
            responseEfficiency = Math.min(100, 1000 / protected_.getAverageDetectionTimeMs() * 100);
        }
        effectiveness.setResponseTimeEfficiency(responseEfficiency);

        // 전체 보안 점수 (가중 평균)
        double overallScore =
            preventionRate * 0.4 +           // 공격 차단이 가장 중요
            dataProtectionRate * 0.3 +       // 데이터 보호
            protected_.getDetectionRate() * 0.2 +  // 탐지율
            responseEfficiency * 0.1;        // 응답 속도
        effectiveness.setOverallSecurityScore(overallScore);

        // 등급 결정
        effectiveness.setGrade(determineGrade(overallScore));

        return effectiveness;
    }

    /**
     * 공격 유형별 분석
     */
    private Map<String, AttackTypeAnalysis> analyzeByAttackType(
            List<AttackResult> unprotectedResults,
            List<AttackResult> protectedResults) {

        Map<String, AttackTypeAnalysis> analysis = new HashMap<>();

        // 모든 공격 유형 수집
        Set<AttackResult.AttackType> allTypes = new HashSet<>();
        unprotectedResults.forEach(r -> {
            if (r.getAttackType() != null) allTypes.add(r.getAttackType());
        });
        protectedResults.forEach(r -> {
            if (r.getAttackType() != null) allTypes.add(r.getAttackType());
        });

        // 각 유형별 분석
        for (AttackResult.AttackType type : allTypes) {
            AttackTypeAnalysis typeAnalysis = new AttackTypeAnalysis();
            typeAnalysis.setAttackType(type.name());

            // 무방비 모드 성공률
            long unprotectedSuccess = unprotectedResults.stream()
                .filter(r -> r.getAttackType() == type && r.isAttackSuccessful())
                .count();
            long unprotectedTotal = unprotectedResults.stream()
                .filter(r -> r.getAttackType() == type)
                .count();

            if (unprotectedTotal > 0) {
                typeAnalysis.setUnprotectedSuccessRate(
                    unprotectedSuccess * 100.0 / unprotectedTotal);
            }

            // 방어 모드 차단률
            long protectedBlocked = protectedResults.stream()
                .filter(r -> r.getAttackType() == type && !r.isAttackSuccessful())
                .count();
            long protectedTotal = protectedResults.stream()
                .filter(r -> r.getAttackType() == type)
                .count();

            if (protectedTotal > 0) {
                typeAnalysis.setProtectedBlockRate(
                    protectedBlocked * 100.0 / protectedTotal);
            }

            // 개선도
            typeAnalysis.setImprovement(
                typeAnalysis.getProtectedBlockRate() -
                (100 - typeAnalysis.getUnprotectedSuccessRate()));

            analysis.put(type.name(), typeAnalysis);
        }

        return analysis;
    }

    /**
     * 데이터 유출 분석
     */
    private DataBreachAnalysis analyzeDataBreaches(String campaignId) {
        DataBreachAnalysis analysis = new DataBreachAnalysis();

        // DataBreachTracker에서 실제 유출 정보 가져오기
        Map<String, Integer> breachesByMode = dataBreachTracker.getBreachCountByMode(campaignId);
        analysis.setUnprotectedBreaches(breachesByMode.getOrDefault("UNPROTECTED", 0));
        analysis.setProtectedBreaches(breachesByMode.getOrDefault("PROTECTED", 0));

        // 민감도별 유출 분석
        Map<String, Integer> bySensitivity = dataBreachTracker.getBreachCountBySensitivity(campaignId);
        analysis.setSensitivityDistribution(bySensitivity);

        // 방어 효과
        int prevented = analysis.getUnprotectedBreaches() - analysis.getProtectedBreaches();
        analysis.setBreachesPrevented(Math.max(0, prevented));

        if (analysis.getUnprotectedBreaches() > 0) {
            double preventionRate = prevented * 100.0 / analysis.getUnprotectedBreaches();
            analysis.setPreventionRate(Math.min(100, preventionRate));
        }

        return analysis;
    }

    /**
     * 위험 평가
     */
    private String assessRisk(AnalysisReport report) {
        double score = report.getEffectiveness().getOverallSecurityScore();

        if (score >= 90) return "LOW - Excellent security posture";
        if (score >= 70) return "MEDIUM - Good security with room for improvement";
        if (score >= 50) return "HIGH - Significant security gaps identified";
        return "CRITICAL - Severe security vulnerabilities detected";
    }

    /**
     * 권장사항 생성
     */
    private List<String> generateRecommendations(AnalysisReport report) {
        List<String> recommendations = new ArrayList<>();
        SecurityEffectiveness eff = report.getEffectiveness();

        // 공격 차단률이 낮은 경우
        if (eff.getAttackPreventionRate() < 70) {
            recommendations.add("공격 탐지 규칙을 강화하고 AI 모델을 재학습시키십시오.");
        }

        // 데이터 보호율이 낮은 경우
        if (eff.getDataProtectionRate() < 80) {
            recommendations.add("민감 데이터에 대한 추가 접근 제어를 구현하십시오.");
        }

        // 탐지율이 낮은 경우
        if (eff.getDetectionEfficiency() < 60) {
            recommendations.add("이상 행위 탐지 임계값을 조정하고 모니터링을 강화하십시오.");
        }

        // 응답 시간이 느린 경우
        if (eff.getResponseTimeEfficiency() < 50) {
            recommendations.add("자동 대응 시스템의 성능을 최적화하십시오.");
        }

        // 특정 공격 유형에 취약한 경우
        for (AttackTypeAnalysis typeAnalysis : report.getAttackTypeAnalysis().values()) {
            if (typeAnalysis.getProtectedBlockRate() < 50) {
                recommendations.add(String.format(
                    "%s 공격에 대한 방어 전략을 개선하십시오 (현재 차단률: %.1f%%)",
                    typeAnalysis.getAttackType(), typeAnalysis.getProtectedBlockRate()));
            }
        }

        // 전체 점수가 우수한 경우에도 지속적 개선 권장
        if (eff.getOverallSecurityScore() >= 90) {
            recommendations.add("현재 우수한 보안 수준을 유지하되, 새로운 위협에 대비하여 지속적으로 모니터링하십시오.");
        }

        return recommendations;
    }

    /**
     * 보안 등급 결정
     */
    private String determineGrade(double score) {
        if (score >= 90) return "A";
        if (score >= 80) return "B";
        if (score >= 70) return "C";
        if (score >= 60) return "D";
        return "F";
    }

    // 분석 결과 클래스들

    @Data
    public static class AnalysisReport {
        private String campaignId;
        private LocalDateTime analysisTime;
        private int totalAttacks;
        private UnprotectedModeAnalysis unprotectedAnalysis;
        private ProtectedModeAnalysis protectedAnalysis;
        private SecurityEffectiveness effectiveness;
        private Map<String, AttackTypeAnalysis> attackTypeAnalysis;
        private DataBreachAnalysis dataBreachAnalysis;
        private String riskAssessment;
        private List<String> recommendations;
    }

    @Data
    public static class UnprotectedModeAnalysis {
        private int totalCount;  // Added
        private int successCount;
        private double successRate;
        private int dataBreachCount;
        private int totalBreachedRecords;
        private double averageDuration;
        private Map<String, Long> riskDistribution;
    }

    @Data
    public static class ProtectedModeAnalysis {
        private int totalCount;  // Added
        private int blockedCount;
        private double blockRate;
        private int detectedCount;
        private double detectionRate;
        private int dataBreachCount;  // Added
        private double averageDetectionTimeMs;
        private int securityEventsGenerated;
        private int autoResponseCount;
    }

    @Data
    public static class SecurityEffectiveness {
        private double attackPreventionRate;
        private double dataProtectionRate;
        private double detectionEfficiency;
        private double responseTimeEfficiency;
        private double overallSecurityScore;
        private String grade;
    }

    @Data
    public static class AttackTypeAnalysis {
        private String attackType;
        private double unprotectedSuccessRate;
        private double protectedBlockRate;
        private double improvement;
    }

    @Data
    public static class DataBreachAnalysis {
        private int unprotectedBreaches;
        private int protectedBreaches;
        private int breachesPrevented;
        private double preventionRate;
        private Map<String, Integer> sensitivityDistribution;
    }
}