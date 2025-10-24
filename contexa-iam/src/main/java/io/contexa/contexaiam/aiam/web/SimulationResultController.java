package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.analyzer.SimulationResultAnalyzer;
import io.contexa.contexacore.simulation.analyzer.SimulationResultAnalyzer.AnalysisReport;
import io.contexa.contexacore.repository.AttackResultRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 시뮬레이션 결과 컨트롤러
 *
 * 이중 모드 시뮬레이션 결과를 조회하고 분석하는 엔드포인트를 제공합니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping("/admin/simulation")
public class SimulationResultController {

    private final SimulationResultAnalyzer resultAnalyzer;
    private final AttackResultRepository attackResultRepository;

    /**
     * 시뮬레이션 결과 페이지
     */
    @GetMapping("/results")
    public String resultsPage() {
        return "admin/dual-mode-simulation-results";
    }

    /**
     * 캠페인 결과 분석 API
     */
    @GetMapping("/api/results/{campaignId}")
    @ResponseBody
    public ResponseEntity<AnalysisReport> getAnalysisReport(@PathVariable String campaignId) {
        log.info("Fetching analysis report for campaign: {}", campaignId);

        try {
            // 캠페인의 공격 결과 조회
            List<AttackResult> allResults = attackResultRepository.findByCampaignId(campaignId);

            if (allResults.isEmpty()) {
                log.warn("No results found for campaign: {}", campaignId);
                return ResponseEntity.notFound().build();
            }

            // 모드별로 분리
            List<AttackResult> unprotectedResults = allResults.stream()
                .filter(r -> r.getDetails().containsKey("simulationMode") &&
                           "UNPROTECTED".equals(r.getDetails().get("simulationMode")))
                .collect(Collectors.toList());

            List<AttackResult> protectedResults = allResults.stream()
                .filter(r -> r.getDetails().containsKey("simulationMode") &&
                           "PROTECTED".equals(r.getDetails().get("simulationMode")))
                .collect(Collectors.toList());

            // 결과 분석
            AnalysisReport report = resultAnalyzer.analyzeCampaign(
                campaignId, unprotectedResults, protectedResults);

            return ResponseEntity.ok(report);

        } catch (Exception e) {
            log.error("Error analyzing campaign results", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 최근 캠페인 목록 조회
     */
    @GetMapping("/api/campaigns/recent")
    @ResponseBody
    public ResponseEntity<List<CampaignSummary>> getRecentCampaigns() {
        try {
            // 최근 10개 캠페인 조회
            List<String> campaigns = attackResultRepository.findDistinctCampaignIds(10);

            List<CampaignSummary> summaries = campaigns.stream()
                .map(this::createCampaignSummary)
                .collect(Collectors.toList());

            return ResponseEntity.ok(summaries);

        } catch (Exception e) {
            log.error("Error fetching recent campaigns", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 결과 CSV 내보내기
     */
    @GetMapping("/api/results/{campaignId}/export")
    public ResponseEntity<byte[]> exportResults(@PathVariable String campaignId) {
        log.info("Exporting results for campaign: {}", campaignId);

        try {
            // 분석 보고서 생성
            List<AttackResult> allResults = attackResultRepository.findByCampaignId(campaignId);

            List<AttackResult> unprotectedResults = allResults.stream()
                .filter(r -> "UNPROTECTED".equals(r.getDetails().get("simulationMode")))
                .collect(Collectors.toList());

            List<AttackResult> protectedResults = allResults.stream()
                .filter(r -> "PROTECTED".equals(r.getDetails().get("simulationMode")))
                .collect(Collectors.toList());

            AnalysisReport report = resultAnalyzer.analyzeCampaign(
                campaignId, unprotectedResults, protectedResults);

            // CSV 생성
            String csv = generateCsvReport(report);
            byte[] csvBytes = csv.getBytes();

            // 파일명 생성
            String filename = String.format("simulation_results_%s_%s.csv",
                campaignId,
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")));

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("text/csv"));
            headers.setContentDispositionFormData("attachment", filename);

            return ResponseEntity.ok()
                .headers(headers)
                .body(csvBytes);

        } catch (Exception e) {
            log.error("Error exporting results", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 캠페인 요약 정보 생성
     */
    private CampaignSummary createCampaignSummary(String campaignId) {
        CampaignSummary summary = new CampaignSummary();
        summary.setCampaignId(campaignId);

        List<AttackResult> results = attackResultRepository.findByCampaignId(campaignId);

        summary.setTotalAttacks(results.size());
        summary.setSuccessfulAttacks((int) results.stream()
            .filter(AttackResult::isAttackSuccessful)
            .count());

        summary.setDataBreaches((int) results.stream()
            .filter(AttackResult::isDataBreached)
            .count());

        // 첫 번째와 마지막 실행 시간
        results.stream()
            .map(AttackResult::getExecutionTime)
            .min(LocalDateTime::compareTo)
            .ifPresent(summary::setStartTime);

        results.stream()
            .map(AttackResult::getExecutionTime)
            .max(LocalDateTime::compareTo)
            .ifPresent(summary::setEndTime);

        // 평균 위험도
        double avgRisk = results.stream()
            .mapToDouble(AttackResult::getRiskScore)
            .average()
            .orElse(0);
        summary.setAverageRiskScore(avgRisk);

        return summary;
    }

    /**
     * CSV 보고서 생성
     */
    private String generateCsvReport(AnalysisReport report) {
        StringBuilder csv = new StringBuilder();

        // 헤더
        csv.append("AI3Security 시뮬레이션 결과 보고서\n");
        csv.append("캠페인 ID,").append(report.getCampaignId()).append("\n");
        csv.append("분석 시간,").append(report.getAnalysisTime()).append("\n");
        csv.append("\n");

        // 전체 효과성
        csv.append("보안 효과성\n");
        csv.append("지표,값\n");
        csv.append("전체 보안 점수,").append(report.getEffectiveness().getOverallSecurityScore()).append("\n");
        csv.append("보안 등급,").append(report.getEffectiveness().getGrade()).append("\n");
        csv.append("공격 차단률,").append(report.getEffectiveness().getAttackPreventionRate()).append("%\n");
        csv.append("데이터 보호율,").append(report.getEffectiveness().getDataProtectionRate()).append("%\n");
        csv.append("탐지 효율성,").append(report.getEffectiveness().getDetectionEfficiency()).append("%\n");
        csv.append("\n");

        // 무방비 모드
        csv.append("무방비 모드 결과\n");
        csv.append("공격 성공,").append(report.getUnprotectedAnalysis().getSuccessCount()).append("\n");
        csv.append("성공률,").append(report.getUnprotectedAnalysis().getSuccessRate()).append("%\n");
        csv.append("데이터 유출,").append(report.getUnprotectedAnalysis().getDataBreachCount()).append("\n");
        csv.append("유출 레코드,").append(report.getUnprotectedAnalysis().getTotalBreachedRecords()).append("\n");
        csv.append("\n");

        // 방어 모드
        csv.append("방어 모드 결과\n");
        csv.append("공격 차단,").append(report.getProtectedAnalysis().getBlockedCount()).append("\n");
        csv.append("차단률,").append(report.getProtectedAnalysis().getBlockRate()).append("%\n");
        csv.append("탐지 건수,").append(report.getProtectedAnalysis().getDetectedCount()).append("\n");
        csv.append("탐지율,").append(report.getProtectedAnalysis().getDetectionRate()).append("%\n");
        csv.append("\n");

        // 공격 유형별 분석
        csv.append("공격 유형별 분석\n");
        csv.append("공격 유형,무방비 성공률,방어 차단률,개선도\n");
        report.getAttackTypeAnalysis().forEach((type, analysis) -> {
            csv.append(type).append(",")
               .append(analysis.getUnprotectedSuccessRate()).append("%,")
               .append(analysis.getProtectedBlockRate()).append("%,")
               .append(analysis.getImprovement()).append("%\n");
        });
        csv.append("\n");

        // 권장사항
        csv.append("보안 권장사항\n");
        report.getRecommendations().forEach(rec -> {
            csv.append("- ").append(rec).append("\n");
        });

        return csv.toString();
    }

    /**
     * 캠페인 요약 정보
     */
    @lombok.Data
    public static class CampaignSummary {
        private String campaignId;
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        private int totalAttacks;
        private int successfulAttacks;
        private int dataBreaches;
        private double averageRiskScore;
    }
}