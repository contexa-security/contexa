package io.contexa.contexaiam.admin.web.monitoring.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * 통합 메트릭 대시보드 컨트롤러
 *
 * 6개의 Grafana 임베딩 대시보드 제공:
 * 1. 임원진 통합 대시보드 (Executive Overview)
 * 2. 제로트러스트 모니터링 (ZeroTrust Real-time)
 * 3. Evolution & Learning 메트릭
 * 4. VectorStore 메트릭
 * 5. Tools 모니터링 (MCP + SOAR)
 * 6. System Overview (시스템 건강도 + JVM)
 *
 * @author contexa
 * @since 3.0.0
 */
@Slf4j
@RequestMapping("/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class MetricsDashboardController {

    /**
     * 임원진 통합 보안 대시보드
     *
     * Grafana 대시보드: executive-overview
     * 주요 메트릭: 전체 보안 건강도, 도메인별 건강도 (ZeroTrust 30%, Evolution 30%, Vector 20%, HCAD 15%)
     */
    @GetMapping("/executive-overview")
    public String executiveOverview(Model model) {
        model.addAttribute("pageTitle", "임원진 통합 보안 대시보드");
        model.addAttribute("activePage", "executive-overview");
        return "admin/executive-overview";
    }

    /**
     * 제로트러스트 실시간 모니터링
     *
     * Grafana 대시보드: zerotrust-monitoring
     * 주요 메트릭: HCAD 피드백 루프, Hot/Cold Path 라우팅, Plane 에스컬레이션, 사용자 신뢰도
     */
    @GetMapping("/zerotrust-monitoring")
    public String zerotrustMonitoring(Model model) {
        model.addAttribute("pageTitle", "제로트러스트 실시간 모니터링");
        model.addAttribute("activePage", "zerotrust-monitoring");
        return "admin/zerotrust-monitoring";
    }

    /**
     * Evolution & Learning 상세 메트릭
     *
     * Grafana 대시보드: evolution-learning
     * 주요 메트릭: 정책 진화 제안, AI 학습 성능, HCAD 피드백 루프, 학습 진행도
     */
    @GetMapping("/evolution-learning")
    public String evolutionLearning(Model model) {
        model.addAttribute("pageTitle", "Evolution & Learning 상세 메트릭");
        model.addAttribute("activePage", "evolution-learning");
        return "admin/evolution-learning";
    }

    /**
     * VectorStore 메트릭 모니터링
     *
     * Grafana 대시보드: vectorstore-metrics
     * 주요 메트릭: VectorStore 작업 통계, 문서 타입별 사용량, 성능 메트릭, 에러율
     */
    @GetMapping("/vectorstore-metrics")
    public String vectorstoreMetrics(Model model) {
        model.addAttribute("pageTitle", "VectorStore 모니터링");
        model.addAttribute("activePage", "vectorstore-metrics");
        return "admin/vectorstore-metrics";
    }

    /**
     * Tools 모니터링 (MCP + SOAR)
     *
     * Grafana 대시보드: tools-monitoring
     * 주요 메트릭: MCP 도구 실행 통계, 캐시 히트율, SOAR 승인율, 필터링 이유
     */
    @GetMapping("/tools-monitoring")
    public String toolsMonitoring(Model model) {
        model.addAttribute("pageTitle", "Tools 모니터링 (MCP + SOAR)");
        model.addAttribute("activePage", "tools-monitoring");
        return "admin/tools-monitoring";
    }

    /**
     * System Overview (시스템 건강도 + JVM)
     *
     * Grafana 대시보드: system-overview
     * 주요 메트릭: 시스템 건강도, JVM 메모리, HTTP 처리량, 응답시간, 스레드, GC
     */
    @GetMapping("/system-overview")
    public String systemOverview(Model model) {
        model.addAttribute("pageTitle", "시스템 개요");
        model.addAttribute("activePage", "system-overview");
        return "admin/system-overview";
    }
}
