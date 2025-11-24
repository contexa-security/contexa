package io.contexa.contexaiam.aiam.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * 무방비 vs 방어 모드 시뮬레이션 뷰 컨트롤러
 *
 * HTML 페이지를 서빙하는 컨트롤러입니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@RequestMapping("/admin")
public class DualModeSimulationViewController {

    /**
     * 무방비 vs 방어 모드 시뮬레이션 페이지
     *
     * @return 템플릿 이름
     */
    @GetMapping("/dual-mode-simulation")
    public String dualModeSimulation() {
        return "admin/dual-mode-simulation";
    }

    /**
     * 향상된 듀얼 모드 시뮬레이션 페이지
     *
     * @return 템플릿 이름
     */
    @GetMapping("/dual-mode-simulation-enhanced")
    public String dualModeSimulationEnhanced() {
        return "admin/dual-mode-simulation-enhanced";
    }
}