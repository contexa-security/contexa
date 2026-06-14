package io.contexa.contexaiam.admin.promptquality.official.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
@RequestMapping("/contexa/admin/prompt-quality")
public class PromptQualityAssurancePageController {

    @GetMapping({"", "/"})
    public String index() {
        return "redirect:/contexa/admin/prompt-quality/dashboard";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        return page(model, "dashboard", "프롬프트 품질 보증 엔진", "contexa/admin/prompt-quality/dashboard");
    }

    @GetMapping("/resources")
    public String resources(Model model) {
        return page(model, "resources", "보호 후보", "contexa/admin/prompt-quality/resources");
    }

    @GetMapping("/resources/{resourceId}")
    public String resourceDetail(
            @PathVariable String resourceId,
            @RequestParam(required = false) String resourceUrl,
            @RequestParam(defaultValue = "GET") String httpMethod,
            Model model) {
        return resourceDetailByQuery(resourceId, resourceUrl, httpMethod, model);
    }

    @GetMapping("/resources/detail")
    public String resourceDetailByQuery(
            @RequestParam String resourceId,
            @RequestParam(required = false) String resourceUrl,
            @RequestParam(defaultValue = "GET") String httpMethod,
            Model model) {
        model.addAttribute("resourceId", resourceId);
        model.addAttribute("resourceUrl", resourceUrl);
        model.addAttribute("httpMethod", httpMethod);
        return page(model, "resources", "보호 후보 상세", "contexa/admin/prompt-quality/resource-detail");
    }

    @GetMapping("/resources/{resourceId}/overlay/edit")
    public String resourceOverlayEdit(
            @PathVariable String resourceId,
            @RequestParam(required = false) String resourceUrl,
            @RequestParam(defaultValue = "GET") String httpMethod,
            @RequestParam(defaultValue = "default") String tenantId,
            Model model) {
        model.addAttribute("resourceId", resourceId);
        model.addAttribute("resourceUrl", resourceUrl);
        model.addAttribute("httpMethod", httpMethod);
        model.addAttribute("tenantId", tenantId);
        return page(model, "resources", "보호 후보 등록 정보 수정", "contexa/admin/prompt-quality/resource-overlay-edit");
    }

    @GetMapping("/runtime-evidence")
    public String runtimeEvidence(Model model) {
        return page(model, "runtime-evidence", "실제 요청 증거", "contexa/admin/prompt-quality/runtime-evidence");
    }

    @GetMapping("/verification")
    public String verification() {
        return "redirect:/contexa/admin/prompt-quality/verification/readiness";
    }

    @GetMapping("/verification/readiness")
    public String verificationReadiness(Model model) {
        model.addAttribute("verificationStage", "readiness");
        return page(model, "verification-readiness", "공식 품질 검사", "contexa/admin/prompt-quality/verification-readiness");
    }

    @GetMapping("/verification/run")
    public String verificationRun(Model model) {
        model.addAttribute("verificationStage", "run");
        return page(model, "verification-run", "공식 품질 검사", "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/prompt-comparison")
    public String verificationPromptComparison(Model model) {
        model.addAttribute("verificationStage", "comparison");
        return page(model, "verification-comparison", "프롬프트 비교", "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/metrics")
    public String verificationMetrics(Model model) {
        model.addAttribute("verificationStage", "metrics");
        return page(model, "verification-metrics", "12지표 상세", "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/handoff")
    public String verificationHandoff() {
        return "redirect:/contexa/admin/prompt-quality/verification/metrics";
    }

    private String page(Model model, String activeKey, String pageTitle, String viewName) {
        model.addAttribute("pageTitle", pageTitle);
        model.addAttribute("activeKey", activeKey);
        model.addAttribute("navigation", navigation(activeKey));
        return viewName;
    }

    private List<PromptQualityNavigationItem> navigation(String activeKey) {
        return List.of(
                item("품질 공정 홈", "/contexa/admin/prompt-quality/dashboard",
                        "프롬프트 품질 공정의 현재 상태를 확인합니다.",
                        "dashboard".equals(activeKey)),
                item("보호 후보", "/contexa/admin/prompt-quality/resources",
                        "공식검사 후보 리소스를 확인합니다.",
                        "resources".equals(activeKey)),
                item("실제 요청 증거", "/contexa/admin/prompt-quality/runtime-evidence",
                        "봉인된 실제 요청 증거를 확인합니다.",
                        "runtime-evidence".equals(activeKey)),
                item("공식 품질 검사", "/contexa/admin/prompt-quality/verification/readiness",
                        "봉인 증거로 공식검사를 실행하고 결과를 확인합니다.",
                        activeKey != null && activeKey.startsWith("verification"),
                        List.of(
                                item("증거 확인", "/contexa/admin/prompt-quality/verification/readiness",
                                        "검사할 요청 증거를 확인합니다.",
                                        "verification-readiness".equals(activeKey)),
                                item("검사 실행", "/contexa/admin/prompt-quality/verification/run",
                                        "선택한 요청 증거로 공식검사를 실행합니다.",
                                        "verification-run".equals(activeKey)),
                                item("프롬프트 비교", "/contexa/admin/prompt-quality/verification/prompt-comparison",
                                        "저장된 프롬프트와 검사 근거를 비교합니다.",
                                        "verification-comparison".equals(activeKey)),
                                item("12지표 상세", "/contexa/admin/prompt-quality/verification/metrics",
                                        "12개 지표별 결과와 상세 근거를 확인합니다.",
                                        "verification-metrics".equals(activeKey))
                        ))
        );
    }

    private static PromptQualityNavigationItem item(
            String label,
            String href,
            String responsibility,
            boolean active) {
        return item(label, href, responsibility, active, List.of());
    }

    private static PromptQualityNavigationItem item(
            String label,
            String href,
            String responsibility,
            boolean active,
            List<PromptQualityNavigationItem> children) {
        return new PromptQualityNavigationItem(label, href, responsibility, active, children);
    }

    public record PromptQualityNavigationItem(
            String label,
            String href,
            String responsibility,
            boolean active,
            List<PromptQualityNavigationItem> children) {
    }
}
