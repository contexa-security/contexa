package io.contexa.contexaiam.admin.promptquality.official.web;

import java.text.MessageFormat;
import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;

@Controller
@RequestMapping("/contexa/admin/prompt-quality")
public class PromptQualityAssurancePageController {

    private final PromptQualityMessageResolver messageResolver;

    public PromptQualityAssurancePageController(PromptQualityMessageResolver messageResolver) {
        this.messageResolver = messageResolver;
    }

    private static final String ROUTE_ROOT = "/contexa/admin/prompt-quality";
    private static final String API_ROOT = "/contexa/admin/api/prompt-quality";

    @GetMapping({"", "/"})
    public String index() {
        return "redirect:/contexa/admin/prompt-quality/resources";
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        return "redirect:/contexa/admin/prompt-quality/resources";
    }

    @GetMapping("/resources")
    public String resources(Model model) {
        return page(model, "resources", message("enterprise.pqa.pageTitle.resources", "보호 대상 리소스"), "contexa/admin/prompt-quality/resources");
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
        return page(model, "resources", message("enterprise.pqa.pageTitle.resourceDetail", "보호 대상 리소스 상세"), "contexa/admin/prompt-quality/resource-detail");
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
        return page(model, "resources", message("enterprise.pqa.pageTitle.resourceEdit", "보호 대상 리소스 지정 정보 수정"), "contexa/admin/prompt-quality/resource-overlay-edit");
    }

    @GetMapping("/runtime-evidence")
    public String runtimeEvidence(Model model) {
        return page(model, "runtime-evidence", message("enterprise.pqa.pageTitle.runtimeEvidence", "요청 증거 자료"), "contexa/admin/prompt-quality/runtime-evidence");
    }

    @GetMapping("/verification")
    public String verification() {
        return "redirect:/contexa/admin/prompt-quality/verification/readiness";
    }

    @GetMapping("/verification/readiness")
    public String verificationReadiness(Model model) {
        model.addAttribute("verificationStage", "readiness");
        return page(model, "verification-readiness", message("enterprise.pqa.pageTitle.verification", "공식 검사"), "contexa/admin/prompt-quality/verification-readiness");
    }

    @GetMapping("/verification/run")
    public String verificationRun(Model model) {
        model.addAttribute("verificationStage", "run");
        return page(model, "verification-run", message("enterprise.pqa.pageTitle.verification", "공식 검사"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/prompt-comparison")
    public String verificationPromptComparison(Model model) {
        model.addAttribute("verificationStage", "comparison");
        return page(model, "verification-comparison", message("enterprise.pqa.pageTitle.comparison", "Prompt 비교"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/metrics")
    public String verificationMetrics(Model model) {
        model.addAttribute("verificationStage", "metrics");
        return page(model, "verification-metrics", message("enterprise.pqa.pageTitle.metrics", "12지표 상세"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/handoff")
    public String verificationHandoff() {
        return "redirect:/contexa/admin/prompt-quality/verification/metrics";
    }

    private String page(Model model, String activeKey, String pageTitle, String viewName) {
        model.addAttribute("pageTitle", pageTitle);
        model.addAttribute("activeKey", activeKey);
        model.addAttribute("navigation", navigation(activeKey));
        model.addAttribute("promptQualityRouteRoot", ROUTE_ROOT);
        model.addAttribute("promptQualityApiRoot", API_ROOT);
        model.addAttribute("promptQualityUiMode", "core");
        return viewName;
    }

    private List<PromptQualityNavigationItem> navigation(String activeKey) {
        return List.of(
                item(message("enterprise.pqa.nav.resources", "보호 대상 리소스"), "/contexa/admin/prompt-quality/resources",
                        message("enterprise.pqa.nav.resources.desc", "공식검사 대상 리소스를 확인합니다."),
                        "resources".equals(activeKey)),
                item(message("enterprise.pqa.nav.runtimeEvidence", "요청 증거 자료"), "/contexa/admin/prompt-quality/runtime-evidence",
                        message("enterprise.pqa.nav.runtimeEvidence.desc", "봉인된 실제 요청 증거를 확인합니다."),
                        "runtime-evidence".equals(activeKey)),
                item(message("enterprise.pqa.nav.verification", "공식 검사"), "/contexa/admin/prompt-quality/verification/readiness",
                        message("enterprise.pqa.nav.verification.desc", "선택한 요청 증거로 12지표 공식검사를 실행하고 결과를 확인합니다."),
                        activeKey != null && activeKey.startsWith("verification"),
                        List.of(
                                item(message("enterprise.pqa.nav.readiness", "증거 확인"), "/contexa/admin/prompt-quality/verification/readiness",
                                        message("enterprise.pqa.nav.readiness.desc", "검사할 요청 증거를 확인합니다."),
                                        "verification-readiness".equals(activeKey)),
                                item(message("enterprise.pqa.nav.run", "검사 실행"), "/contexa/admin/prompt-quality/verification/run",
                                        message("enterprise.pqa.nav.run.desc", "선택한 요청 증거로 공식검사를 실행합니다."),
                                        "verification-run".equals(activeKey)),
                                item(message("enterprise.pqa.nav.comparison", "Prompt 비교"), "/contexa/admin/prompt-quality/verification/prompt-comparison",
                                        message("enterprise.pqa.nav.comparison.desc", "저장된 프롬프트와 검사 근거를 비교합니다."),
                                        "verification-comparison".equals(activeKey)),
                                item(message("enterprise.pqa.nav.metrics", "12지표 상세"), "/contexa/admin/prompt-quality/verification/metrics",
                                        message("enterprise.pqa.nav.metrics.desc", "12개 지표별 결과와 상세 근거를 확인합니다."),
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
    private String message(String key, String fallback, Object... args) {
        if (messageResolver == null) {
            return args == null || args.length == 0 ? fallback : MessageFormat.format(fallback, args);
        }
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            return args == null || args.length == 0 ? fallback : MessageFormat.format(fallback, args);
        }
        return resolved;
    }
}
