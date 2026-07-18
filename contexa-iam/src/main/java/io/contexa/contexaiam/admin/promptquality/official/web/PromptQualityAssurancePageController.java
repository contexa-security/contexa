package io.contexa.contexaiam.admin.promptquality.official.web;

import java.util.List;
import java.util.Objects;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.web.model.PromptQualityNavigationItem;

@Controller
@RequestMapping("/contexa/admin/prompt-quality")
public class PromptQualityAssurancePageController {

    private final PromptQualityMessageResolver messageResolver;

    public PromptQualityAssurancePageController(PromptQualityMessageResolver messageResolver) {
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    private static final String ROUTE_ROOT = "/contexa/admin/prompt-quality";

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
        return page(model, "resources", message("enterprise.pqa.pageTitle.resources"), "contexa/admin/prompt-quality/resources");
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
        return page(model, "resources", message("enterprise.pqa.pageTitle.resourceDetail"), "contexa/admin/prompt-quality/resource-detail");
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
        return page(model, "resources", message("enterprise.pqa.pageTitle.resourceEdit"), "contexa/admin/prompt-quality/resource-overlay-edit");
    }

    @GetMapping("/runtime-evidence")
    public String runtimeEvidence(Model model) {
        return page(model, "runtime-evidence", message("enterprise.pqa.pageTitle.runtimeEvidence"), "contexa/admin/prompt-quality/runtime-evidence");
    }

    @GetMapping("/verification")
    public String verification() {
        return "redirect:/contexa/admin/prompt-quality/runtime-evidence";
    }

    @GetMapping("/verification/summary")
    public String verificationSummary(Model model) {
        model.addAttribute("verificationStage", "summary");
        return page(model, "verification-summary", message("enterprise.pqa.pageTitle.verification"), "contexa/admin/prompt-quality/verification");
    }
    @GetMapping("/verification/readiness")
    public String verificationReadiness(Model model) {
        model.addAttribute("verificationStage", "readiness");
        return page(model, "verification-readiness", message("enterprise.pqa.pageTitle.verification"), "contexa/admin/prompt-quality/verification-readiness");
    }

    @GetMapping("/verification/run")
    public String verificationRun(Model model) {
        model.addAttribute("verificationStage", "run");
        return page(model, "verification-run", message("enterprise.pqa.pageTitle.verification"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/prompt-comparison")
    public String verificationPromptComparison(Model model) {
        model.addAttribute("verificationStage", "comparison");
        return page(model, "verification-comparison", message("enterprise.pqa.pageTitle.comparison"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/metrics")
    public String verificationMetrics(Model model) {
        model.addAttribute("verificationStage", "prompt-metrics");
        return page(model, "verification-metrics", message("enterprise.pqa.pageTitle.metrics"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/llm-metrics")
    public String verificationLlmMetrics(Model model) {
        model.addAttribute("verificationStage", "llm-metrics");
        return page(model, "verification-llm-metrics", message("enterprise.pqa.nav.llmMetrics"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/failures")
    public String verificationFailures(Model model) {
        model.addAttribute("verificationStage", "failures");
        return page(model, "verification-failures", message("enterprise.pqa.pageTitle.failures"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/evidence-package")
    public String verificationEvidencePackage(Model model) {
        model.addAttribute("verificationStage", "evidence-package");
        return page(model, "verification-evidence-package", message("enterprise.pqa.pageTitle.evidencePackage"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/reverify")
    public String verificationReverify(Model model) {
        model.addAttribute("verificationStage", "reverify");
        return page(model, "verification-reverify", message("enterprise.pqa.pageTitle.reverify"), "contexa/admin/prompt-quality/verification");
    }
    @GetMapping("/verification/handoff")
    public String verificationHandoff() {
        return "redirect:/contexa/admin/prompt-quality/verification/failures";
    }

    private String page(Model model, String activeKey, String pageTitle, String viewName) {
        model.addAttribute("pageTitle", pageTitle);
        model.addAttribute("verificationPageHeaderTitle", pageTitle);
        model.addAttribute("verificationPageHeaderSubtitle",
                message("enterprise.pqa.verification.pageSubtitle"));
        model.addAttribute("activeKey", activeKey);
        model.addAttribute("navigation", navigation(activeKey));
        model.addAttribute("promptQualityRouteRoot", ROUTE_ROOT);
        model.addAttribute("promptQualityUiMode", "core");
        return viewName;
    }

    private List<PromptQualityNavigationItem> navigation(String activeKey) {
        return List.of(
                item(message("enterprise.pqa.nav.resources"), "/contexa/admin/prompt-quality/resources",
                        message("enterprise.pqa.nav.resources.desc"),
                        "resources".equals(activeKey)),
                item(message("enterprise.pqa.nav.runtimeEvidence"), "/contexa/admin/prompt-quality/runtime-evidence",
                        message("enterprise.pqa.nav.runtimeEvidence.desc"),
                        "runtime-evidence".equals(activeKey) || (activeKey != null && activeKey.startsWith("verification")),
                        List.of(
                                item(message("enterprise.pqa.nav.readiness"), "/contexa/admin/prompt-quality/verification/readiness",
                                        message("enterprise.pqa.nav.readiness.desc"),
                                        "verification-readiness".equals(activeKey)),
                                item(message("enterprise.pqa.nav.run"), "/contexa/admin/prompt-quality/verification/run",
                                        message("enterprise.pqa.nav.run.desc"),
                                        "verification-run".equals(activeKey)),
                                item(message("enterprise.pqa.nav.summary"), "/contexa/admin/prompt-quality/verification/summary",
                                        message("enterprise.pqa.nav.summary.desc"),
                                        "verification-summary".equals(activeKey)),
                                item(message("enterprise.pqa.nav.promptMetrics"), "/contexa/admin/prompt-quality/verification/metrics",
                                        message("enterprise.pqa.nav.promptMetrics.desc"),
                                        "verification-metrics".equals(activeKey)),
                                item(message("enterprise.pqa.nav.llmMetrics"), "/contexa/admin/prompt-quality/verification/llm-metrics",
                                        message("enterprise.pqa.nav.llmMetrics.desc"),
                                        "verification-llm-metrics".equals(activeKey)),
                                item(message("enterprise.pqa.nav.failures"), "/contexa/admin/prompt-quality/verification/failures",
                                        message("enterprise.pqa.nav.failures.desc"),
                                        "verification-failures".equals(activeKey)),
                                item(message("enterprise.pqa.nav.evidencePackage"), "/contexa/admin/prompt-quality/verification/evidence-package",
                                        message("enterprise.pqa.nav.evidencePackage.desc"),
                                        "verification-evidence-package".equals(activeKey)),
                                item(message("enterprise.pqa.nav.reverify"), "/contexa/admin/prompt-quality/verification/reverify",
                                        message("enterprise.pqa.nav.reverify.desc"),
                                        "verification-reverify".equals(activeKey))
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

    private String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }
}


