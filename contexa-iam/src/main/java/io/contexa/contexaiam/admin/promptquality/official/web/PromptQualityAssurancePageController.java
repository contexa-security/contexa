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
        return page(model, "resources", message("enterprise.pqa.pageTitle.resources", "Protected resources"), "contexa/admin/prompt-quality/resources");
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
        return page(model, "resources", message("enterprise.pqa.pageTitle.resourceDetail", "Protected resource detail"), "contexa/admin/prompt-quality/resource-detail");
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
        return page(model, "resources", message("enterprise.pqa.pageTitle.resourceEdit", "Protected resource edit"), "contexa/admin/prompt-quality/resource-overlay-edit");
    }

    @GetMapping("/runtime-evidence")
    public String runtimeEvidence(Model model) {
        return page(model, "runtime-evidence", message("enterprise.pqa.pageTitle.runtimeEvidence", "Official inspection"), "contexa/admin/prompt-quality/runtime-evidence");
    }

    @GetMapping("/verification")
    public String verification() {
        return "redirect:/contexa/admin/prompt-quality/runtime-evidence";
    }

    @GetMapping("/verification/summary")
    public String verificationSummary(Model model) {
        model.addAttribute("verificationStage", "summary");
        return page(model, "verification-summary", message("enterprise.pqa.pageTitle.verification", "Official inspection"), "contexa/admin/prompt-quality/verification");
    }
    @GetMapping("/verification/readiness")
    public String verificationReadiness(Model model) {
        model.addAttribute("verificationStage", "readiness");
        return page(model, "verification-readiness", message("enterprise.pqa.pageTitle.verification", "Official inspection"), "contexa/admin/prompt-quality/verification-readiness");
    }

    @GetMapping("/verification/run")
    public String verificationRun(Model model) {
        model.addAttribute("verificationStage", "run");
        return page(model, "verification-run", message("enterprise.pqa.pageTitle.verification", "Official inspection"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/prompt-comparison")
    public String verificationPromptComparison(Model model) {
        model.addAttribute("verificationStage", "comparison");
        return page(model, "verification-comparison", message("enterprise.pqa.pageTitle.comparison", "Prompt comparison"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/metrics")
    public String verificationMetrics(Model model) {
        model.addAttribute("verificationStage", "prompt-metrics");
        return page(model, "verification-metrics", message("enterprise.pqa.pageTitle.metrics", "Prompt metrics"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/llm-metrics")
    public String verificationLlmMetrics(Model model) {
        model.addAttribute("verificationStage", "llm-metrics");
        return page(model, "verification-llm-metrics", message("enterprise.pqa.nav.llmMetrics", "LLM decision metrics"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/failures")
    public String verificationFailures(Model model) {
        model.addAttribute("verificationStage", "failures");
        return page(model, "verification-failures", message("enterprise.pqa.pageTitle.failures", "Failure causes"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/evidence-package")
    public String verificationEvidencePackage(Model model) {
        model.addAttribute("verificationStage", "evidence-package");
        return page(model, "verification-evidence-package", message("enterprise.pqa.pageTitle.evidencePackage", "Evidence package"), "contexa/admin/prompt-quality/verification");
    }

    @GetMapping("/verification/reverify")
    public String verificationReverify(Model model) {
        model.addAttribute("verificationStage", "reverify");
        return page(model, "verification-reverify", message("enterprise.pqa.pageTitle.reverify", "Reverification"), "contexa/admin/prompt-quality/verification");
    }
    @GetMapping("/verification/handoff")
    public String verificationHandoff() {
        return "redirect:/contexa/admin/prompt-quality/verification/failures";
    }

    private String page(Model model, String activeKey, String pageTitle, String viewName) {
        model.addAttribute("pageTitle", pageTitle);
        model.addAttribute("verificationPageHeaderTitle", pageTitle);
        model.addAttribute("verificationPageHeaderSubtitle",
                message("enterprise.pqa.verification.pageSubtitle", "Review official inspection evidence and results."));
        model.addAttribute("activeKey", activeKey);
        model.addAttribute("navigation", navigation(activeKey));
        model.addAttribute("promptQualityRouteRoot", ROUTE_ROOT);
        model.addAttribute("promptQualityApiRoot", API_ROOT);
        model.addAttribute("promptQualityUiMode", "core");
        return viewName;
    }

    private List<PromptQualityNavigationItem> navigation(String activeKey) {
        return List.of(
                item(message("enterprise.pqa.nav.resources", "Protected resources"), "/contexa/admin/prompt-quality/resources",
                        message("enterprise.pqa.nav.resources.desc", "Review official inspection target resources."),
                        "resources".equals(activeKey)),
                item(message("enterprise.pqa.nav.runtimeEvidence", "Official inspection"), "/contexa/admin/prompt-quality/runtime-evidence",
                        message("enterprise.pqa.nav.runtimeEvidence.desc", "Select sealed actual request evidence and run official inspection."),
                        "runtime-evidence".equals(activeKey) || (activeKey != null && activeKey.startsWith("verification")),
                        List.of(
                                item(message("enterprise.pqa.nav.readiness", "Evidence check"), "/contexa/admin/prompt-quality/verification/readiness",
                                        message("enterprise.pqa.nav.readiness.desc", "Check request evidence to inspect."),
                                        "verification-readiness".equals(activeKey)),
                                item(message("enterprise.pqa.nav.run", "Inspection run"), "/contexa/admin/prompt-quality/verification/run",
                                        message("enterprise.pqa.nav.run.desc", "Run official inspection with selected request evidence."),
                                        "verification-run".equals(activeKey)),
                                item(message("enterprise.pqa.nav.summary", "Integrated result"), "/contexa/admin/prompt-quality/verification/summary",
                                        message("enterprise.pqa.nav.summary.desc", "Review prompt and LLM official inspection results together."),
                                        "verification-summary".equals(activeKey)),
                                item(message("enterprise.pqa.nav.promptMetrics", "Prompt 12 metrics"), "/contexa/admin/prompt-quality/verification/metrics",
                                        message("enterprise.pqa.nav.promptMetrics.desc", "Review 12 prompt and context quality metrics."),
                                        "verification-metrics".equals(activeKey)),
                                item(message("enterprise.pqa.nav.llmMetrics", "LLM decision metrics"), "/contexa/admin/prompt-quality/verification/llm-metrics",
                                        message("enterprise.pqa.nav.llmMetrics.desc", "Review LLM decision quality metrics."),
                                        "verification-llm-metrics".equals(activeKey)),
                                item(message("enterprise.pqa.nav.failures", "Failure causes"), "/contexa/admin/prompt-quality/verification/failures",
                                        message("enterprise.pqa.nav.failures.desc", "Review official inspection failure causes and remediation targets."),
                                        "verification-failures".equals(activeKey)),
                                item(message("enterprise.pqa.nav.evidencePackage", "Evidence package"), "/contexa/admin/prompt-quality/verification/evidence-package",
                                        message("enterprise.pqa.nav.evidencePackage.desc", "Review sealed evidence and decision payload."),
                                        "verification-evidence-package".equals(activeKey)),
                                item(message("enterprise.pqa.nav.reverify", "Reverification"), "/contexa/admin/prompt-quality/verification/reverify",
                                        message("enterprise.pqa.nav.reverify.desc", "Review prompt, LLM, and full reverification scopes."),
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


