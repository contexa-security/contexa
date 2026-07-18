package io.contexa.contexaiam.admin.promptquality.official.api;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/contexa/admin/api/prompt-quality/resources")
public class PromptQualityOfficialResourceApiController {

    private final PromptQualityOfficialConsoleViewAssembler views;

    public PromptQualityOfficialResourceApiController(PromptQualityOfficialConsoleViewAssembler views) {
        this.views = views;
    }

    @GetMapping("/summary")
    public Map<String, Object> resourceSummary() {
        List<Map<String, Object>> resources = views.resourcesFromEvidence(500);
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("total", resources.size());
        summary.put("ready", resources.size());
        summary.put("pending", 0);
        summary.put("blocked", 0);
        return Map.of(
                "summary", summary,
                "resources", resources,
                "stateCatalog", Map.of("states", views.stateCatalogRows()));
    }

    @GetMapping("/detail")
    public Map<String, Object> resourceDetailByQuery(
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String resourceUrl,
            @RequestParam(defaultValue = "GET") String httpMethod) {
        Map<String, Object> resource = views.resolveResource(resourceId, resourceUrl, httpMethod);
        List<Map<String, Object>> history = views.resourceHistory(resource);
        return Map.of(
                "summary", Map.of("state", "READY"),
                "resource", resource,
                "certificate", Map.of(),
                "history", history,
                "lineage", history);
    }

    @GetMapping("/{resourceId}")
    public Map<String, Object> resourceDetail(
            @PathVariable String resourceId,
            @RequestParam(defaultValue = "GET") String httpMethod) {
        return resourceDetailByQuery(resourceId, null, httpMethod);
    }

    @GetMapping("/state-search")
    public Map<String, Object> resourceStateSearch(
            @RequestParam String resourceId,
            @RequestParam(required = false) String resourceUrl,
            @RequestParam(required = false) String httpMethod) {
        Map<String, Object> resource = views.resolveResource(resourceId, resourceUrl, httpMethod);
        List<Map<String, Object>> stages = List.of(
                views.processStage(
                        "PROTECTABLE_RESOURCES",
                        views.message("enterprise.pqa.stage.protectableResources"),
                        "/contexa/admin/prompt-quality/resources"),
                views.processStage(
                        "RUNTIME_EVIDENCE",
                        views.message("enterprise.pqa.stage.runtimeEvidence"),
                        views.runtimeEvidenceHref(resource)),
                views.processStage(
                        "OFFICIAL_VERIFICATION",
                        views.message("enterprise.pqa.stage.officialVerification"),
                        views.verificationHref(resource)));
        return Map.of(
                "resource", resource,
                "currentStage", Map.of(
                        "code", "OFFICIAL_VERIFICATION",
                        "label", views.message("enterprise.pqa.stage.officialVerification")),
                "currentExecutionState", "READY",
                "currentExecutionStateDescriptor", Map.of(
                        "code", "READY",
                        "label", views.message("enterprise.pqa.state.ready"),
                        "tone", "ready"),
                "metrics", List.of(
                        Map.of(
                                "code", "evidence",
                                "label", views.message("enterprise.pqa.stage.runtimeEvidence"),
                                "value", views.message("enterprise.pqa.state.actionCheck"),
                                "tone", "ready",
                                "route", views.runtimeEvidenceHref(resource)),
                        Map.of(
                                "code", "inspection",
                                "label", views.message("enterprise.pqa.stage.officialVerification"),
                                "value", views.message("enterprise.pqa.state.actionRun"),
                                "tone", "info",
                                "route", views.verificationHref(resource))),
                "processStages", stages,
                "routes", stages);
    }

    @GetMapping("/{resourceId}/overlay")
    public Map<String, Object> overlay(@PathVariable String resourceId) {
        return Map.of("present", false, "overlay", Map.of());
    }

    @PostMapping("/{resourceId}/overlay")
    public Map<String, Object> saveOverlay(
            @PathVariable String resourceId,
            @RequestBody(required = false) Map<String, Object> body) {
        return Map.of(
                "resourceId", resourceId,
                "state", "OSS_READ_ONLY",
                "overlay", body == null ? Map.of() : body);
    }

    @DeleteMapping("/{resourceId}/overlay")
    public Map<String, Object> deleteOverlay(@PathVariable String resourceId) {
        return Map.of("resourceId", resourceId, "state", "OSS_READ_ONLY");
    }
}