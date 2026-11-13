package io.contexa.contexaiam.admin.promptquality.official.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/contexa/admin/api/prompt-quality/resources")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PromptQualityOfficialResourceApiController {

    /**
     * The state of a resource overlay without enterprise: there is no overlay store, so an overlay is never present and
     * cannot be saved or removed here.
     */
    public static final String OSS_READ_ONLY = "OSS_READ_ONLY";

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

    /** No overlay exists without enterprise; the screen reads {@code editable=false} and shows the form read-only. */
    @GetMapping("/{resourceId}/overlay")
    public Map<String, Object> overlay(@PathVariable String resourceId) {
        return Map.of("present", false, "overlay", Map.of(), "editable", false, "state", OSS_READ_ONLY,
                "message", views.message("enterprise.pqa.resourceOverlayEdit.readOnly.detail"));
    }

    /** Nothing is stored without enterprise, so a save is refused (409) instead of answering as if it were saved. */
    @PostMapping("/{resourceId}/overlay")
    public ResponseEntity<Map<String, Object>> saveOverlay(
            @PathVariable String resourceId,
            @RequestBody(required = false) Map<String, Object> body) {
        return readOnly(resourceId, "save");
    }

    /** Nothing is stored without enterprise, so there is nothing to remove: the removal is refused (409). */
    @DeleteMapping("/{resourceId}/overlay")
    public ResponseEntity<Map<String, Object>> deleteOverlay(@PathVariable String resourceId) {
        return readOnly(resourceId, "delete");
    }

    private ResponseEntity<Map<String, Object>> readOnly(String resourceId, String action) {
        log.warn("[PQA-OVERLAY] Overlay {} refused: resource overlays are read-only without enterprise (resource={})",
                action, resourceId);
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                "resourceId", resourceId,
                "code", OSS_READ_ONLY,
                "state", OSS_READ_ONLY,
                "message", views.message("enterprise.pqa.resourceOverlayEdit.readOnly.detail")));
    }
}